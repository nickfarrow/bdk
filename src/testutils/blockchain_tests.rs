use crate::testutils::TestIncomingTx;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::sha256d;
use bitcoin::{blockdata::witness::Witness, Address, Amount, Script, Transaction, Txid};
pub use bitcoincore_rpc::{Auth, Client as RpcClient, RpcApi};
use core::str::FromStr;
use electrsd::bitcoind::BitcoinD;
use electrsd::{bitcoind, ElectrsD};
pub use electrum_client::{Client as ElectrumClient, ElectrumApi};
#[allow(unused_imports)]
use log::{debug, error, info, log_enabled, trace, Level};
use std::collections::HashMap;
use std::env;
use std::ops::Deref;
use std::time::Duration;

pub struct TestClient {
    pub bitcoind: BitcoinD,
    pub electrsd: ElectrsD,
}

impl TestClient {
    pub fn new(bitcoind_exe: String, electrs_exe: String) -> Self {
        debug!("launching {} and {}", &bitcoind_exe, &electrs_exe);

        let mut conf = bitcoind::Conf::default();
        conf.view_stdout = log_enabled!(Level::Debug);
        let bitcoind = BitcoinD::with_conf(bitcoind_exe, &conf).unwrap();

        let mut conf = electrsd::Conf::default();
        conf.view_stderr = log_enabled!(Level::Debug);
        conf.http_enabled = cfg!(feature = "test-esplora");

        let electrsd = ElectrsD::with_conf(electrs_exe, &bitcoind, &conf).unwrap();

        let node_address = bitcoind.client.get_new_address(None, None).unwrap();
        bitcoind
            .client
            .generate_to_address(101, &node_address)
            .unwrap();

        let mut test_client = TestClient { bitcoind, electrsd };
        TestClient::wait_for_block(&mut test_client, 101);
        test_client
    }

    fn wait_for_tx(&mut self, txid: Txid, monitor_script: &Script) {
        // wait for electrs to index the tx
        exponential_backoff_poll(|| {
            self.electrsd.trigger().unwrap();
            trace!("wait_for_tx {}", txid);

            self.electrsd
                .client
                .script_get_history(monitor_script)
                .unwrap()
                .iter()
                .position(|entry| entry.tx_hash == txid)
        });
    }

    pub fn wait_for_block(&mut self, min_height: usize) {
        self.electrsd.client.block_headers_subscribe().unwrap();

        loop {
            let header = exponential_backoff_poll(|| {
                self.electrsd.trigger().unwrap();
                self.electrsd.client.ping().unwrap();
                self.electrsd.client.block_headers_pop().unwrap()
            });
            if header.height >= min_height {
                break;
            }
        }
    }

    pub fn receive(&mut self, meta_tx: TestIncomingTx) -> Txid {
        assert!(
            !meta_tx.output.is_empty(),
            "can't create a transaction with no outputs"
        );

        let mut map = HashMap::new();

        let mut required_balance = 0;
        for out in &meta_tx.output {
            required_balance += out.value;
            map.insert(out.to_address.clone(), Amount::from_sat(out.value));
        }

        if self.get_balance(None, None).unwrap() < Amount::from_sat(required_balance) {
            panic!("Insufficient funds in bitcoind. Please generate a few blocks with: `bitcoin-cli generatetoaddress 10 {}`", self.get_new_address(None, None).unwrap());
        }

        // FIXME: core can't create a tx with two outputs to the same address
        let tx = self
            .create_raw_transaction_hex(&[], &map, meta_tx.locktime, meta_tx.replaceable)
            .unwrap();
        let tx = self.fund_raw_transaction(tx, None, None).unwrap();
        let mut tx: Transaction = deserialize(&tx.hex).unwrap();

        if let Some(true) = meta_tx.replaceable {
            // for some reason core doesn't set this field right
            for input in &mut tx.input {
                input.sequence = 0xFFFFFFFD;
            }
        }

        let tx = self
            .sign_raw_transaction_with_wallet(&serialize(&tx), None, None)
            .unwrap();

        // broadcast through electrum so that it caches the tx immediately

        let txid = self
            .electrsd
            .client
            .transaction_broadcast(&deserialize(&tx.hex).unwrap())
            .unwrap();
        debug!("broadcasted to electrum {}", txid);

        if let Some(num) = meta_tx.min_confirmations {
            self.generate(num, None);
        }

        let monitor_script = Address::from_str(&meta_tx.output[0].to_address)
            .unwrap()
            .script_pubkey();
        self.wait_for_tx(txid, &monitor_script);

        debug!("Sent tx: {}", txid);

        txid
    }

    pub fn bump_fee(&mut self, txid: &Txid) -> Txid {
        let tx = self.get_raw_transaction_info(txid, None).unwrap();
        assert!(
            tx.confirmations.is_none(),
            "Can't bump tx {} because it's already confirmed",
            txid
        );

        let bumped: serde_json::Value = self.call("bumpfee", &[txid.to_string().into()]).unwrap();
        let new_txid = Txid::from_str(&bumped["txid"].as_str().unwrap().to_string()).unwrap();
        let monitor_script = Script::from_hex(&mut tx.vout[0].script_pub_key.hex.to_hex()).unwrap();
        self.wait_for_tx(new_txid, &monitor_script);

        debug!("Bumped {}, new txid {}", txid, new_txid);

        new_txid
    }

    pub fn generate_manually(&mut self, txs: Vec<Transaction>) -> String {
        use bitcoin::blockdata::block::{Block, BlockHeader};
        use bitcoin::blockdata::script::Builder;
        use bitcoin::blockdata::transaction::{OutPoint, TxIn, TxOut};
        use bitcoin::hash_types::{BlockHash, TxMerkleNode};

        let block_template: serde_json::Value = self
            .call("getblocktemplate", &[json!({"rules": ["segwit"]})])
            .unwrap();
        trace!("getblocktemplate: {:#?}", block_template);

        let header = BlockHeader {
            version: block_template["version"].as_i64().unwrap() as i32,
            prev_blockhash: BlockHash::from_hex(
                block_template["previousblockhash"].as_str().unwrap(),
            )
            .unwrap(),
            merkle_root: TxMerkleNode::default(),
            time: block_template["curtime"].as_u64().unwrap() as u32,
            bits: u32::from_str_radix(block_template["bits"].as_str().unwrap(), 16).unwrap(),
            nonce: 0,
        };
        debug!("header: {:#?}", header);

        let height = block_template["height"].as_u64().unwrap() as i64;
        let witness_reserved_value: Vec<u8> = sha256d::Hash::default().as_ref().into();
        // burn block subsidy and fees, not a big deal
        let mut coinbase_tx = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: Builder::new().push_int(height).into_script(),
                sequence: 0xFFFFFFFF,
                witness: Witness::from_vec(vec![witness_reserved_value]),
            }],
            output: vec![],
        };

        let mut txdata = vec![coinbase_tx.clone()];
        txdata.extend_from_slice(&txs);

        let mut block = Block { header, txdata };

        let witness_root = block.witness_root().unwrap();
        let witness_commitment = Block::compute_witness_commitment(
            &witness_root,
            &coinbase_tx.input[0].witness.to_vec()[0],
        );

        // now update and replace the coinbase tx
        let mut coinbase_witness_commitment_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        coinbase_witness_commitment_script.extend_from_slice(&witness_commitment);

        coinbase_tx.output.push(TxOut {
            value: 0,
            script_pubkey: coinbase_witness_commitment_script.into(),
        });
        block.txdata[0] = coinbase_tx;

        // set merkle root
        let merkle_root = block.merkle_root().unwrap();
        block.header.merkle_root = merkle_root;

        assert!(block.check_merkle_root());
        assert!(block.check_witness_commitment());

        // now do PoW :)
        let target = block.header.target();
        while block.header.validate_pow(&target).is_err() {
            block.header.nonce = block.header.nonce.checked_add(1).unwrap(); // panic if we run out of nonces
        }

        let block_hex: String = serialize(&block).to_hex();
        debug!("generated block hex: {}", block_hex);

        self.electrsd.client.block_headers_subscribe().unwrap();

        let submit_result: serde_json::Value =
            self.call("submitblock", &[block_hex.into()]).unwrap();
        debug!("submitblock: {:?}", submit_result);
        assert!(
            submit_result.is_null(),
            "submitblock error: {:?}",
            submit_result.as_str()
        );

        self.wait_for_block(height as usize);

        block.header.block_hash().to_hex()
    }

    pub fn generate(&mut self, num_blocks: u64, address: Option<Address>) {
        let address = address.unwrap_or_else(|| self.get_new_address(None, None).unwrap());
        let hashes = self.generate_to_address(num_blocks, &address).unwrap();
        let best_hash = hashes.last().unwrap();
        let height = self.get_block_info(best_hash).unwrap().height;

        self.wait_for_block(height);

        debug!("Generated blocks to new height {}", height);
    }

    pub fn invalidate(&mut self, num_blocks: u64) {
        self.electrsd.client.block_headers_subscribe().unwrap();

        let best_hash = self.get_best_block_hash().unwrap();
        let initial_height = self.get_block_info(&best_hash).unwrap().height;

        let mut to_invalidate = best_hash;
        for i in 1..=num_blocks {
            trace!(
                "Invalidating block {}/{} ({})",
                i,
                num_blocks,
                to_invalidate
            );

            self.invalidate_block(&to_invalidate).unwrap();
            to_invalidate = self.get_best_block_hash().unwrap();
        }

        self.wait_for_block(initial_height - num_blocks as usize);

        debug!(
            "Invalidated {} blocks to new height of {}",
            num_blocks,
            initial_height - num_blocks as usize
        );
    }

    pub fn reorg(&mut self, num_blocks: u64) {
        self.invalidate(num_blocks);
        self.generate(num_blocks, None);
    }

    pub fn get_node_address(&self) -> Address {
        Address::from_str(&self.get_new_address(None, None).unwrap().to_string()).unwrap()
    }
}

pub fn get_electrum_url() -> String {
    env::var("BDK_ELECTRUM_URL").unwrap_or_else(|_| "tcp://127.0.0.1:50001".to_string())
}

impl Deref for TestClient {
    type Target = RpcClient;

    fn deref(&self) -> &Self::Target {
        &self.bitcoind.client
    }
}

impl Default for TestClient {
    fn default() -> Self {
        let bitcoind_exe = env::var("BITCOIND_EXE")
            .ok()
            .or(bitcoind::downloaded_exe_path())
            .expect(
                "you should provide env var BITCOIND_EXE or specifiy a bitcoind version feature",
            );
        let electrs_exe = env::var("ELECTRS_EXE")
            .ok()
            .or(electrsd::downloaded_exe_path())
            .expect(
                "you should provide env var ELECTRS_EXE or specifiy a electrsd version feature",
            );
        Self::new(bitcoind_exe, electrs_exe)
    }
}

fn exponential_backoff_poll<T, F>(mut poll: F) -> T
where
    F: FnMut() -> Option<T>,
{
    let mut delay = Duration::from_millis(64);
    loop {
        match poll() {
            Some(data) => break data,
            None if delay.as_millis() < 512 => delay = delay.mul_f32(2.0),
            None => {}
        }

        std::thread::sleep(delay);
    }
}

/// This macro runs blockchain tests against a `Blockchain` implementation. It requires access to a
/// Bitcoin core wallet via RPC. At the moment you have to dig into the code yourself and look at
/// the setup required to run the tests yourself.
#[macro_export]
macro_rules! bdk_blockchain_tests {
    (
     fn $_fn_name:ident ( $( $test_client:ident : &TestClient )? $(,)? ) -> $blockchain:ty $block:block) => {
        #[cfg(test)]
        mod bdk_blockchain_tests {
            use $crate::bitcoin::{Network, Address};
            use $crate::testutils::blockchain_tests::TestClient;
            use $crate::blockchain::noop_progress;
            use $crate::database::MemoryDatabase;
            use $crate::types::KeychainKind;
            use $crate::{Wallet, FeeRate};
            use $crate::testutils;
            use $crate::blockchain::*;
            use $crate::wallet::AddressIndex;
            use core::str::FromStr;
            #[allow(unused_imports)]
            use super::*;

            #[allow(unused_variables)]
            fn get_blockchain(test_client: &TestClient) -> $blockchain {
                $( let $test_client = test_client; )?
                $block
            }

            fn get_wallet_from_descriptors(descriptors: &(String, Option<String>), test_client: &TestClient) -> Wallet<$blockchain, MemoryDatabase> {
                Wallet::new(&descriptors.0.to_string(), descriptors.1.as_ref(), Network::Regtest, MemoryDatabase::new(), get_blockchain(test_client)).unwrap()
            }

            fn _init_single_sig(descriptors: (String, Option<String>)) -> (Wallet<$blockchain, MemoryDatabase>, (String, Option<String>), TestClient) {
                let _ = env_logger::try_init();

                let test_client = TestClient::default();
                let wallet = get_wallet_from_descriptors(&descriptors, &test_client);

                // rpc need to call import_multi before receiving any tx, otherwise will not see tx in the mempool
                #[cfg(feature = "test-rpc")]
                wallet.sync(noop_progress(), None).unwrap();

                (wallet, descriptors, test_client)
            }

            fn init_single_sig() -> (Wallet<$blockchain, MemoryDatabase>, (String, Option<String>), TestClient) {
                let descriptors = testutils! {
                    @descriptors ( "wpkh(Alice)" ) ( "wpkh(Alice)" ) ( @keys ( "Alice" => (@generate_xprv "/44'/0'/0'/0/*", "/44'/0'/0'/1/*") ) )
                };
                _init_single_sig(descriptors)
            }

            fn init_single_sig_tr() -> (Wallet<$blockchain, MemoryDatabase>, (String, Option<String>), TestClient) {
                let descriptors = testutils! {
                    @descriptors ( "tr(Alice)" ) ( "tr(Alice)" ) ( @keys ( "Alice" => (@generate_xprv "/86'/0'/0'/0/*", "/86'/0'/0'/1/*") ) )
                };
                _init_single_sig(descriptors)
            }

            #[test]
            fn test_sync_simple() {
                use std::ops::Deref;
                use crate::database::Database;

                let (wallet, descriptors, mut test_client) = init_single_sig();

                let tx = testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                };
                println!("{:?}", tx);
                let txid = test_client.receive(tx);

                // the RPC blockchain needs to call `sync()` during initialization to import the
                // addresses (see `init_single_sig()`), so we skip this assertion
                #[cfg(not(feature = "test-rpc"))]
                assert!(wallet.database().deref().get_sync_time().unwrap().is_none(), "initial sync_time not none");

                wallet.sync(noop_progress(), None).unwrap();
                assert!(wallet.database().deref().get_sync_time().unwrap().is_some(), "sync_time hasn't been updated");

                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");
                assert_eq!(wallet.list_unspent().unwrap()[0].keychain, KeychainKind::External, "incorrect keychain kind");

                let list_tx_item = &wallet.list_transactions(false).unwrap()[0];
                assert_eq!(list_tx_item.txid, txid, "incorrect txid");
                assert_eq!(list_tx_item.received, 50_000, "incorrect received");
                assert_eq!(list_tx_item.sent, 0, "incorrect sent");
                assert_eq!(list_tx_item.confirmation_time, None, "incorrect confirmation time");
            }

            #[test]
            fn test_sync_stop_gap_20() {
                let (wallet, descriptors, mut test_client) = init_single_sig();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 5) => 50_000 )
                });
                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 25) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();

                assert_eq!(wallet.get_balance().unwrap(), 100_000, "incorrect balance");
                assert_eq!(wallet.list_transactions(false).unwrap().len(), 2, "incorrect number of txs");
            }

            #[test]
            fn test_sync_before_and_after_receive() {
                let (wallet, descriptors, mut test_client) = init_single_sig();

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 0);

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();

                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");
                assert_eq!(wallet.list_transactions(false).unwrap().len(), 1, "incorrect number of txs");
            }

            #[test]
            fn test_sync_multiple_outputs_same_tx() {
                let (wallet, descriptors, mut test_client) = init_single_sig();

                let txid = test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000, (@external descriptors, 1) => 25_000, (@external descriptors, 5) => 30_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();

                assert_eq!(wallet.get_balance().unwrap(), 105_000, "incorrect balance");
                assert_eq!(wallet.list_transactions(false).unwrap().len(), 1, "incorrect number of txs");
                assert_eq!(wallet.list_unspent().unwrap().len(), 3, "incorrect number of unspents");

                let list_tx_item = &wallet.list_transactions(false).unwrap()[0];
                assert_eq!(list_tx_item.txid, txid, "incorrect txid");
                assert_eq!(list_tx_item.received, 105_000, "incorrect received");
                assert_eq!(list_tx_item.sent, 0, "incorrect sent");
                assert_eq!(list_tx_item.confirmation_time, None, "incorrect confirmation_time");
            }

            #[test]
            fn test_sync_receive_multi() {
                let (wallet, descriptors, mut test_client) = init_single_sig();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });
                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 5) => 25_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();

                assert_eq!(wallet.get_balance().unwrap(), 75_000, "incorrect balance");
                assert_eq!(wallet.list_transactions(false).unwrap().len(), 2, "incorrect number of txs");
                assert_eq!(wallet.list_unspent().unwrap().len(), 2, "incorrect number of unspent");
            }

            #[test]
            fn test_sync_address_reuse() {
                let (wallet, descriptors, mut test_client) = init_single_sig();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000);

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 25_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 75_000, "incorrect balance");
            }

            #[test]
            fn test_sync_receive_rbf_replaced() {
                let (wallet, descriptors, mut test_client) = init_single_sig();

                let txid = test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 ) ( @replaceable true )
                });

                wallet.sync(noop_progress(), None).unwrap();

                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");
                assert_eq!(wallet.list_transactions(false).unwrap().len(), 1, "incorrect number of txs");
                assert_eq!(wallet.list_unspent().unwrap().len(), 1, "incorrect unspent");

                let list_tx_item = &wallet.list_transactions(false).unwrap()[0];
                assert_eq!(list_tx_item.txid, txid, "incorrect txid");
                assert_eq!(list_tx_item.received, 50_000, "incorrect received");
                assert_eq!(list_tx_item.sent, 0, "incorrect sent");
                assert_eq!(list_tx_item.confirmation_time, None, "incorrect confirmation_time");

                let new_txid = test_client.bump_fee(&txid);

                wallet.sync(noop_progress(), None).unwrap();

                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance after bump");
                assert_eq!(wallet.list_transactions(false).unwrap().len(), 1, "incorrect number of txs after bump");
                assert_eq!(wallet.list_unspent().unwrap().len(), 1, "incorrect unspent after bump");

                let list_tx_item = &wallet.list_transactions(false).unwrap()[0];
                assert_eq!(list_tx_item.txid, new_txid, "incorrect txid after bump");
                assert_eq!(list_tx_item.received, 50_000, "incorrect received after bump");
                assert_eq!(list_tx_item.sent, 0, "incorrect sent after bump");
                assert_eq!(list_tx_item.confirmation_time, None, "incorrect height after bump");
            }

            // FIXME: I would like this to be cfg_attr(not(feature = "test-esplora"), ignore) but it
            // doesn't work for some reason.
            #[cfg(not(feature = "esplora"))]
            #[test]
            fn test_sync_reorg_block() {
                let (wallet, descriptors, mut test_client) = init_single_sig();

                let txid = test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 ) ( @confirmations 1 ) ( @replaceable true )
                });

                wallet.sync(noop_progress(), None).unwrap();

                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");
                assert_eq!(wallet.list_transactions(false).unwrap().len(), 1, "incorrect number of txs");
                assert_eq!(wallet.list_unspent().unwrap().len(), 1, "incorrect number of unspents");

                let list_tx_item = &wallet.list_transactions(false).unwrap()[0];
                assert_eq!(list_tx_item.txid, txid, "incorrect txid");
                assert!(list_tx_item.confirmation_time.is_some(), "incorrect confirmation_time");

                // Invalidate 1 block
                test_client.invalidate(1);

                wallet.sync(noop_progress(), None).unwrap();

                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance after invalidate");

                let list_tx_item = &wallet.list_transactions(false).unwrap()[0];
                assert_eq!(list_tx_item.txid, txid, "incorrect txid after invalidate");
                assert_eq!(list_tx_item.confirmation_time, None, "incorrect confirmation time after invalidate");
            }

            #[test]
            fn test_sync_after_send() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                println!("{}", descriptors.0);
                let node_addr = test_client.get_node_address();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");

                let mut builder = wallet.build_tx();
                builder.add_recipient(node_addr.script_pubkey(), 25_000);
                let (mut psbt, details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                let tx = psbt.extract_tx();
                println!("{}", bitcoin::consensus::encode::serialize_hex(&tx));
                wallet.broadcast(&tx).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), details.received, "incorrect balance after send");

                assert_eq!(wallet.list_transactions(false).unwrap().len(), 2, "incorrect number of txs");
                assert_eq!(wallet.list_unspent().unwrap().len(), 1, "incorrect number of unspents");
            }

            #[test]
            fn test_sync_after_send_tr() {
                let (wallet, descriptors, mut test_client) = init_single_sig_tr();
                println!("{}", descriptors.0);
                let node_addr = test_client.get_node_address();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");

                let mut builder = wallet.build_tx();
                builder.add_recipient(node_addr.script_pubkey(), 25_000);
                builder.add_recipient(wallet.get_address(AddressIndex::New).unwrap().script_pubkey(), 10_000);
                let (mut psbt, details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                let tx = psbt.extract_tx();
                println!("{}", bitcoin::consensus::encode::serialize_hex(&tx));
                wallet.broadcast(&tx).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                dbg!(wallet.get_balance().unwrap(), details.received);
                assert_eq!(wallet.get_balance().unwrap(), details.received, "incorrect balance after send");

                assert_eq!(wallet.list_transactions(false).unwrap().len(), 2, "incorrect number of txs");
                assert_eq!(wallet.list_unspent().unwrap().len(), 2, "incorrect number of unspents");
            }

            /// Send two conflicting transactions to the same address twice in a row.
            /// The coins should only be received once!
            #[test]
            fn test_sync_double_receive() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                let receiver_wallet = get_wallet_from_descriptors(&("wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)".to_string(), None), &test_client);
                // need to sync so rpc can start watching
                receiver_wallet.sync(noop_progress(), None).unwrap();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000, (@external descriptors, 1) => 25_000 ) (@confirmations 1)
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 75_000, "incorrect balance");
                let target_addr = receiver_wallet.get_address($crate::wallet::AddressIndex::New).unwrap().address;

                let tx1 = {
                    let mut builder = wallet.build_tx();
                    builder.add_recipient(target_addr.script_pubkey(), 49_000).enable_rbf();
                    let (mut psbt, _details) = builder.finish().unwrap();
                    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                    assert!(finalized, "Cannot finalize transaction");
                    psbt.extract_tx()
                };

                let tx2 = {
                    let mut builder = wallet.build_tx();
                    builder.add_recipient(target_addr.script_pubkey(), 49_000).enable_rbf().fee_rate(FeeRate::from_sat_per_vb(5.0));
                    let (mut psbt, _details) = builder.finish().unwrap();
                    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                    assert!(finalized, "Cannot finalize transaction");
                    psbt.extract_tx()
                };

                wallet.broadcast(&tx1).unwrap();
                wallet.broadcast(&tx2).unwrap();

                receiver_wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(receiver_wallet.get_balance().unwrap(), 49_000, "should have received coins once and only once");
            }

            #[test]
            fn test_sync_many_sends_to_a_single_address() {
                let (wallet, descriptors, mut test_client) = init_single_sig();

                for _ in 0..4 {
                    // split this up into multiple blocks so rpc doesn't get angry
                    for _ in 0..20 {
                        test_client.receive(testutils! {
                            @tx ( (@external descriptors, 0) => 1_000 )
                        });
                    }
                    test_client.generate(1, None);
                }

                // add some to the mempool as well.
                for _ in 0..20 {
                    test_client.receive(testutils! {
                        @tx ( (@external descriptors, 0) => 1_000 )
                    });
                }

                wallet.sync(noop_progress(), None).unwrap();

                assert_eq!(wallet.get_balance().unwrap(), 100_000);
            }

            #[test]
            fn test_update_confirmation_time_after_generate() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                println!("{}", descriptors.0);
                let node_addr = test_client.get_node_address();

                let received_txid = test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");

                let tx_map = wallet.list_transactions(false).unwrap().into_iter().map(|tx| (tx.txid, tx)).collect::<std::collections::HashMap<_, _>>();
                let details = tx_map.get(&received_txid).unwrap();
                assert!(details.confirmation_time.is_none());

                test_client.generate(1, Some(node_addr));
                wallet.sync(noop_progress(), None).unwrap();

                let tx_map = wallet.list_transactions(false).unwrap().into_iter().map(|tx| (tx.txid, tx)).collect::<std::collections::HashMap<_, _>>();
                let details = tx_map.get(&received_txid).unwrap();
                assert!(details.confirmation_time.is_some());

            }

            #[test]
            fn test_sync_outgoing_from_scratch() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                let node_addr = test_client.get_node_address();
                let received_txid = test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");

                let mut builder = wallet.build_tx();
                builder.add_recipient(node_addr.script_pubkey(), 25_000);
                let (mut psbt, details) = builder.finish().unwrap();

                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                let sent_txid = wallet.broadcast(&psbt.extract_tx()).unwrap();

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), details.received, "incorrect balance after receive");

                // empty wallet
                let wallet = get_wallet_from_descriptors(&descriptors, &test_client);

                #[cfg(feature = "rpc")]  // rpc cannot see mempool tx before importmulti
                test_client.generate(1, Some(node_addr));

                wallet.sync(noop_progress(), None).unwrap();
                let tx_map = wallet.list_transactions(false).unwrap().into_iter().map(|tx| (tx.txid, tx)).collect::<std::collections::HashMap<_, _>>();

                let received = tx_map.get(&received_txid).unwrap();
                assert_eq!(received.received, 50_000, "incorrect received from receiver");
                assert_eq!(received.sent, 0, "incorrect sent from receiver");

                let sent = tx_map.get(&sent_txid).unwrap();
                assert_eq!(sent.received, details.received, "incorrect received from sender");
                assert_eq!(sent.sent, details.sent, "incorrect sent from sender");
                assert_eq!(sent.fee.unwrap_or(0), details.fee.unwrap_or(0), "incorrect fees from sender");
            }

            #[test]
            fn test_sync_long_change_chain() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                let node_addr = test_client.get_node_address();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");

                let mut total_sent = 0;
                for _ in 0..5 {
                    let mut builder = wallet.build_tx();
                    builder.add_recipient(node_addr.script_pubkey(), 5_000);
                    let (mut psbt, details) = builder.finish().unwrap();
                    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                    assert!(finalized, "Cannot finalize transaction");
                    wallet.broadcast(&psbt.extract_tx()).unwrap();

                    wallet.sync(noop_progress(), None).unwrap();

                    total_sent += 5_000 + details.fee.unwrap_or(0);
                }

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000 - total_sent, "incorrect balance after chain");

                // empty wallet

                let wallet = get_wallet_from_descriptors(&descriptors, &test_client);

                #[cfg(feature = "rpc")]  // rpc cannot see mempool tx before importmulti
                test_client.generate(1, Some(node_addr));

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000 - total_sent, "incorrect balance empty wallet");

            }

            #[test]
            fn test_sync_bump_fee_basic() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                let node_addr = test_client.get_node_address();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 ) (@confirmations 1)
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");

                let mut builder = wallet.build_tx();
                builder.add_recipient(node_addr.script_pubkey().clone(), 5_000).enable_rbf();
                let (mut psbt, details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                wallet.broadcast(&psbt.extract_tx()).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000 - details.fee.unwrap_or(0) - 5_000, "incorrect balance from fees");
                assert_eq!(wallet.get_balance().unwrap(), details.received, "incorrect balance from received");

                let mut builder = wallet.build_fee_bump(details.txid).unwrap();
                builder.fee_rate(FeeRate::from_sat_per_vb(2.1));
                let (mut new_psbt, new_details) = builder.finish().expect("fee bump tx");
                let finalized = wallet.sign(&mut new_psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                wallet.broadcast(&new_psbt.extract_tx()).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000 - new_details.fee.unwrap_or(0) - 5_000, "incorrect balance from fees after bump");
                assert_eq!(wallet.get_balance().unwrap(), new_details.received, "incorrect balance from received after bump");

                assert!(new_details.fee.unwrap_or(0) > details.fee.unwrap_or(0), "incorrect fees");
            }

            #[test]
            fn test_sync_bump_fee_remove_change() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                let node_addr = test_client.get_node_address();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 ) (@confirmations 1)
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");

                let mut builder = wallet.build_tx();
                builder.add_recipient(node_addr.script_pubkey().clone(), 49_000).enable_rbf();
                let (mut psbt, details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                wallet.broadcast(&psbt.extract_tx()).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 1_000 - details.fee.unwrap_or(0), "incorrect balance after send");
                assert_eq!(wallet.get_balance().unwrap(), details.received, "incorrect received after send");

                let mut builder = wallet.build_fee_bump(details.txid).unwrap();
                builder.fee_rate(FeeRate::from_sat_per_vb(5.0));
                let (mut new_psbt, new_details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut new_psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                wallet.broadcast(&new_psbt.extract_tx()).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 0, "incorrect balance after change removal");
                assert_eq!(new_details.received, 0, "incorrect received after change removal");

                assert!(new_details.fee.unwrap_or(0) > details.fee.unwrap_or(0), "incorrect fees");
            }

            #[test]
            fn test_sync_bump_fee_add_input_simple() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                let node_addr = test_client.get_node_address();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000, (@external descriptors, 1) => 25_000 ) (@confirmations 1)
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 75_000, "incorrect balance");

                let mut builder = wallet.build_tx();
                builder.add_recipient(node_addr.script_pubkey().clone(), 49_000).enable_rbf();
                let (mut psbt, details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                wallet.broadcast(&psbt.extract_tx()).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 26_000 - details.fee.unwrap_or(0), "incorrect balance after send");
                assert_eq!(details.received, 1_000 - details.fee.unwrap_or(0), "incorrect received after send");

                let mut builder = wallet.build_fee_bump(details.txid).unwrap();
                builder.fee_rate(FeeRate::from_sat_per_vb(10.0));
                let (mut new_psbt, new_details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut new_psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                wallet.broadcast(&new_psbt.extract_tx()).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(new_details.sent, 75_000, "incorrect sent");
                assert_eq!(wallet.get_balance().unwrap(), new_details.received, "incorrect balance after add input");
            }

            #[test]
            fn test_sync_bump_fee_add_input_no_change() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                let node_addr = test_client.get_node_address();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000, (@external descriptors, 1) => 25_000 ) (@confirmations 1)
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 75_000, "incorrect balance");

                let mut builder = wallet.build_tx();
                builder.add_recipient(node_addr.script_pubkey().clone(), 49_000).enable_rbf();
                let (mut psbt, details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                wallet.broadcast(&psbt.extract_tx()).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 26_000 - details.fee.unwrap_or(0), "incorrect balance after send");
                assert_eq!(details.received, 1_000 - details.fee.unwrap_or(0), "incorrect received after send");

                let mut builder = wallet.build_fee_bump(details.txid).unwrap();
                builder.fee_rate(FeeRate::from_sat_per_vb(123.0));
                let (mut new_psbt, new_details) = builder.finish().unwrap();
                println!("{:#?}", new_details);

                let finalized = wallet.sign(&mut new_psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                wallet.broadcast(&new_psbt.extract_tx()).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(new_details.sent, 75_000, "incorrect sent");
                assert_eq!(wallet.get_balance().unwrap(), 0, "incorrect balance after add input");
                assert_eq!(new_details.received, 0, "incorrect received after add input");
            }


            #[test]
            fn test_add_data() {
                let (wallet, descriptors, mut test_client) = init_single_sig();
                let node_addr = test_client.get_node_address();
                let _ = test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000, "incorrect balance");

                let mut builder = wallet.build_tx();
                let data = [42u8;80];
                builder.add_data(&data);
                let (mut psbt, details) = builder.finish().unwrap();

                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                let tx = psbt.extract_tx();
                let serialized_tx = bitcoin::consensus::encode::serialize(&tx);
                assert!(serialized_tx.windows(data.len()).any(|e| e==data), "cannot find op_return data in transaction");
                let sent_txid = wallet.broadcast(&tx).unwrap();
                test_client.generate(1, Some(node_addr));
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000 - details.fee.unwrap_or(0), "incorrect balance after send");

                let tx_map = wallet.list_transactions(false).unwrap().into_iter().map(|tx| (tx.txid, tx)).collect::<std::collections::HashMap<_, _>>();
                let _ = tx_map.get(&sent_txid).unwrap();
            }

            #[test]
            fn test_sync_receive_coinbase() {
                let (wallet, _, mut test_client) = init_single_sig();

                let wallet_addr = wallet.get_address($crate::wallet::AddressIndex::New).unwrap().address;

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 0, "incorrect balance");

                test_client.generate(1, Some(wallet_addr));

                #[cfg(feature = "rpc")]
                {
                    // rpc consider coinbase only when mature (100 blocks)
                    let node_addr = test_client.get_node_address();
                    test_client.generate(100, Some(node_addr));
                }


                wallet.sync(noop_progress(), None).unwrap();
                assert!(wallet.get_balance().unwrap() > 0, "incorrect balance after receiving coinbase");
            }

            // #[test]
            // #[cfg(feature = "esplora")]
            // fn test_utxo_exists() {
            //     use std::str::FromStr;
            //     let (wallet, descriptors, mut test_client) = init_single_sig();
            //     assert!(!wallet
            //             .client()
            //             .utxo_exists(OutPoint {
            //                 txid:  Txid::from_str("0d3dbc4a250d7bbc12e57fd7e13c7875cca726d757217d97eb910fd8ad24af79").unwrap(),
            //                 vout: 0 })
            //             .unwrap(), "random UTXO shouldn't exist");

            //     test_client.receive(testutils! {
            //         @tx ( (@external descriptors, 0) => 50_000 )
            //     });

            //     wallet.sync(noop_progress(), None).unwrap();
            //     assert_eq!(wallet.get_balance().unwrap(), 50_000);
            //     let outpoint = wallet.list_unspent().unwrap()[0].outpoint;
            //     assert!(wallet.client().utxo_exists(outpoint).unwrap(), "utxo should exist");

            //     let mut builder = wallet.build_tx();
            //     builder.add_recipient(wallet.get_address($crate::wallet::AddressIndex::New).unwrap().script_pubkey(), 25_000);
            //     let (mut psbt, _details) = builder.finish().unwrap();
            //     let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
            //     assert!(finalized, "Cannot finalize transaction");
            //     let tx = psbt.extract_tx();
            //     wallet.broadcast(tx).unwrap();
            //     assert!(wallet.client().utxo_exists(outpoint).unwrap(), "UTXO should still be there even when spending tx is in mempool");
            //     test_client.generate(1, None);
            //     assert!(!wallet.client().utxo_exists(outpoint).unwrap(), "UTXO should be gone now");
            // }

            #[test]
            #[cfg(feature = "esplora")]
            fn test_broadcast() {
                use crate::blockchain::{BroadcastError, Broadcast};
                use bitcoin::blockdata::witness::Witness;
                let (wallet, descriptors, mut test_client) = init_single_sig();
                let node_addr = test_client.get_node_address();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000);

                let mut builder = wallet.build_tx();
                builder.add_recipient(node_addr.script_pubkey(), 25_000);
                let (mut psbt, _details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "Cannot finalize transaction");
                let tx = psbt.extract_tx();
                {
                    let mut tx = tx.clone();
                    let mut new_witness = tx.input[0].witness.to_vec();
                    // hose the key
                    new_witness[1][1] += 1;
                    tx.input[0].witness = Witness::from_vec(new_witness);
                    assert_eq!(Broadcast::broadcast(wallet.client(), tx), Err(BroadcastError::Tx(BroadcastTxError::ScriptPubkeyNotSatisfied("Script failed an OP_EQUALVERIFY operation".into()))));
                }
                {
                    let mut tx = tx.clone();
                    // hose the signature
                    let mut new_witness = tx.input[0].witness.to_vec();
                    new_witness[0][20] += 1;
                    tx.input[0].witness = Witness::from_vec(new_witness);
                    assert_eq!(Broadcast::broadcast(wallet.client(), tx), Err(BroadcastError::Tx(BroadcastTxError::ScriptPubkeyNotSatisfied("Signature must be zero for failed CHECK(MULTI)SIG operation".into()))));
                }

                Broadcast::broadcast(wallet.client(), tx.clone()).unwrap();

                {
                    let tx2 = {
                        let mut builder = wallet.build_tx();
                        builder.add_utxo(tx.input[0].previous_output).unwrap();
                        builder.add_recipient(node_addr.script_pubkey(), 30_000);
                        let (mut psbt, _details) = builder.finish().unwrap();
                        let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                        assert!(finalized, "Cannot finalize transaction");
                        psbt.extract_tx()
                    };

                    assert_eq!(Broadcast::broadcast(wallet.client(), tx2.clone()), Err(BroadcastError::Tx(BroadcastTxError::ConflictsWithMempool)));
                }

                test_client.generate(1, None);

                {
                    let tx2 = {
                        let mut builder = wallet.build_tx();
                        builder.add_utxo(tx.input[0].previous_output).unwrap();
                        builder.add_recipient(node_addr.script_pubkey(), 30_000);
                        let (mut psbt, _details) = builder.finish().unwrap();
                        let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                        assert!(finalized, "Cannot finalize transaction");
                        psbt.extract_tx()
                    };

                    assert_eq!(Broadcast::broadcast(wallet.client(), tx2.clone()), Err(BroadcastError::Tx(BroadcastTxError::MissingOrSpent)));
                }

            }

            #[test]
            #[cfg(feature = "esplora")]
            fn test_tx_state() {
                pub use bitcoincore_rpc::RpcApi;
                let (wallet, descriptors, mut test_client) = init_single_sig();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();

                let tx1 = {
                    let mut builder = wallet.build_tx();
                    builder.add_recipient(wallet.get_address($crate::wallet::AddressIndex::New).unwrap().script_pubkey(), 30_000);
                    let (mut psbt, _details) = builder.finish().unwrap();
                    let _ = wallet.sign(&mut psbt, Default::default()).unwrap();
                    psbt.extract_tx()
                };

                let tx2 = {
                    let mut builder = wallet.build_tx();
                    builder.add_recipient(wallet.get_address($crate::wallet::AddressIndex::New).unwrap().script_pubkey(), 30_000)
                        // create a different conflict
                        .add_unspendable(tx1.input[0].previous_output);
                    let (mut psbt, _details) = builder.finish().unwrap();
                    let _ = wallet.sign(&mut psbt, Default::default()).unwrap();
                    psbt.extract_tx()
                };

                let tx3 = {
                    let mut builder = wallet.build_tx();
                    builder.add_recipient(wallet.get_address($crate::wallet::AddressIndex::New).unwrap().script_pubkey(), 30_000)
                        // conflict with both tx1 and tx2
                           .add_utxo(tx1.input[0].previous_output).unwrap()
                           .add_utxo(tx2.input[0].previous_output).unwrap();
                    let (mut psbt, _details) = builder.finish().unwrap();
                    let _ = wallet.sign(&mut psbt, Default::default()).unwrap();
                    psbt.extract_tx()
                };

                assert_eq!(wallet.client().tx_state(&tx1).unwrap(), TxState::NotFound, "tx1 not in broadcasted");
                assert_eq!(wallet.client().tx_state(&tx2).unwrap(), TxState::NotFound, "tx2 not in broadcasted");
                assert_eq!(wallet.client().tx_state(&tx3).unwrap(), TxState::NotFound, "tx3 not in broadcasted");
                Broadcast::broadcast(wallet.client(), tx2.clone()).unwrap();
                assert_eq!(wallet.client().tx_state(&tx2).unwrap(), TxState::Present { height: None });
                assert_eq!(wallet.client().tx_state(&tx1).unwrap(), TxState::NotFound, "tx1 doesn't conflict with tx2 and has not been broadcast" );
                assert_eq!(wallet.client().tx_state(&tx3).unwrap(), TxState::Conflict { txid: tx2.txid(), vin: 0, vin_target:1, height: None });
                test_client.generate(1, None);
                let height = test_client.get_blockchain_info().unwrap().blocks as u32;
                assert_eq!(wallet.client().tx_state(&tx2).unwrap(), TxState::Present { height: Some(height) });
                assert_eq!(wallet.client().tx_state(&tx1).unwrap(), TxState::NotFound, "tx1 doesn't conflict with tx2 and has not been broadcast" );
                assert_eq!(wallet.client().tx_state(&tx3).unwrap(), TxState::Conflict { height: Some(height), vin: 0, vin_target: 1, txid: tx2.txid() }, "tx3 should conflict with tx1");
                Broadcast::broadcast(wallet.client(), tx1.clone()).unwrap();
                assert_eq!(wallet.client().tx_state(&tx2).unwrap(), TxState::Present { height: Some(height) });
                assert_eq!(wallet.client().tx_state(&tx1).unwrap(), TxState::Present { height: None } );
                assert_eq!(wallet.client().tx_state(&tx3).unwrap(), TxState::Conflict { height: Some(height), vin: 0, vin_target: 1, txid: tx2.txid() }, "should still conflict with tx1 because tx2 is not even confirmed yet");
                test_client.generate(1, None);
                assert_eq!(wallet.client().tx_state(&tx2).unwrap(), TxState::Present { height: Some(height) });
                assert_eq!(wallet.client().tx_state(&tx1).unwrap(), TxState::Present { height: Some(height + 1) } );
                assert_eq!(wallet.client().tx_state(&tx3).unwrap(), TxState::Conflict { height: Some(height), vin: 0, vin_target: 1, txid: tx2.txid() }, "should still conflict with tx1 because it is deeper");
                //NOTE: I would like to test this with a fork but esplora isn't working with that
            }

            #[test]
            #[cfg(feature = "esplora")]
            fn test_input_state() {
                pub use bitcoincore_rpc::RpcApi;
                let (wallet, descriptors, mut test_client) = init_single_sig();

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();

                let tx1 = {
                    let mut builder = wallet.build_tx();
                    builder.add_recipient(wallet.get_address($crate::wallet::AddressIndex::New).unwrap().script_pubkey(), 30_000);
                    let (mut psbt, _details) = builder.finish().unwrap();
                    let _ = wallet.sign(&mut psbt, Default::default()).unwrap();
                    psbt.extract_tx()
                };

                let tx2 = {
                    let mut builder = wallet.build_tx();
                    builder.add_recipient(wallet.get_address($crate::wallet::AddressIndex::New).unwrap().script_pubkey(), 30_000)
                        // create a different conflict
                        .add_unspendable(tx1.input[0].previous_output);
                    let (mut psbt, _details) = builder.finish().unwrap();
                    let _ = wallet.sign(&mut psbt, Default::default()).unwrap();
                    psbt.extract_tx()
                };

                let inputs = {
                    let mut builder = wallet.build_tx();
                    builder.add_recipient(wallet.get_address($crate::wallet::AddressIndex::New).unwrap().script_pubkey(), 30_000)
                        // conflict with both tx1 and tx2
                           .add_utxo(tx1.input[0].previous_output).unwrap()
                           .add_utxo(tx2.input[0].previous_output).unwrap();
                    let (mut psbt, _details) = builder.finish().unwrap();
                    let _ = wallet.sign(&mut psbt, Default::default()).unwrap();
                    psbt.extract_tx().input.into_iter().map(|x| x.previous_output).collect::<Vec<_>>()
                };


                assert_eq!(wallet.client().input_state(&inputs[..]).unwrap(), InputState::Unspent, "no inputs have been spent yet");
                Broadcast::broadcast(wallet.client(), tx2.clone()).unwrap();
                assert_eq!(wallet.client().input_state(&inputs).unwrap(), InputState::Spent { height: None, txid: tx2.txid(), vin: 0, index: 1 });
                test_client.generate(1, None);
                let height = test_client.get_blockchain_info().unwrap().blocks as u32;
                assert_eq!(wallet.client().input_state(&inputs[..]).unwrap(), InputState::Spent { height: Some(height), txid: tx2.txid(), vin: 0, index: 1 }, "tx2 has spent it");
                Broadcast::broadcast(wallet.client(), tx1.clone()).unwrap();
                assert_eq!(wallet.client().input_state(&inputs[..]).unwrap(), InputState::Spent { height: Some(height), txid: tx2.txid(), vin: 0, index: 1 }, "tx2 is confirmed and tx1 isn't");
                test_client.generate(1, None);
                assert_eq!(wallet.client().input_state(&inputs[..]).unwrap(), InputState::Spent { height: Some(height), txid: tx2.txid(), vin: 0, index: 1 }, "tx2 is confirmed deeper than tx1");
            }

            #[test]
            fn test_send_to_bech32m_addr() {
                use std::str::FromStr;
                use serde;
                use serde_json;
                use serde::Serialize;
                use bitcoincore_rpc::jsonrpc::serde_json::Value;
                use bitcoincore_rpc::{Auth, Client, RpcApi};

                let (wallet, descriptors, mut test_client) = init_single_sig();

                // TODO remove once rust-bitcoincore-rpc with PR 199 released
                // https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/199
                /// Import Descriptor Request
                #[derive(Serialize, Clone, PartialEq, Eq, Debug)]
                pub struct ImportDescriptorRequest {
                    pub active: bool,
                    #[serde(rename = "desc")]
                    pub descriptor: String,
                    pub range: [i64; 2],
                    pub next_index: i64,
                    pub timestamp: String,
                    pub internal: bool,
                }

                // TODO remove once rust-bitcoincore-rpc with PR 199 released
                impl ImportDescriptorRequest {
                    /// Create a new Import Descriptor request providing just the descriptor and internal flags
                    pub fn new(descriptor: &str, internal: bool) -> Self {
                        ImportDescriptorRequest {
                            descriptor: descriptor.to_string(),
                            internal,
                            active: true,
                            range: [0, 100],
                            next_index: 0,
                            timestamp: "now".to_string(),
                        }
                    }
                }

                // 1. Create and add descriptors to a test bitcoind node taproot wallet

                // TODO replace once rust-bitcoincore-rpc with PR 174 released
                // https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/174
                let _createwallet_result: Value = test_client.bitcoind.client.call("createwallet", &["taproot_wallet".into(),false.into(),true.into(),serde_json::to_value("").unwrap(), false.into(), true.into()]).unwrap();

                // TODO replace once bitcoind released with support for rust-bitcoincore-rpc PR 174
                let taproot_wallet_client = Client::new(&test_client.bitcoind.rpc_url_with_wallet("taproot_wallet"), Auth::CookieFile(test_client.bitcoind.params.cookie_file.clone())).unwrap();

                let wallet_descriptor = "tr(tprv8ZgxMBicQKsPdBtxmEMPnNq58KGusNAimQirKFHqX2yk2D8q1v6pNLiKYVAdzDHy2w3vF4chuGfMvNtzsbTTLVXBcdkCA1rje1JG6oksWv8/86h/1h/0h/0/*)#y283ssmn";
                let change_descriptor = "tr(tprv8ZgxMBicQKsPdBtxmEMPnNq58KGusNAimQirKFHqX2yk2D8q1v6pNLiKYVAdzDHy2w3vF4chuGfMvNtzsbTTLVXBcdkCA1rje1JG6oksWv8/86h/1h/0h/1/*)#47zsd9tt";

                let tr_descriptors = vec![
                            ImportDescriptorRequest::new(wallet_descriptor, false),
                            ImportDescriptorRequest::new(change_descriptor, false),
                        ];

                // TODO replace once rust-bitcoincore-rpc with PR 199 released
                let _import_result: Value = taproot_wallet_client.call("importdescriptors", &[serde_json::to_value(tr_descriptors).unwrap()]).unwrap();

                // 2. Get a new bech32m address from test bitcoind node taproot wallet

                // TODO replace once rust-bitcoincore-rpc with PR 199 released
                let node_addr: bitcoin::Address = taproot_wallet_client.call("getnewaddress", &["test address".into(), "bech32m".into()]).unwrap();
                assert_eq!(node_addr, bitcoin::Address::from_str("bcrt1pj5y3f0fu4y7g98k4v63j9n0xvj3lmln0cpwhsjzknm6nt0hr0q7qnzwsy9").unwrap());

                // 3. Send 50_000 sats from test bitcoind node to test BDK wallet

                test_client.receive(testutils! {
                    @tx ( (@external descriptors, 0) => 50_000 )
                });

                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), 50_000, "wallet has incorrect balance");

                // 4. Send 25_000 sats from test BDK wallet to test bitcoind node taproot wallet

                let mut builder = wallet.build_tx();
                builder.add_recipient(node_addr.script_pubkey(), 25_000);
                let (mut psbt, details) = builder.finish().unwrap();
                let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
                assert!(finalized, "wallet cannot finalize transaction");
                let tx = psbt.extract_tx();
                wallet.broadcast(&tx).unwrap();
                wallet.sync(noop_progress(), None).unwrap();
                assert_eq!(wallet.get_balance().unwrap(), details.received, "wallet has incorrect balance after send");
                assert_eq!(wallet.list_transactions(false).unwrap().len(), 2, "wallet has incorrect number of txs");
                assert_eq!(wallet.list_unspent().unwrap().len(), 1, "wallet has incorrect number of unspents");
                test_client.generate(1, None);

                // 5. Verify 25_000 sats are received by test bitcoind node taproot wallet

                let taproot_balance = taproot_wallet_client.get_balance(None, None).unwrap();
                assert_eq!(taproot_balance.as_sat(), 25_000, "node has incorrect taproot wallet balance");
            }
        }
    };

    ( fn $fn_name:ident ($( $tt:tt )+) -> $blockchain:ty $block:block) => {
        compile_error!(concat!("Invalid arguments `", stringify!($($tt)*), "` in the blockchain tests fn."));
        compile_error!("Only the exact `&TestClient` type is supported, **without** any leading path items.");
    };
}
