use std::str::FromStr;

use bitcoin::{util::psbt, Network};

use crate::database::memory::MemoryDatabase;
use crate::database::Database;
use crate::types::KeychainKind;

use super::*;
use crate::signer::{SignOptions, SignerError};
use crate::testutils;
use crate::wallet::AddressIndex::{LastUnused, New, Peek, Reset};

#[test]
fn test_cache_addresses_fixed() {
    let db = MemoryDatabase::new();
    let wallet = Wallet::new_offline(
        "wpkh(L5EZftvrYaSudiozVRzTqLcHLNDoVn7H5HSfM9BAN6tMJX8oTWz6)",
        None,
        Network::Testnet,
        db,
    )
    .unwrap();

    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1qj08ys4ct2hzzc2hcz6h2hgrvlmsjynaw43s835"
    );
    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1qj08ys4ct2hzzc2hcz6h2hgrvlmsjynaw43s835"
    );

    assert!(wallet
        .database
        .borrow_mut()
        .get_script_pubkey_from_path(KeychainKind::External, 0)
        .unwrap()
        .is_some());
    assert!(wallet
        .database
        .borrow_mut()
        .get_script_pubkey_from_path(KeychainKind::Internal, 0)
        .unwrap()
        .is_none());
}

#[test]
fn test_cache_addresses() {
    let db = MemoryDatabase::new();
    let wallet = Wallet::new_offline("wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)", None, Network::Testnet, db).unwrap();

    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1q6yn66vajcctph75pvylgkksgpp6nq04ppwct9a"
    );
    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7"
    );

    assert!(wallet
        .database
        .borrow_mut()
        .get_script_pubkey_from_path(KeychainKind::External, CACHE_ADDR_BATCH_SIZE - 1)
        .unwrap()
        .is_some());
    assert!(wallet
        .database
        .borrow_mut()
        .get_script_pubkey_from_path(KeychainKind::External, CACHE_ADDR_BATCH_SIZE)
        .unwrap()
        .is_none());
}

#[test]
fn test_cache_addresses_refill() {
    let db = MemoryDatabase::new();
    let wallet = Wallet::new_offline("wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)", None, Network::Testnet, db).unwrap();

    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1q6yn66vajcctph75pvylgkksgpp6nq04ppwct9a"
    );
    assert!(wallet
        .database
        .borrow_mut()
        .get_script_pubkey_from_path(KeychainKind::External, CACHE_ADDR_BATCH_SIZE - 1)
        .unwrap()
        .is_some());

    for _ in 0..CACHE_ADDR_BATCH_SIZE {
        wallet.get_address(New).unwrap();
    }

    assert!(wallet
        .database
        .borrow_mut()
        .get_script_pubkey_from_path(KeychainKind::External, CACHE_ADDR_BATCH_SIZE * 2 - 1)
        .unwrap()
        .is_some());
}

pub(crate) fn get_test_wpkh() -> &'static str {
    "wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)"
}

pub(crate) fn get_test_single_sig_csv() -> &'static str {
    // and(pk(Alice),older(6))
    "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),older(6)))"
}

pub(crate) fn get_test_a_or_b_plus_csv() -> &'static str {
    // or(pk(Alice),and(pk(Bob),older(144)))
    "wsh(or_d(pk(cRjo6jqfVNP33HhSS76UhXETZsGTZYx8FMFvR9kpbtCSV1PmdZdu),and_v(v:pk(cMnkdebixpXMPfkcNEjjGin7s94hiehAH4mLbYkZoh9KSiNNmqC8),older(144))))"
}

pub(crate) fn get_test_single_sig_cltv() -> &'static str {
    // and(pk(Alice),after(100000))
    "wsh(and_v(v:pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW),after(100000)))"
}

pub(crate) fn get_funded_wallet(
    descriptor: &str,
) -> (
    Wallet<(), MemoryDatabase>,
    (String, Option<String>),
    bitcoin::Txid,
) {
    let descriptors = testutils!(@descriptors (descriptor));
    let wallet = Wallet::new_offline(
        &descriptors.0,
        None,
        Network::Regtest,
        MemoryDatabase::new(),
    )
    .unwrap();

    let funding_address_kix = 0;

    let tx_meta = testutils! {
        @tx ( (@external descriptors, funding_address_kix) => 50_000 ) (@confirmations 1)
    };

    wallet
        .database
        .borrow_mut()
        .set_script_pubkey(
            &bitcoin::Address::from_str(&tx_meta.output.get(0).unwrap().to_address)
                .unwrap()
                .script_pubkey(),
            KeychainKind::External,
            funding_address_kix,
        )
        .unwrap();
    wallet
        .database
        .borrow_mut()
        .set_last_index(KeychainKind::External, funding_address_kix)
        .unwrap();

    let txid = crate::populate_test_db!(wallet.database.borrow_mut(), tx_meta, Some(100));

    (wallet, descriptors, txid)
}

macro_rules! assert_fee_rate {
    ($tx:expr, $fees:expr, $fee_rate:expr $( ,@dust_change $( $dust_change:expr )* )* $( ,@add_signature $( $add_signature:expr )* )* ) => ({
        let mut tx = $tx.clone();
        $(
            $( $add_signature )*
                for txin in &mut tx.input {
                    txin.witness.push([0x00; 108].to_vec()); // fake signature
                }
        )*

            #[allow(unused_mut)]
        #[allow(unused_assignments)]
        let mut dust_change = false;
        $(
            $( $dust_change )*
                dust_change = true;
        )*

            let tx_fee_rate = $fees as f32 / (tx.get_weight().vbytes());
        let fee_rate = $fee_rate.as_sat_vb();

        if !dust_change {
            assert!((tx_fee_rate - fee_rate).abs() < 0.5, "Expected fee rate of {}, the tx has {}", fee_rate, tx_fee_rate);
        } else {
            assert!(tx_fee_rate >= fee_rate, "Expected fee rate of at least {}, the tx has {}", fee_rate, tx_fee_rate);
        }
    });
}

#[test]
#[should_panic(expected = "NoRecipients")]
fn test_create_tx_empty_recipients() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    wallet.build_tx().finish().unwrap();
}

#[test]
#[should_panic(expected = "NoUtxosSelected")]
fn test_create_tx_manually_selected_empty_utxos() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .manually_selected_only();
    builder.finish().unwrap();
}

#[test]
#[should_panic(expected = "Invalid version `0`")]
fn test_create_tx_version_0() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .version(0);
    builder.finish().unwrap();
}

#[test]
#[should_panic(
    expected = "TxBuilder requested version `1`, but at least `2` is needed to use OP_CSV"
)]
fn test_create_tx_version_1_csv() {
    let (wallet, _, _) = get_funded_wallet(get_test_single_sig_csv());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .version(1);
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_custom_version() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .version(42);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.version, 42);
}

#[test]
fn test_create_tx_default_locktime() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 25_000);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.lock_time, 0);
}

#[test]
fn test_create_tx_default_locktime_cltv() {
    let (wallet, _, _) = get_funded_wallet(get_test_single_sig_cltv());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 25_000);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.lock_time, 100_000);
}

#[test]
fn test_create_tx_custom_locktime() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .nlocktime(630_000);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.lock_time, 630_000);
}

#[test]
fn test_create_tx_custom_locktime_compatible_with_cltv() {
    let (wallet, _, _) = get_funded_wallet(get_test_single_sig_cltv());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .nlocktime(630_000);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.lock_time, 630_000);
}

#[test]
#[should_panic(
    expected = "TxBuilder requested timelock of `50000`, but at least `100000` is required to spend from this script"
)]
fn test_create_tx_custom_locktime_incompatible_with_cltv() {
    let (wallet, _, _) = get_funded_wallet(get_test_single_sig_cltv());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .nlocktime(50000);
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_no_rbf_csv() {
    let (wallet, _, _) = get_funded_wallet(get_test_single_sig_csv());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 25_000);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.input[0].sequence, 6);
}

#[test]
fn test_create_tx_with_default_rbf_csv() {
    let (wallet, _, _) = get_funded_wallet(get_test_single_sig_csv());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .enable_rbf();
    let (psbt, _) = builder.finish().unwrap();
    // When CSV is enabled it takes precedence over the rbf value (unless forced by the user).
    // It will be set to the OP_CSV value, in this case 6
    assert_eq!(psbt.global.unsigned_tx.input[0].sequence, 6);
}

#[test]
#[should_panic(expected = "Cannot enable RBF with nSequence `3` given a required OP_CSV of `6`")]
fn test_create_tx_with_custom_rbf_csv() {
    let (wallet, _, _) = get_funded_wallet(get_test_single_sig_csv());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .enable_rbf_with_sequence(3);
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_no_rbf_cltv() {
    let (wallet, _, _) = get_funded_wallet(get_test_single_sig_cltv());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 25_000);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.input[0].sequence, 0xFFFFFFFE);
}

#[test]
#[should_panic(expected = "Cannot enable RBF with a nSequence >= 0xFFFFFFFE")]
fn test_create_tx_invalid_rbf_sequence() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .enable_rbf_with_sequence(0xFFFFFFFE);
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_custom_rbf_sequence() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .enable_rbf_with_sequence(0xDEADBEEF);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.input[0].sequence, 0xDEADBEEF);
}

#[test]
fn test_create_tx_default_sequence() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 25_000);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.input[0].sequence, 0xFFFFFFFF);
}

#[test]
#[should_panic(
    expected = "The `change_policy` can be set only if the wallet has a change_descriptor"
)]
fn test_create_tx_change_policy_no_internal() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .do_not_spend_change();
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_drain_wallet_and_drain_to() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.output.len(), 1);
    assert_eq!(
        psbt.global.unsigned_tx.output[0].value,
        50_000 - details.fee.unwrap_or(0)
    );
}

#[test]
fn test_create_tx_drain_wallet_and_drain_to_and_with_recipient() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt").unwrap();
    let drain_addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 20_000)
        .drain_to(drain_addr.script_pubkey())
        .drain_wallet();
    let (psbt, details) = builder.finish().unwrap();
    let outputs = psbt.global.unsigned_tx.output;

    assert_eq!(outputs.len(), 2);
    let main_output = outputs
        .iter()
        .find(|x| x.script_pubkey == addr.script_pubkey())
        .unwrap();
    let drain_output = outputs
        .iter()
        .find(|x| x.script_pubkey == drain_addr.script_pubkey())
        .unwrap();
    assert_eq!(main_output.value, 20_000,);
    assert_eq!(drain_output.value, 30_000 - details.fee.unwrap_or(0));
}

#[test]
fn test_split_n_change() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let mut builder = wallet.build_tx();
    builder.drain_wallet().split_change(5_000, 5);
    let (psbt, details) = builder.finish().unwrap();
    let outputs = psbt.global.unsigned_tx.output;
    assert_eq!(outputs.len(), 6);
    assert_eq!(
        outputs.iter().filter(|txout| txout.value == 5_000).count(),
        5
    );
    assert_eq!(details.received, 50_000 - details.fee.unwrap_or(0));
}

#[test]
fn test_split_max_change() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let mut builder = wallet.build_tx();
    builder.drain_wallet().split_change(5_000, usize::MAX);
    let (psbt, details) = builder.finish().unwrap();
    let outputs = psbt.global.unsigned_tx.output;
    assert_eq!(outputs.len(), 10);
    assert_eq!(
        outputs.iter().filter(|txout| txout.value == 5_000).count(),
        9
    );
    let non_fixed_output = outputs.iter().find(|txout| txout.value != 5_000).unwrap();
    assert_eq!(non_fixed_output.value, 5_000 - details.fee.unwrap_or(0));
    assert_eq!(details.received, 50_000 - details.fee.unwrap_or(0));
}

#[test]
fn test_create_tx_default_fee_rate() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 25_000);
    let (psbt, details) = builder.finish().unwrap();

    assert_fee_rate!(psbt.extract_tx(), details.fee.unwrap_or(0), FeeRate::default(), @add_signature);
}

#[test]
fn test_create_tx_custom_fee_rate() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .fee_rate(FeeRate::from_sat_per_vb(5.0));
    let (psbt, details) = builder.finish().unwrap();

    assert_fee_rate!(psbt.extract_tx(), details.fee.unwrap_or(0), FeeRate::from_sat_per_vb(5.0), @add_signature);
}

#[test]
fn test_create_tx_absolute_fee() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_absolute(100);
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.fee.unwrap_or(0), 100);
    assert_eq!(psbt.global.unsigned_tx.output.len(), 1);
    assert_eq!(
        psbt.global.unsigned_tx.output[0].value,
        50_000 - details.fee.unwrap_or(0)
    );
}

#[test]
fn test_create_tx_absolute_zero_fee() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_absolute(0);
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.fee.unwrap_or(0), 0);
    assert_eq!(psbt.global.unsigned_tx.output.len(), 1);
    assert_eq!(
        psbt.global.unsigned_tx.output[0].value,
        50_000 - details.fee.unwrap_or(0)
    );
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn test_create_tx_absolute_high_fee() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_absolute(60_000);
    let (_psbt, _details) = builder.finish().unwrap();
}

#[test]
fn test_create_tx_add_change() {
    use super::tx_builder::TxOrdering;

    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .ordering(TxOrdering::Untouched);
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.output.len(), 2);
    assert_eq!(psbt.global.unsigned_tx.output[0].value, 25_000);
    assert_eq!(
        psbt.global.unsigned_tx.output[1].value,
        25_000 - details.fee.unwrap_or(0)
    );
}

#[test]
fn test_create_tx_skip_change_dust() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 49_800);
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.output.len(), 1);
    assert_eq!(psbt.global.unsigned_tx.output[0].value, 49_800);
    assert_eq!(details.fee.unwrap_or(0), 200);
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn test_create_tx_drain_to_dust_amount() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    // very high fee rate, so that the only output would be below dust
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .fee_rate(FeeRate::from_sat_per_vb(453.0));
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_ordering_respected() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 30_000)
        .add_recipient(addr.script_pubkey(), 10_000)
        .ordering(super::tx_builder::TxOrdering::Bip69Lexicographic);
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.output.len(), 3);
    assert_eq!(
        psbt.global.unsigned_tx.output[0].value,
        10_000 - details.fee.unwrap_or(0)
    );
    assert_eq!(psbt.global.unsigned_tx.output[1].value, 10_000);
    assert_eq!(psbt.global.unsigned_tx.output[2].value, 30_000);
}

#[test]
fn test_create_tx_default_sighash() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 30_000);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.inputs[0].sighash_type, None);
}

#[test]
fn test_create_tx_custom_sighash() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 30_000)
        .sighash(bitcoin::SigHashType::Single);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(
        psbt.inputs[0].sighash_type,
        Some(bitcoin::SigHashType::Single)
    );
}

#[test]
fn test_create_tx_input_hd_keypaths() {
    use bitcoin::util::bip32::{DerivationPath, Fingerprint};
    use std::str::FromStr;

    let (wallet, _, _) = get_funded_wallet("wpkh([d34db33f/44'/0'/0']tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.inputs[0].bip32_derivation.len(), 1);
    assert_eq!(
        psbt.inputs[0].bip32_derivation.values().next().unwrap(),
        &(
            Fingerprint::from_str("d34db33f").unwrap(),
            DerivationPath::from_str("m/44'/0'/0'/0/0").unwrap()
        )
    );
}

#[test]
fn test_create_tx_output_hd_keypaths() {
    use bitcoin::util::bip32::{DerivationPath, Fingerprint};
    use std::str::FromStr;

    let (wallet, descriptors, _) = get_funded_wallet("wpkh([d34db33f/44'/0'/0']tpubDEnoLuPdBep9bzw5LoGYpsxUQYheRQ9gcgrJhJEcdKFB9cWQRyYmkCyRoTqeD4tJYiVVgt6A3rN6rWn9RYhR9sBsGxji29LYWHuKKbdb1ev/0/*)");
    // cache some addresses
    wallet.get_address(New).unwrap();

    let addr = testutils!(@external descriptors, 5);
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.outputs[0].bip32_derivation.len(), 1);
    assert_eq!(
        psbt.outputs[0].bip32_derivation.values().next().unwrap(),
        &(
            Fingerprint::from_str("d34db33f").unwrap(),
            DerivationPath::from_str("m/44'/0'/0'/0/5").unwrap()
        )
    );
}

#[test]
fn test_create_tx_set_redeem_script_p2sh() {
    use bitcoin::hashes::hex::FromHex;

    let (wallet, _, _) =
        get_funded_wallet("sh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(
        psbt.inputs[0].redeem_script,
        Some(Script::from(
            Vec::<u8>::from_hex(
                "21032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3ac"
            )
            .unwrap()
        ))
    );
    assert_eq!(psbt.inputs[0].witness_script, None);
}

#[test]
fn test_create_tx_set_witness_script_p2wsh() {
    use bitcoin::hashes::hex::FromHex;

    let (wallet, _, _) =
        get_funded_wallet("wsh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.inputs[0].redeem_script, None);
    assert_eq!(
        psbt.inputs[0].witness_script,
        Some(Script::from(
            Vec::<u8>::from_hex(
                "21032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3ac"
            )
            .unwrap()
        ))
    );
}

#[test]
fn test_create_tx_set_redeem_witness_script_p2wsh_p2sh() {
    use bitcoin::hashes::hex::FromHex;

    let (wallet, _, _) =
        get_funded_wallet("sh(wsh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)))");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (psbt, _) = builder.finish().unwrap();

    let script = Script::from(
        Vec::<u8>::from_hex(
            "21032b0558078bec38694a84933d659303e2575dae7e91685911454115bfd64487e3ac",
        )
        .unwrap(),
    );

    assert_eq!(psbt.inputs[0].redeem_script, Some(script.to_v0_p2wsh()));
    assert_eq!(psbt.inputs[0].witness_script, Some(script));
}

#[test]
fn test_create_tx_non_witness_utxo() {
    let (wallet, _, _) =
        get_funded_wallet("sh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (psbt, _) = builder.finish().unwrap();

    assert!(psbt.inputs[0].non_witness_utxo.is_some());
    assert!(psbt.inputs[0].witness_utxo.is_none());
}

#[test]
fn test_create_tx_only_witness_utxo() {
    let (wallet, _, _) =
        get_funded_wallet("wsh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .only_witness_utxo()
        .drain_wallet();
    let (psbt, _) = builder.finish().unwrap();

    assert!(psbt.inputs[0].non_witness_utxo.is_none());
    assert!(psbt.inputs[0].witness_utxo.is_some());
}

#[test]
fn test_create_tx_shwpkh_has_witness_utxo() {
    let (wallet, _, _) =
        get_funded_wallet("sh(wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (psbt, _) = builder.finish().unwrap();

    assert!(psbt.inputs[0].witness_utxo.is_some());
}

#[test]
fn test_create_tx_both_non_witness_utxo_and_witness_utxo_default() {
    let (wallet, _, _) =
        get_funded_wallet("wsh(pk(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW))");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (psbt, _) = builder.finish().unwrap();

    assert!(psbt.inputs[0].non_witness_utxo.is_some());
    assert!(psbt.inputs[0].witness_utxo.is_some());
}

#[test]
fn test_create_tx_add_utxo() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    let small_output_txid = crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 30_000)
        .add_utxo(OutPoint {
            txid: small_output_txid,
            vout: 0,
        })
        .unwrap();
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(
        psbt.global.unsigned_tx.input.len(),
        2,
        "should add an additional input since 25_000 < 30_000"
    );
    assert_eq!(details.sent, 75_000, "total should be sum of both inputs");
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn test_create_tx_manually_selected_insufficient() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    let small_output_txid = crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 30_000)
        .add_utxo(OutPoint {
            txid: small_output_txid,
            vout: 0,
        })
        .unwrap()
        .manually_selected_only();
    builder.finish().unwrap();
}

#[test]
#[should_panic(expected = "SpendingPolicyRequired(External)")]
fn test_create_tx_policy_path_required() {
    let (wallet, _, _) = get_funded_wallet(get_test_a_or_b_plus_csv());

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 30_000);
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_policy_path_no_csv() {
    let (wallet, _, _) = get_funded_wallet(get_test_a_or_b_plus_csv());

    let external_policy = wallet.policies(KeychainKind::External).unwrap().unwrap();
    let root_id = external_policy.id;
    // child #0 is just the key "A"
    let path = vec![(root_id, vec![0])].into_iter().collect();

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 30_000)
        .policy_path(path, KeychainKind::External);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.input[0].sequence, 0xFFFFFFFF);
}

#[test]
fn test_create_tx_policy_path_use_csv() {
    let (wallet, _, _) = get_funded_wallet(get_test_a_or_b_plus_csv());

    let external_policy = wallet.policies(KeychainKind::External).unwrap().unwrap();
    let root_id = external_policy.id;
    // child #1 is or(pk(B),older(144))
    let path = vec![(root_id, vec![1])].into_iter().collect();

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 30_000)
        .policy_path(path, KeychainKind::External);
    let (psbt, _) = builder.finish().unwrap();

    assert_eq!(psbt.global.unsigned_tx.input[0].sequence, 144);
}

#[test]
fn test_create_tx_global_xpubs_with_origin() {
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::util::base58;
    use bitcoin::util::psbt::raw::Key;

    let (wallet, _, _) = get_funded_wallet("wpkh([73756c7f/48'/0'/0'/2']tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .add_global_xpubs();
    let (psbt, _) = builder.finish().unwrap();

    let type_value = 0x01;
    let key = base58::from_check("tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3").unwrap();

    let psbt_key = Key { type_value, key };

    // This key has an explicit origin, so it will be encoded here
    let value_bytes = Vec::<u8>::from_hex("73756c7f30000080000000800000008002000080").unwrap();

    assert_eq!(psbt.global.unknown.len(), 1);
    assert_eq!(psbt.global.unknown.get(&psbt_key), Some(&value_bytes));
}

#[test]
fn test_add_foreign_utxo() {
    let (wallet1, _, _) = get_funded_wallet(get_test_wpkh());
    let (wallet2, _, _) =
        get_funded_wallet("wpkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)");

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let utxo = wallet2.list_unspent().unwrap().remove(0);
    let foreign_utxo_satisfaction = wallet2
        .get_descriptor_for_keychain(KeychainKind::External)
        .max_satisfaction_weight()
        .unwrap();

    let psbt_input = psbt::Input {
        witness_utxo: Some(utxo.txout.clone()),
        ..Default::default()
    };

    let mut builder = wallet1.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 60_000)
        .only_witness_utxo()
        .add_foreign_utxo(utxo.outpoint, psbt_input, foreign_utxo_satisfaction)
        .unwrap();
    let (mut psbt, details) = builder.finish().unwrap();

    assert_eq!(
        details.sent - details.received,
        10_000 + details.fee.unwrap_or(0),
        "we should have only net spent ~10_000"
    );

    assert!(
        psbt.global
            .unsigned_tx
            .input
            .iter()
            .any(|input| input.previous_output == utxo.outpoint),
        "foreign_utxo should be in there"
    );

    let finished = wallet1
        .sign(
            &mut psbt,
            SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            },
        )
        .unwrap();

    assert!(
        !finished,
        "only one of the inputs should have been signed so far"
    );

    let finished = wallet2
        .sign(
            &mut psbt,
            SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(finished, "all the inputs should have been signed now");
}

#[test]
#[should_panic(expected = "Generic(\"Foreign utxo missing witness_utxo or non_witness_utxo\")")]
fn test_add_foreign_utxo_invalid_psbt_input() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let mut builder = wallet.build_tx();
    let outpoint = wallet.list_unspent().unwrap()[0].outpoint;
    let foreign_utxo_satisfaction = wallet
        .get_descriptor_for_keychain(KeychainKind::External)
        .max_satisfaction_weight()
        .unwrap();
    builder
        .add_foreign_utxo(outpoint, psbt::Input::default(), foreign_utxo_satisfaction)
        .unwrap();
}

#[test]
fn test_add_foreign_utxo_where_outpoint_doesnt_match_psbt_input() {
    let (wallet1, _, txid1) = get_funded_wallet(get_test_wpkh());
    let (wallet2, _, txid2) =
        get_funded_wallet("wpkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)");

    let utxo2 = wallet2.list_unspent().unwrap().remove(0);
    let tx1 = wallet1
        .database
        .borrow()
        .get_tx(&txid1, true)
        .unwrap()
        .unwrap()
        .transaction
        .unwrap();
    let tx2 = wallet2
        .database
        .borrow()
        .get_tx(&txid2, true)
        .unwrap()
        .unwrap()
        .transaction
        .unwrap();

    let satisfaction_weight = wallet2
        .get_descriptor_for_keychain(KeychainKind::External)
        .max_satisfaction_weight()
        .unwrap();

    let mut builder = wallet1.build_tx();
    assert!(
        builder
            .add_foreign_utxo(
                utxo2.outpoint,
                psbt::Input {
                    non_witness_utxo: Some(tx1),
                    ..Default::default()
                },
                satisfaction_weight
            )
            .is_err(),
        "should fail when outpoint doesn't match psbt_input"
    );
    assert!(
        builder
            .add_foreign_utxo(
                utxo2.outpoint,
                psbt::Input {
                    non_witness_utxo: Some(tx2),
                    ..Default::default()
                },
                satisfaction_weight
            )
            .is_ok(),
        "shoulld be ok when outpoint does match psbt_input"
    );
}

#[test]
fn test_add_foreign_utxo_only_witness_utxo() {
    let (wallet1, _, _) = get_funded_wallet(get_test_wpkh());
    let (wallet2, _, txid2) =
        get_funded_wallet("wpkh(cVbZ8ovhye9AoAHFsqobCf7LxbXDAECy9Kb8TZdfsDYMZGBUyCnm)");
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let utxo2 = wallet2.list_unspent().unwrap().remove(0);

    let satisfaction_weight = wallet2
        .get_descriptor_for_keychain(KeychainKind::External)
        .max_satisfaction_weight()
        .unwrap();

    let mut builder = wallet1.build_tx();
    builder.add_recipient(addr.script_pubkey(), 60_000);

    {
        let mut builder = builder.clone();
        let psbt_input = psbt::Input {
            witness_utxo: Some(utxo2.txout.clone()),
            ..Default::default()
        };
        builder
            .add_foreign_utxo(utxo2.outpoint, psbt_input, satisfaction_weight)
            .unwrap();
        assert!(
            builder.finish().is_err(),
            "psbt_input with witness_utxo should fail with only witness_utxo"
        );
    }

    {
        let mut builder = builder.clone();
        let psbt_input = psbt::Input {
            witness_utxo: Some(utxo2.txout.clone()),
            ..Default::default()
        };
        builder
            .only_witness_utxo()
            .add_foreign_utxo(utxo2.outpoint, psbt_input, satisfaction_weight)
            .unwrap();
        assert!(
            builder.finish().is_ok(),
            "psbt_input with just witness_utxo should succeed when `only_witness_utxo` is enabled"
        );
    }

    {
        let mut builder = builder.clone();
        let tx2 = wallet2
            .database
            .borrow()
            .get_tx(&txid2, true)
            .unwrap()
            .unwrap()
            .transaction
            .unwrap();
        let psbt_input = psbt::Input {
            non_witness_utxo: Some(tx2),
            ..Default::default()
        };
        builder
            .add_foreign_utxo(utxo2.outpoint, psbt_input, satisfaction_weight)
            .unwrap();
        assert!(
            builder.finish().is_ok(),
            "psbt_input with non_witness_utxo should succeed by default"
        );
    }
}

#[test]
fn test_get_psbt_input() {
    // this should grab a known good utxo and set the input
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    for utxo in wallet.list_unspent().unwrap() {
        let psbt_input = wallet.get_psbt_input(utxo, None, false).unwrap();
        assert!(psbt_input.witness_utxo.is_some() || psbt_input.non_witness_utxo.is_some());
    }
}

#[test]
#[should_panic(
    expected = "MissingKeyOrigin(\"tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3\")"
)]
fn test_create_tx_global_xpubs_origin_missing() {
    let (wallet, _, _) = get_funded_wallet("wpkh(tpubDCKxNyM3bLgbEX13Mcd8mYxbVg9ajDkWXMh29hMWBurKfVmBfWAM96QVP3zaUcN51HvkZ3ar4VwP82kC8JZhhux8vFQoJintSpVBwpFvyU3/0/*)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .add_global_xpubs();
    builder.finish().unwrap();
}

#[test]
fn test_create_tx_global_xpubs_master_without_origin() {
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::util::base58;
    use bitcoin::util::psbt::raw::Key;

    let (wallet, _, _) = get_funded_wallet("wpkh(tpubD6NzVbkrYhZ4Y55A58Gv9RSNF5hy84b5AJqYy7sCcjFrkcLpPre8kmgfit6kY1Zs3BLgeypTDBZJM222guPpdz7Cup5yzaMu62u7mYGbwFL/0/*)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .add_global_xpubs();
    let (psbt, _) = builder.finish().unwrap();

    let type_value = 0x01;
    let key = base58::from_check("tpubD6NzVbkrYhZ4Y55A58Gv9RSNF5hy84b5AJqYy7sCcjFrkcLpPre8kmgfit6kY1Zs3BLgeypTDBZJM222guPpdz7Cup5yzaMu62u7mYGbwFL").unwrap();

    let psbt_key = Key { type_value, key };

    // This key doesn't have an explicit origin, but it's a master key (depth = 0). So we encode
    // its fingerprint directly and an empty path
    let value_bytes = Vec::<u8>::from_hex("997a323b").unwrap();

    assert_eq!(psbt.global.unknown.len(), 1);
    assert_eq!(psbt.global.unknown.get(&psbt_key), Some(&value_bytes));
}

#[test]
#[should_panic(expected = "IrreplaceableTransaction")]
fn test_bump_fee_irreplaceable_tx() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 25_000);
    let (psbt, mut details) = builder.finish().unwrap();

    let tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the utxos, we know they can't be used anyways
    details.transaction = Some(tx);
    wallet.database.borrow_mut().set_tx(&details).unwrap();

    wallet.build_fee_bump(txid).unwrap().finish().unwrap();
}

#[test]
#[should_panic(expected = "TransactionConfirmed")]
fn test_bump_fee_confirmed_tx() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.add_recipient(addr.script_pubkey(), 25_000);
    let (psbt, mut details) = builder.finish().unwrap();

    let tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the utxos, we know they can't be used anyways
    details.transaction = Some(tx);
    details.confirmation_time = Some(ConfirmationTime {
        timestamp: 12345678,
        height: 42,
    });
    wallet.database.borrow_mut().set_tx(&details).unwrap();

    wallet.build_fee_bump(txid).unwrap().finish().unwrap();
}

#[test]
#[should_panic(expected = "FeeRateTooLow")]
fn test_bump_fee_low_fee_rate() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .enable_rbf();
    let (psbt, mut details) = builder.finish().unwrap();

    let tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the utxos, we know they can't be used anyways
    details.transaction = Some(tx);
    wallet.database.borrow_mut().set_tx(&details).unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(FeeRate::from_sat_per_vb(1.0));
    builder.finish().unwrap();
}

#[test]
#[should_panic(expected = "FeeTooLow")]
fn test_bump_fee_low_abs() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .enable_rbf();
    let (psbt, mut details) = builder.finish().unwrap();

    let tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the utxos, we know they can't be used anyways
    details.transaction = Some(tx);
    wallet.database.borrow_mut().set_tx(&details).unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_absolute(10);
    builder.finish().unwrap();
}

#[test]
#[should_panic(expected = "FeeTooLow")]
fn test_bump_fee_zero_abs() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .enable_rbf();
    let (psbt, mut details) = builder.finish().unwrap();

    let tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the utxos, we know they can't be used anyways
    details.transaction = Some(tx);
    wallet.database.borrow_mut().set_tx(&details).unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_absolute(0);
    builder.finish().unwrap();
}

#[test]
fn test_bump_fee_reduce_change() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the new utxos, we know they can't be used anyways
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(FeeRate::from_sat_per_vb(2.5)).enable_rbf();
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.sent, original_details.sent);
    assert_eq!(
        details.received + details.fee.unwrap_or(0),
        original_details.received + original_details.fee.unwrap_or(0)
    );
    assert!(details.fee.unwrap_or(0) > original_details.fee.unwrap_or(0));

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        25_000
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        details.received
    );

    assert_fee_rate!(psbt.extract_tx(), details.fee.unwrap_or(0), FeeRate::from_sat_per_vb(2.5), @add_signature);
}

#[test]
fn test_bump_fee_absolute_reduce_change() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 25_000)
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the new utxos, we know they can't be used anyways
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_absolute(200);
    builder.enable_rbf();
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.sent, original_details.sent);
    assert_eq!(
        details.received + details.fee.unwrap_or(0),
        original_details.received + original_details.fee.unwrap_or(0)
    );
    assert!(
        details.fee.unwrap_or(0) > original_details.fee.unwrap_or(0),
        "{} > {}",
        details.fee.unwrap_or(0),
        original_details.fee.unwrap_or(0)
    );

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        25_000
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        details.received
    );

    assert_eq!(details.fee.unwrap_or(0), 200);
}

#[test]
fn test_bump_fee_reduce_single_recipient() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .fee_rate(FeeRate::from_sat_per_vb(2.5))
        .allow_shrinking(addr.script_pubkey())
        .unwrap();
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.sent, original_details.sent);
    assert!(details.fee.unwrap_or(0) > original_details.fee.unwrap_or(0));

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].value + details.fee.unwrap_or(0), details.sent);

    assert_fee_rate!(psbt.extract_tx(), details.fee.unwrap_or(0), FeeRate::from_sat_per_vb(2.5), @add_signature);
}

#[test]
fn test_bump_fee_absolute_reduce_single_recipient() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .drain_wallet()
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .allow_shrinking(addr.script_pubkey())
        .unwrap()
        .fee_absolute(300);
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.sent, original_details.sent);
    assert!(details.fee.unwrap_or(0) > original_details.fee.unwrap_or(0));

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.output.len(), 1);
    assert_eq!(tx.output[0].value + details.fee.unwrap_or(0), details.sent);

    assert_eq!(details.fee.unwrap_or(0), 300);
}

#[test]
fn test_bump_fee_drain_wallet() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    // receive an extra tx so that our wallet has two utxos.
    let incoming_txid = crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );
    let outpoint = OutPoint {
        txid: incoming_txid,
        vout: 0,
    };
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .add_utxo(outpoint)
        .unwrap()
        .manually_selected_only()
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();
    assert_eq!(original_details.sent, 25_000);

    // for the new feerate, it should be enough to reduce the output, but since we specify
    // `drain_wallet` we expect to spend everything
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .drain_wallet()
        .allow_shrinking(addr.script_pubkey())
        .unwrap()
        .fee_rate(FeeRate::from_sat_per_vb(5.0));
    let (_, details) = builder.finish().unwrap();
    assert_eq!(details.sent, 75_000);
}

#[test]
#[should_panic(expected = "InsufficientFunds")]
fn test_bump_fee_remove_output_manually_selected_only() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    // receive an extra tx so that our wallet has two utxos. then we manually pick only one of
    // them, and make sure that `bump_fee` doesn't try to add more. This fails because we've
    // told the wallet it's not allowed to add more inputs AND it can't reduce the value of the
    // existing output. In other words, bump_fee + manually_selected_only is always an error
    // unless you've also set "allow_shrinking" OR there is a change output.
    let incoming_txid = crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );
    let outpoint = OutPoint {
        txid: incoming_txid,
        vout: 0,
    };
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .add_utxo(outpoint)
        .unwrap()
        .manually_selected_only()
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();
    assert_eq!(original_details.sent, 25_000);

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .manually_selected_only()
        .fee_rate(FeeRate::from_sat_per_vb(255.0));
    builder.finish().unwrap();
}

#[test]
fn test_bump_fee_add_input() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 45_000)
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the new utxos, we know they can't be used anyways
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(FeeRate::from_sat_per_vb(50.0));
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.sent, original_details.sent + 25_000);
    assert_eq!(details.fee.unwrap_or(0) + details.received, 30_000);

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        45_000
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        details.received
    );

    assert_fee_rate!(psbt.extract_tx(), details.fee.unwrap_or(0), FeeRate::from_sat_per_vb(50.0), @add_signature);
}

#[test]
fn test_bump_fee_absolute_add_input() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 45_000)
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the new utxos, we know they can't be used anyways
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_absolute(6_000);
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.sent, original_details.sent + 25_000);
    assert_eq!(details.fee.unwrap_or(0) + details.received, 30_000);

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        45_000
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        details.received
    );

    assert_eq!(details.fee.unwrap_or(0), 6_000);
}

#[test]
fn test_bump_fee_no_change_add_input_and_change() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    let incoming_txid = crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );

    // initially make a tx without change by using `drain_to`
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .add_utxo(OutPoint {
            txid: incoming_txid,
            vout: 0,
        })
        .unwrap()
        .manually_selected_only()
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();

    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the new utxos, we know they can't be used anyways
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    // now bump the fees without using `allow_shrinking`. the wallet should add an
    // extra input and a change output, and leave the original output untouched
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(FeeRate::from_sat_per_vb(50.0));
    let (psbt, details) = builder.finish().unwrap();

    let original_send_all_amount = original_details.sent - original_details.fee.unwrap_or(0);
    assert_eq!(details.sent, original_details.sent + 50_000);
    assert_eq!(
        details.received,
        75_000 - original_send_all_amount - details.fee.unwrap_or(0)
    );

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        original_send_all_amount
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        75_000 - original_send_all_amount - details.fee.unwrap_or(0)
    );

    assert_fee_rate!(psbt.extract_tx(), details.fee.unwrap_or(0), FeeRate::from_sat_per_vb(50.0), @add_signature);
}

#[test]
fn test_bump_fee_add_input_change_dust() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 45_000)
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    assert_eq!(tx.input.len(), 1);
    assert_eq!(tx.output.len(), 2);
    let txid = tx.txid();
    // skip saving the new utxos, we know they can't be used anyways
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder.fee_rate(FeeRate::from_sat_per_vb(140.0));
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(
        original_details.received,
        5_000 - original_details.fee.unwrap_or(0)
    );

    assert_eq!(details.sent, original_details.sent + 25_000);
    assert_eq!(details.fee.unwrap_or(0), 30_000);
    assert_eq!(details.received, 0);

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 1);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        45_000
    );

    assert_fee_rate!(psbt.extract_tx(), details.fee.unwrap_or(0), FeeRate::from_sat_per_vb(140.0), @dust_change, @add_signature);
}

#[test]
fn test_bump_fee_force_add_input() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    let incoming_txid = crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 45_000)
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the new utxos, we know they can't be used anyways
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    // the new fee_rate is low enough that just reducing the change would be fine, but we force
    // the addition of an extra input with `add_utxo()`
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .add_utxo(OutPoint {
            txid: incoming_txid,
            vout: 0,
        })
        .unwrap()
        .fee_rate(FeeRate::from_sat_per_vb(5.0));
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.sent, original_details.sent + 25_000);
    assert_eq!(details.fee.unwrap_or(0) + details.received, 30_000);

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        45_000
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        details.received
    );

    assert_fee_rate!(psbt.extract_tx(), details.fee.unwrap_or(0), FeeRate::from_sat_per_vb(5.0), @add_signature);
}

#[test]
fn test_bump_fee_absolute_force_add_input() {
    let (wallet, descriptors, _) = get_funded_wallet(get_test_wpkh());
    let incoming_txid = crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );

    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 45_000)
        .enable_rbf();
    let (psbt, mut original_details) = builder.finish().unwrap();
    let mut tx = psbt.extract_tx();
    let txid = tx.txid();
    // skip saving the new utxos, we know they can't be used anyways
    for txin in &mut tx.input {
        txin.witness.push([0x00; 108].to_vec()); // fake signature
        wallet
            .database
            .borrow_mut()
            .del_utxo(&txin.previous_output)
            .unwrap();
    }
    original_details.transaction = Some(tx);
    wallet
        .database
        .borrow_mut()
        .set_tx(&original_details)
        .unwrap();

    // the new fee_rate is low enough that just reducing the change would be fine, but we force
    // the addition of an extra input with `add_utxo()`
    let mut builder = wallet.build_fee_bump(txid).unwrap();
    builder
        .add_utxo(OutPoint {
            txid: incoming_txid,
            vout: 0,
        })
        .unwrap()
        .fee_absolute(250);
    let (psbt, details) = builder.finish().unwrap();

    assert_eq!(details.sent, original_details.sent + 25_000);
    assert_eq!(details.fee.unwrap_or(0) + details.received, 30_000);

    let tx = &psbt.global.unsigned_tx;
    assert_eq!(tx.input.len(), 2);
    assert_eq!(tx.output.len(), 2);
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey == addr.script_pubkey())
            .unwrap()
            .value,
        45_000
    );
    assert_eq!(
        tx.output
            .iter()
            .find(|txout| txout.script_pubkey != addr.script_pubkey())
            .unwrap()
            .value,
        details.received
    );

    assert_eq!(details.fee.unwrap_or(0), 250);
}

#[test]
fn test_sign_single_xprv() {
    let (wallet, _, _) = get_funded_wallet("wpkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (mut psbt, _) = builder.finish().unwrap();

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx();
    assert_eq!(extracted.input[0].witness.len(), 2);
}

#[test]
fn test_sign_single_xprv_with_master_fingerprint_and_path() {
    let (wallet, _, _) = get_funded_wallet("wpkh([d34db33f/84h/1h/0h]tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (mut psbt, _) = builder.finish().unwrap();

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx();
    assert_eq!(extracted.input[0].witness.len(), 2);
}

#[test]
fn test_sign_single_xprv_bip44_path() {
    let (wallet, _, _) = get_funded_wallet("wpkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/44'/0'/0'/0/*)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (mut psbt, _) = builder.finish().unwrap();

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx();
    assert_eq!(extracted.input[0].witness.len(), 2);
}

#[test]
fn test_sign_single_xprv_sh_wpkh() {
    let (wallet, _, _) = get_funded_wallet("sh(wpkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*))");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (mut psbt, _) = builder.finish().unwrap();

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx();
    assert_eq!(extracted.input[0].witness.len(), 2);
}

#[test]
fn test_sign_single_wif() {
    let (wallet, _, _) =
        get_funded_wallet("wpkh(cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (mut psbt, _) = builder.finish().unwrap();

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx();
    assert_eq!(extracted.input[0].witness.len(), 2);
}

#[test]
fn test_sign_single_xprv_no_hd_keypaths() {
    let (wallet, _, _) = get_funded_wallet("wpkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder.drain_to(addr.script_pubkey()).drain_wallet();
    let (mut psbt, _) = builder.finish().unwrap();

    psbt.inputs[0].bip32_derivation.clear();
    assert_eq!(psbt.inputs[0].bip32_derivation.len(), 0);

    let finalized = wallet.sign(&mut psbt, Default::default()).unwrap();
    assert!(finalized);

    let extracted = psbt.extract_tx();
    assert_eq!(extracted.input[0].witness.len(), 2);
}

#[test]
fn test_include_output_redeem_witness_script() {
    let (wallet, _, _) = get_funded_wallet("sh(wsh(multi(1,cVpPVruEDdmutPzisEsYvtST1usBR3ntr8pXSyt6D2YYqXRyPcFW,cRjo6jqfVNP33HhSS76UhXETZsGTZYx8FMFvR9kpbtCSV1PmdZdu)))");
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 45_000)
        .include_output_redeem_witness_script();
    let (psbt, _) = builder.finish().unwrap();

    // p2sh-p2wsh transaction should contain both witness and redeem scripts
    assert!(psbt
        .outputs
        .iter()
        .any(|output| output.redeem_script.is_some() && output.witness_script.is_some()));
}

#[test]
fn test_signing_only_one_of_multiple_inputs() {
    let (wallet, _, _) = get_funded_wallet(get_test_wpkh());
    let addr = Address::from_str("2N1Ffz3WaNzbeLFBb51xyFMHYSEUXcbiSoX").unwrap();
    let mut builder = wallet.build_tx();
    builder
        .add_recipient(addr.script_pubkey(), 45_000)
        .include_output_redeem_witness_script();
    let (mut psbt, _) = builder.finish().unwrap();

    // add another input to the psbt that is at least passable.
    let dud_input = bitcoin::util::psbt::Input {
        witness_utxo: Some(TxOut {
            value: 100_000,
            script_pubkey: miniscript::Descriptor::<bitcoin::PublicKey>::from_str(
                "wpkh(025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357)",
            )
            .unwrap()
            .script_pubkey(),
        }),
        ..Default::default()
    };

    psbt.inputs.push(dud_input);
    psbt.global.unsigned_tx.input.push(bitcoin::TxIn::default());
    let is_final = wallet
        .sign(
            &mut psbt,
            SignOptions {
                trust_witness_utxo: true,
                ..Default::default()
            },
        )
        .unwrap();
    assert!(
        !is_final,
        "shouldn't be final since we can't sign one of the inputs"
    );
    assert!(
        psbt.inputs[0].final_script_witness.is_some(),
        "should finalized input it signed"
    )
}

#[test]
fn test_sign_nonstandard_sighash() {
    let sighash = SigHashType::NonePlusAnyoneCanPay;

    let (wallet, _, _) = get_funded_wallet("wpkh(tprv8ZgxMBicQKsPd3EupYiPRhaMooHKUHJxNsTfYuScep13go8QFfHdtkG9nRkFGb7busX4isf6X9dURGCoKgitaApQ6MupRhZMcELAxTBRJgS/*)");
    let addr = wallet.get_address(New).unwrap();
    let mut builder = wallet.build_tx();
    builder
        .drain_to(addr.script_pubkey())
        .sighash(sighash)
        .drain_wallet();
    let (mut psbt, _) = builder.finish().unwrap();

    let result = wallet.sign(&mut psbt, Default::default());
    assert!(
        result.is_err(),
        "Signing should have failed because the TX uses non-standard sighashes"
    );
    assert!(
        matches!(
            result.unwrap_err(),
            Error::Signer(SignerError::NonStandardSighash)
        ),
        "Signing failed with the wrong error type"
    );

    // try again after opting-in
    let result = wallet.sign(
        &mut psbt,
        SignOptions {
            allow_all_sighashes: true,
            ..Default::default()
        },
    );
    assert!(result.is_ok(), "Signing should have worked");
    assert!(
        result.unwrap(),
        "Should finalize the input since we can produce signatures"
    );

    let extracted = psbt.extract_tx();
    assert_eq!(
        *extracted.input[0].witness[0].last().unwrap(),
        sighash.as_u32() as u8,
        "The signature should have been made with the right sighash"
    );
}

#[test]
fn test_unused_address() {
    let db = MemoryDatabase::new();
    let wallet = Wallet::new_offline("wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)",
                                     None, Network::Testnet, db).unwrap();

    assert_eq!(
        wallet.get_address(LastUnused).unwrap().to_string(),
        "tb1q6yn66vajcctph75pvylgkksgpp6nq04ppwct9a"
    );
    assert_eq!(
        wallet.get_address(LastUnused).unwrap().to_string(),
        "tb1q6yn66vajcctph75pvylgkksgpp6nq04ppwct9a"
    );
}

#[test]
fn test_next_unused_address() {
    let descriptor = "wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)";
    let descriptors = testutils!(@descriptors (descriptor));
    let wallet = Wallet::new_offline(
        &descriptors.0,
        None,
        Network::Testnet,
        MemoryDatabase::new(),
    )
    .unwrap();

    assert_eq!(
        wallet.get_address(LastUnused).unwrap().to_string(),
        "tb1q6yn66vajcctph75pvylgkksgpp6nq04ppwct9a"
    );

    // use the above address
    crate::populate_test_db!(
        wallet.database.borrow_mut(),
        testutils! (@tx ( (@external descriptors, 0) => 25_000 ) (@confirmations 1)),
        Some(100),
    );

    assert_eq!(
        wallet.get_address(LastUnused).unwrap().to_string(),
        "tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7"
    );
}

#[test]
fn test_peek_address_at_index() {
    let db = MemoryDatabase::new();
    let wallet = Wallet::new_offline("wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)",
                                     None, Network::Testnet, db).unwrap();

    assert_eq!(
        wallet.get_address(Peek(1)).unwrap().to_string(),
        "tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7"
    );

    assert_eq!(
        wallet.get_address(Peek(0)).unwrap().to_string(),
        "tb1q6yn66vajcctph75pvylgkksgpp6nq04ppwct9a"
    );

    assert_eq!(
        wallet.get_address(Peek(2)).unwrap().to_string(),
        "tb1qzntf2mqex4ehwkjlfdyy3ewdlk08qkvkvrz7x2"
    );

    // current new address is not affected
    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1q6yn66vajcctph75pvylgkksgpp6nq04ppwct9a"
    );

    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7"
    );
}

#[test]
fn test_peek_address_at_index_not_derivable() {
    let db = MemoryDatabase::new();
    let wallet = Wallet::new_offline("wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/1)",
                                     None, Network::Testnet, db).unwrap();

    assert_eq!(
        wallet.get_address(Peek(1)).unwrap().to_string(),
        "tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7"
    );

    assert_eq!(
        wallet.get_address(Peek(0)).unwrap().to_string(),
        "tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7"
    );

    assert_eq!(
        wallet.get_address(Peek(2)).unwrap().to_string(),
        "tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7"
    );
}

#[test]
fn test_reset_address_index() {
    let db = MemoryDatabase::new();
    let wallet = Wallet::new_offline("wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)",
                                     None, Network::Testnet, db).unwrap();

    // new index 0
    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1q6yn66vajcctph75pvylgkksgpp6nq04ppwct9a"
    );

    // new index 1
    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7"
    );

    // new index 2
    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1qzntf2mqex4ehwkjlfdyy3ewdlk08qkvkvrz7x2"
    );

    //  reset index 1 again
    assert_eq!(
        wallet.get_address(Reset(1)).unwrap().to_string(),
        "tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7"
    );

    // new index 2 again
    assert_eq!(
        wallet.get_address(New).unwrap().to_string(),
        "tb1qzntf2mqex4ehwkjlfdyy3ewdlk08qkvkvrz7x2"
    );
}

#[test]
fn test_returns_index_and_address() {
    let db = MemoryDatabase::new();
    let wallet = Wallet::new_offline("wpkh(tpubEBr4i6yk5nf5DAaJpsi9N2pPYBeJ7fZ5Z9rmN4977iYLCGco1VyjB9tvvuvYtfZzjD5A8igzgw3HeWeeKFmanHYqksqZXYXGsw5zjnj7KM9/*)",
                                     None, Network::Testnet, db).unwrap();

    // new index 0
    assert_eq!(
        wallet.get_address(New).unwrap(),
        AddressInfo {
            index: 0,
            address: Address::from_str("tb1q6yn66vajcctph75pvylgkksgpp6nq04ppwct9a").unwrap(),
        }
    );

    // new index 1
    assert_eq!(
        wallet.get_address(New).unwrap(),
        AddressInfo {
            index: 1,
            address: Address::from_str("tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7").unwrap()
        }
    );

    // peek index 25
    assert_eq!(
        wallet.get_address(Peek(25)).unwrap(),
        AddressInfo {
            index: 25,
            address: Address::from_str("tb1qsp7qu0knx3sl6536dzs0703u2w2ag6ppl9d0c2").unwrap()
        }
    );

    // new index 2
    assert_eq!(
        wallet.get_address(New).unwrap(),
        AddressInfo {
            index: 2,
            address: Address::from_str("tb1qzntf2mqex4ehwkjlfdyy3ewdlk08qkvkvrz7x2").unwrap()
        }
    );

    //  reset index 1 again
    assert_eq!(
        wallet.get_address(Reset(1)).unwrap(),
        AddressInfo {
            index: 1,
            address: Address::from_str("tb1q4er7kxx6sssz3q7qp7zsqsdx4erceahhax77d7").unwrap()
        }
    );

    // new index 2 again
    assert_eq!(
        wallet.get_address(New).unwrap(),
        AddressInfo {
            index: 2,
            address: Address::from_str("tb1qzntf2mqex4ehwkjlfdyy3ewdlk08qkvkvrz7x2").unwrap()
        }
    );
}
