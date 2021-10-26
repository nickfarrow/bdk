// Bitcoin Dev Kit
// Written in 2020 by Alekos Filini <alekos.filini@gmail.com>
//
// Copyright (c) 2020-2021 Bitcoin Dev Kit Developers
//
// This file is licensed under the Apache License, Version 2.0 <LICENSE-APACHE
// or http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your option.
// You may not use this file except in accordance with one or both of these
// licenses.

//! Esplora by way of `reqwest` HTTP client.

use std::collections::{HashMap, HashSet};

use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::{BlockHash, BlockHeader, Script, Transaction, Txid};

#[allow(unused_imports)]
use log::{debug, error, info, trace};

use ::reqwest::{Client, StatusCode};
use futures::stream::{FuturesOrdered, TryStreamExt};

use super::responses::{Tx, TxStatus};
use crate::blockchain::esplora::EsploraError;
use crate::blockchain::*;
use crate::database::BatchDatabase;
use crate::error::Error;
use crate::FeeRate;

const DEFAULT_CONCURRENT_REQUESTS: u8 = 4;

#[derive(Debug)]
struct UrlClient {
    url: String,
    // We use the async client instead of the blocking one because it automatically uses `fetch`
    // when the target platform is wasm32.
    client: Client,
    concurrency: u8,
}

/// Structure that implements the logic to sync with Esplora
///
/// ## Example
/// See the [`blockchain::esplora`](crate::blockchain::esplora) module for a usage example.
#[derive(Debug)]
pub struct EsploraBlockchain {
    url_client: UrlClient,
    stop_gap: usize,
}

impl std::convert::From<UrlClient> for EsploraBlockchain {
    fn from(url_client: UrlClient) -> Self {
        EsploraBlockchain {
            url_client,
            stop_gap: 20,
        }
    }
}

impl EsploraBlockchain {
    /// Create a new instance of the client from a base URL and `stop_gap`.
    pub fn new(base_url: &str, stop_gap: usize) -> Self {
        EsploraBlockchain {
            url_client: UrlClient {
                url: base_url.to_string(),
                client: Client::new(),
                concurrency: DEFAULT_CONCURRENT_REQUESTS,
            },
            stop_gap,
        }
    }

    /// Set the concurrency to use when doing batch queries against the Esplora instance.
    pub fn with_concurrency(mut self, concurrency: u8) -> Self {
        self.url_client.concurrency = concurrency;
        self
    }
}

#[maybe_async]
impl Blockchain for EsploraBlockchain {
    fn get_capabilities(&self) -> HashSet<Capability> {
        vec![
            Capability::FullHistory,
            Capability::GetAnyTx,
            Capability::AccurateFees,
        ]
        .into_iter()
        .collect()
    }

    fn setup<D: BatchDatabase, P: Progress>(
        &self,
        database: &mut D,
        _progress_update: P,
    ) -> Result<(), Error> {
        use crate::blockchain::script_sync::Request;
        let mut request = script_sync::start(database, self.stop_gap)?;
        let mut tx_index: HashMap<Txid, Tx> = HashMap::new();

        let batch_update = loop {
            request = match request {
                Request::Script(script_req) => {
                    let futures: FuturesOrdered<_> = script_req
                        .request()
                        .take(self.url_client.concurrency as usize)
                        .map(|script| async move {
                            let mut related_txs: Vec<Tx> =
                                self.url_client._scripthash_txs(script, None).await?;

                            let mut confirmed = vec![];
                            related_txs.retain(|tx| match tx.status {
                                TxStatus {
                                    confirmed: true,
                                    block_height: Some(_),
                                    block_time: Some(_),
                                } => {
                                    confirmed.push(tx.clone());
                                    false
                                }
                                _ => true,
                            });
                            let unconfirmed = related_txs;

                            if confirmed.len() >= 25 {
                                loop {
                                    let related_txs: Vec<Tx> = self
                                        .url_client
                                        ._scripthash_txs(
                                            script,
                                            Some(confirmed.last().unwrap().txid),
                                        )
                                        .await?;
                                    let n = related_txs.len();

                                    let related_confirmed_txs = related_txs
                                        .into_iter()
                                        .filter_map(|tx| match tx.status {
                                            TxStatus {
                                                confirmed: true,
                                                block_height: Some(_),
                                                block_time: Some(_),
                                            } => Some(tx),
                                            _ => None,
                                        })
                                        .collect::<Vec<_>>();

                                    debug_assert_eq!(
                                        related_confirmed_txs.len(),
                                        n,
                                        "all of them should be confirmed since it comes from /chain"
                                    );

                                    confirmed.extend(related_confirmed_txs);

                                    if n < 25 {
                                        break;
                                    }
                                }
                            }

                            Result::<_, Error>::Ok(
                                confirmed.into_iter().chain(unconfirmed).collect::<Vec<_>>(),
                            )
                        })
                        .collect();
                    let mut satisfaction = vec![];
                    let txs_per_script: Vec<Vec<Tx>> = await_or_block!(futures.try_collect())?;
                    for txs in txs_per_script {
                        satisfaction.push(
                            txs.iter()
                                .map(|tx| (tx.txid, tx.status.block_height))
                                .collect(),
                        );
                        for tx in txs {
                            tx_index.insert(tx.txid, tx);
                        }
                    }
                    script_req.satisfy(satisfaction)?
                }
                Request::Conftime(conftimereq) => {
                    let conftimes = conftimereq
                        .request()
                        .map(|txid| {
                            tx_index
                                .get(txid)
                                .expect("must be in index")
                                .confirmation_time()
                        })
                        .collect();
                    conftimereq.satisfy(conftimes)?
                }
                Request::Tx(txreq) => {
                    let full_txs = txreq
                        .request()
                        .map(|txid| {
                            let tx = tx_index.get(txid).expect("must be in index");
                            (tx.confirmation_time(), tx.previous_outputs(), tx.to_tx())
                        })
                        .collect();
                    txreq.satisfy(full_txs)?
                }
                Request::Finish(batch_update) => break batch_update,
            }
        };

        database.commit_batch(batch_update)?;

        Ok(())
    }

    fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        Ok(await_or_block!(self.url_client._get_tx(txid))?)
    }

    fn broadcast(&self, tx: &Transaction) -> Result<(), Error> {
        Ok(await_or_block!(self.url_client._broadcast(tx))?)
    }

    fn get_height(&self) -> Result<u32, Error> {
        Ok(await_or_block!(self.url_client._get_height())?)
    }

    fn estimate_fee(&self, target: usize) -> Result<FeeRate, Error> {
        let estimates = await_or_block!(self.url_client._get_fee_estimates())?;
        super::into_fee_rate(target, estimates)
    }
}

impl UrlClient {
    async fn _get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, EsploraError> {
        let resp = self
            .client
            .get(&format!("{}/tx/{}/raw", self.url, txid))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Ok(None);
        }

        Ok(Some(deserialize(&resp.error_for_status()?.bytes().await?)?))
    }

    async fn _get_tx_no_opt(&self, txid: &Txid) -> Result<Transaction, EsploraError> {
        match self._get_tx(txid).await {
            Ok(Some(tx)) => Ok(tx),
            Ok(None) => Err(EsploraError::TransactionNotFound(*txid)),
            Err(e) => Err(e),
        }
    }

    async fn _get_header(&self, block_height: u32) -> Result<BlockHeader, EsploraError> {
        let resp = self
            .client
            .get(&format!("{}/block-height/{}", self.url, block_height))
            .send()
            .await?;

        if let StatusCode::NOT_FOUND = resp.status() {
            return Err(EsploraError::HeaderHeightNotFound(block_height));
        }
        let bytes = resp.bytes().await?;
        let hash = std::str::from_utf8(&bytes)
            .map_err(|_| EsploraError::HeaderHeightNotFound(block_height))?;

        let resp = self
            .client
            .get(&format!("{}/block/{}/header", self.url, hash))
            .send()
            .await?;

        let header = deserialize(&Vec::from_hex(&resp.text().await?)?)?;

        Ok(header)
    }

    async fn _broadcast(&self, transaction: &Transaction) -> Result<(), EsploraError> {
        self.client
            .post(&format!("{}/tx", self.url))
            .body(serialize(transaction).to_hex())
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    async fn _get_height(&self) -> Result<u32, EsploraError> {
        let req = self
            .client
            .get(&format!("{}/blocks/tip/height", self.url))
            .send()
            .await?;

        Ok(req.error_for_status()?.text().await?.parse()?)
    }

    async fn _scripthash_txs(
        &self,
        script: &Script,
        last_seen: Option<Txid>,
    ) -> Result<Vec<Tx>, EsploraError> {
        let script_hash = sha256::Hash::hash(script.as_bytes()).into_inner().to_hex();
        let url = match last_seen {
            Some(last_seen) => format!("{}/scripthash/{}/txs/chain/{}", self.url, script_hash, last_seen),
            None => format!("{}/scripthash/{}/txs/chain", self.url, script_hash),
        };
        Ok(self
            .client
            .get(url)
            .send()
            .await?
            .error_for_status()?
            .json::<Vec<Tx>>()
            .await?)
    }

    async fn _get_fee_estimates(&self) -> Result<HashMap<String, f64>, EsploraError> {
        Ok(self
            .client
            .get(&format!("{}/fee-estimates", self.url,))
            .send()
            .await?
            .error_for_status()?
            .json::<HashMap<String, f64>>()
            .await?)
    }

    async fn _tx_state(
        &self,
        inputs: &[OutPoint],
        target_txid: Txid,
    ) -> Result<TxState, EsploraError> {
        #[derive(serde::Deserialize, Debug)]
        struct OutSpend {
            spent: bool,
            txid: Option<Txid>,
            vin: Option<u32>,
            status: Option<Status>,
        }
        #[derive(serde::Deserialize, Debug)]
        struct Status {
            confirmed: bool,
            block_height: Option<u32>,
            block_hash: Option<BlockHash>,
        }

        let mut state = TxState::NotFound;

        for (i, input) in inputs.iter().enumerate() {
            let url = format!("{}/tx/{}/outspend/{}", self.url, input.txid, input.vout);
            let outspend = self
                .client
                .get(&url)
                .send()
                .await?
                .error_for_status()?
                .json::<OutSpend>()
                .await?;

            if let OutSpend {
                txid: Some(txid),
                vin: Some(vin),
                status: Some(status),
                ..
            } = outspend
            {
                if txid == target_txid {
                    // If the node is telling us the input has been spent to the tx we're looking
                    // for then we can just exit.
                    return Ok(TxState::Present {
                        height: status.block_height,
                    });
                } else {
                    let existing_conflict_height = match state {
                        TxState::Conflict { height, .. } => height,
                        _ => None,
                    };
                    match (status.block_height, existing_conflict_height) {
                        (None, Some(_)) => {}
                        (Some(conflict_height), Some(existing_conflict_height))
                            if conflict_height > existing_conflict_height => {}
                        // overwrite unless the existing conflict is deeper in the chain
                        _ => {
                            state = TxState::Conflict {
                                txid,
                                vin,
                                vin_target: i as u32,
                                height: status.block_height,
                            }
                        }
                    }
                }
            }
        }

        Ok(state)
    }

    async fn _input_state(&self, inputs: &[OutPoint]) -> Result<InputState, EsploraError> {
        #[derive(serde::Deserialize, Debug)]
        struct OutSpend {
            spent: bool,
            txid: Option<Txid>,
            vin: Option<u32>,
            status: Option<Status>,
        }
        #[derive(serde::Deserialize, Debug)]
        struct Status {
            confirmed: bool,
            block_height: Option<u32>,
            block_hash: Option<BlockHash>,
        }

        let mut state = InputState::Unspent;

        for (i, input) in inputs.iter().enumerate() {
            let url = format!("{}/tx/{}/outspend/{}", self.url, input.txid, input.vout);
            let outspend = self
                .client
                .get(&url)
                .send()
                .await?
                .error_for_status()?
                .json::<OutSpend>()
                .await?;

            if let OutSpend {
                txid: Some(txid),
                vin: Some(vin),
                status: Some(status),
                ..
            } = outspend
            {
                let existing_spend_height = match state {
                    InputState::Spent { height, .. } => height,
                    _ => None,
                };

                match (status.block_height, existing_spend_height) {
                    (None, Some(_)) => {}
                    (Some(spend_height), Some(existing_spend_height))
                        if spend_height > existing_spend_height => {}
                    _ => {
                        state = InputState::Spent {
                            index: i as u32,
                            txid,
                            vin,
                            height: status.block_height,
                        }
                    }
                }
            }
        }

        Ok(state)
    }
}

#[maybe_async]
impl Broadcast for EsploraBlockchain {
    fn broadcast(&self, transaction: Transaction) -> Result<(), BroadcastError> {
        let url = format!("{}/tx", self.url_client.url);

        let res = await_or_block!(self
            .url_client
            .client
            .post(&url)
            .body(serialize(&transaction).to_hex())
            .send())
        .map_err(|_| BroadcastError::Http {
            status: None,
            url: url.clone(),
        })?;

        let http_error = BroadcastError::Http {
            status: Some(res.status().into()),
            url,
        };

        if res.status().is_client_error() {
            let text = await_or_block!(res.text()).map_err(|_| http_error.clone())?;
            Err(BroadcastTxError::from_core_rpc_response(&text)
                .map(BroadcastError::Tx)
                .unwrap_or(http_error))
        } else if res.status().is_server_error() {
            Err(http_error)
        } else {
            Ok(())
        }
    }
}

impl ConfigurableBlockchain for EsploraBlockchain {
    type Config = EsploraBlockchainConfig;

    fn from_config(config: &Self::Config) -> Result<Self, Error> {
        let map_e = |e: reqwest::Error| Error::Esplora(Box::new(e.into()));

        let mut blockchain = EsploraBlockchain::new(config.base_url.as_str(), config.stop_gap);
        if let Some(concurrency) = config.concurrency {
            blockchain.url_client.concurrency = concurrency;
        }
        #[cfg(not(target_arch = "wasm32"))]
        if let Some(proxy) = &config.proxy {
            blockchain.url_client.client = Client::builder()
                .proxy(reqwest::Proxy::all(proxy).map_err(map_e)?)
                .build()
                .map_err(map_e)?;
        }
        Ok(blockchain)
    }
}

#[maybe_async]
impl TransactionState for EsploraBlockchain {
    fn tx_input_state(&self, inputs: &[OutPoint], txid: Txid) -> Result<TxState, Error> {
        Ok(await_or_block!(self.url_client._tx_state(inputs, txid))?)
    }
}

#[maybe_async]
impl GetInputState for EsploraBlockchain {
    fn input_state(&self, inputs: &[OutPoint]) -> Result<InputState, Error> {
        Ok(await_or_block!(self.url_client._input_state(inputs))?)
    }
}
