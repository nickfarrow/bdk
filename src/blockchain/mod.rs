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

//! Blockchain backends
//!
//! This module provides the implementation of a few commonly-used backends like
//! [Electrum](crate::blockchain::electrum), [Esplora](crate::blockchain::esplora) and
//! [Compact Filters/Neutrino](crate::blockchain::compact_filters), along with a generalized trait
//! [`Blockchain`] that can be implemented to build customized backends.

use std::collections::HashSet;
use std::ops::Deref;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use bitcoin::{OutPoint, Transaction, Txid};

use crate::database::BatchDatabase;
use crate::error::Error;
use crate::FeeRate;

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
pub mod any;
mod script_sync;

#[cfg(any(
    feature = "electrum",
    feature = "esplora",
    feature = "compact_filters",
    feature = "rpc"
))]
pub use any::{AnyBlockchain, AnyBlockchainConfig};

#[cfg(feature = "electrum")]
#[cfg_attr(docsrs, doc(cfg(feature = "electrum")))]
pub mod electrum;
#[cfg(feature = "electrum")]
pub use self::electrum::ElectrumBlockchain;
#[cfg(feature = "electrum")]
pub use self::electrum::ElectrumBlockchainConfig;

#[cfg(feature = "rpc")]
#[cfg_attr(docsrs, doc(cfg(feature = "rpc")))]
pub mod rpc;
#[cfg(feature = "rpc")]
pub use self::rpc::RpcBlockchain;
#[cfg(feature = "rpc")]
pub use self::rpc::RpcConfig;

#[cfg(feature = "esplora")]
#[cfg_attr(docsrs, doc(cfg(feature = "esplora")))]
pub mod esplora;
#[cfg(feature = "esplora")]
pub use self::esplora::EsploraBlockchain;

#[cfg(feature = "compact_filters")]
#[cfg_attr(docsrs, doc(cfg(feature = "compact_filters")))]
pub mod compact_filters;

#[cfg(feature = "compact_filters")]
pub use self::compact_filters::CompactFiltersBlockchain;

/// Capabilities that can be supported by a [`Blockchain`] backend
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Can recover the full history of a wallet and not only the set of currently spendable UTXOs
    FullHistory,
    /// Can fetch any historical transaction given its txid
    GetAnyTx,
    /// Can compute accurate fees for the transactions found during sync
    AccurateFees,
}

/// Trait that defines the actions that must be supported by a blockchain backend
#[maybe_async]
pub trait Blockchain {
    /// Return the set of [`Capability`] supported by this backend
    fn get_capabilities(&self) -> HashSet<Capability>;

    /// Setup the backend and populate the internal database for the first time
    ///
    /// This method is the equivalent of [`Blockchain::sync`], but it's guaranteed to only be
    /// called once, at the first [`Wallet::sync`](crate::wallet::Wallet::sync).
    ///
    /// The rationale behind the distinction between `sync` and `setup` is that some custom backends
    /// might need to perform specific actions only the first time they are synced.
    ///
    /// For types that do not have that distinction, only this method can be implemented, since
    /// [`Blockchain::sync`] defaults to calling this internally if not overridden.
    fn setup<D: BatchDatabase, P: 'static + Progress>(
        &self,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error>;
    /// Populate the internal database with transactions and UTXOs
    ///
    /// If not overridden, it defaults to calling [`Blockchain::setup`] internally.
    ///
    /// This method should implement the logic required to iterate over the list of the wallet's
    /// script_pubkeys using [`Database::iter_script_pubkeys`] and look for relevant transactions
    /// in the blockchain to populate the database with [`BatchOperations::set_tx`] and
    /// [`BatchOperations::set_utxo`].
    ///
    /// This method should also take care of removing UTXOs that are seen as spent in the
    /// blockchain, using [`BatchOperations::del_utxo`].
    ///
    /// The `progress_update` object can be used to give the caller updates about the progress by using
    /// [`Progress::update`].
    ///
    /// [`Database::iter_script_pubkeys`]: crate::database::Database::iter_script_pubkeys
    /// [`BatchOperations::set_tx`]: crate::database::BatchOperations::set_tx
    /// [`BatchOperations::set_utxo`]: crate::database::BatchOperations::set_utxo
    /// [`BatchOperations::del_utxo`]: crate::database::BatchOperations::del_utxo
    fn sync<D: BatchDatabase, P: 'static + Progress>(
        &self,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error> {
        maybe_await!(self.setup(database, progress_update))
    }

    /// Fetch a transaction from the blockchain given its txid
    fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error>;
    /// Broadcast a transaction
    fn broadcast(&self, tx: &Transaction) -> Result<(), Error>;

    /// Return the current height
    fn get_height(&self) -> Result<u32, Error>;
    /// Estimate the fee rate required to confirm a transaction in a given `target` of blocks
    fn estimate_fee(&self, target: usize) -> Result<FeeRate, Error>;
}

/// Trait for [`Blockchain`] types that can be created given a configuration
pub trait ConfigurableBlockchain: Blockchain + Sized {
    /// Type that contains the configuration
    type Config: std::fmt::Debug;

    /// Create a new instance given a configuration
    fn from_config(config: &Self::Config) -> Result<Self, Error>;
}

/// Data sent with a progress update over a [`channel`]
pub type ProgressData = (f32, Option<String>);

/// Trait for types that can receive and process progress updates during [`Blockchain::sync`] and
/// [`Blockchain::setup`]
pub trait Progress: Send {
    /// Send a new progress update
    ///
    /// The `progress` value should be in the range 0.0 - 100.0, and the `message` value is an
    /// optional text message that can be displayed to the user.
    fn update(&self, progress: f32, message: Option<String>) -> Result<(), Error>;
}

/// Shortcut to create a [`channel`] (pair of [`Sender`] and [`Receiver`]) that can transport [`ProgressData`]
pub fn progress() -> (Sender<ProgressData>, Receiver<ProgressData>) {
    channel()
}

impl Progress for Sender<ProgressData> {
    fn update(&self, progress: f32, message: Option<String>) -> Result<(), Error> {
        if !(0.0..=100.0).contains(&progress) {
            return Err(Error::InvalidProgressValue(progress));
        }

        self.send((progress, message))
            .map_err(|_| Error::ProgressUpdateError)
    }
}

/// Type that implements [`Progress`] and drops every update received
#[derive(Clone, Copy)]
pub struct NoopProgress;

/// Create a new instance of [`NoopProgress`]
pub fn noop_progress() -> NoopProgress {
    NoopProgress
}

impl Progress for NoopProgress {
    fn update(&self, _progress: f32, _message: Option<String>) -> Result<(), Error> {
        Ok(())
    }
}

/// Type that implements [`Progress`] and logs at level `INFO` every update received
#[derive(Clone, Copy)]
pub struct LogProgress;

/// Create a new instance of [`LogProgress`]
pub fn log_progress() -> LogProgress {
    LogProgress
}

impl Progress for LogProgress {
    fn update(&self, progress: f32, message: Option<String>) -> Result<(), Error> {
        log::info!(
            "Sync {:.3}%: `{}`",
            progress,
            message.unwrap_or_else(|| "".into())
        );

        Ok(())
    }
}

#[maybe_async]
impl<T: Blockchain> Blockchain for Arc<T> {
    fn get_capabilities(&self) -> HashSet<Capability> {
        maybe_await!(self.deref().get_capabilities())
    }

    fn setup<D: BatchDatabase, P: 'static + Progress>(
        &self,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error> {
        maybe_await!(self.deref().setup(database, progress_update))
    }

    fn sync<D: BatchDatabase, P: 'static + Progress>(
        &self,
        database: &mut D,
        progress_update: P,
    ) -> Result<(), Error> {
        maybe_await!(self.deref().sync(database, progress_update))
    }

    fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        maybe_await!(self.deref().get_tx(txid))
    }
    fn broadcast(&self, tx: &Transaction) -> Result<(), Error> {
        maybe_await!(self.deref().broadcast(tx))
    }

    fn get_height(&self) -> Result<u32, Error> {
        maybe_await!(self.deref().get_height())
    }
    fn estimate_fee(&self, target: usize) -> Result<FeeRate, Error> {
        maybe_await!(self.deref().estimate_fee(target))
    }
}

/// Can get a UTXO
#[maybe_async]
pub trait UtxoExists: Blockchain {
    /// Checks if a UTXO exists
    fn utxo_exists(&self, outpoint: OutPoint) -> Result<bool, Error>;
}

/// A failure to broadcast a transaction.
#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum BroadcastError {
    /// The transaction was rejected by the node because it was invalid.
    #[error("transaction was not broadcast because {0}")]
    Tx(BroadcastTxError),
    /// There was an error making the HTTP on the backend
    #[error("there was a problem with the HTTP request to {url:} (status: {status:?})")]
    Http {
        /// HTTP status if we got a response.
        status: Option<u16>,
        /// path the POST request was made to
        url: String,
    },
    /// The electrum server returned an error while broadcasting the transaction.
    #[error("there was an error while broadcasting the transaction electrum server {0:}")]
    Other(String),
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
/// The reason the backend rejected the transaction we tried to broadcast.
pub enum BroadcastTxError {
    /// The transaction failed to verify (e.g. it had an invalid signature)
    #[error("the transaction was rejected by network rules ({0})")]
    VerifyRejected(String),
    /// The transaction was generally invalid (e.g. one of the inputs it is spending from doesn't exist)
    #[error("there was a general error while verifying the transaction ({0})")]
    VerifyError(String),
    /// That transaction has already been confirmed.
    #[error("the transaction has already been broadcast")]
    AlreadyInChain,
    /// The wallet contained an input from a coinbase transaction that wasn't matured yet.
    #[error("premature spend of coinbase output")]
    PrematureSpendOfCoinbase,
    /// The transaction conflicts with one that is already in the mempool (and that one is not
    /// replaceable).
    #[error("the transaction conflicts with one that is already in the mempool")]
    ConflictsWithMempool,
    /// The transaction has an input that is missing or spent.
    #[error("the transaction has an input that is missing or spent")]
    MissingOrSpent,
    /// At least one of the inputs had a witness  or script pubkey that did not satisfy the script pubkey
    #[error("the witness or scriptsig was invalid for one of the inputs (#{0})")]
    ScriptPubkeyNotSatisfied(String),
}

impl BroadcastTxError {
    /// parses a bitcoin core rpc `sendrawtransaction` call error response.
    pub fn from_core_rpc_response(text: &str) -> Option<Self> {
        text.strip_prefix("sendrawtransaction RPC error: ")
            .and_then(|text| match serde_json::from_str::<RpcError>(&text) {
                Ok(rpc_error) => Some(match rpc_error.code {
                    -25 => {
                        if rpc_error
                            .message
                            .starts_with("bad-txns-inputs-missingorspent")
                        {
                            BroadcastTxError::MissingOrSpent
                        } else {
                            BroadcastTxError::VerifyError(rpc_error.message)
                        }
                    }
                    -26 => {
                        if rpc_error
                            .message
                            .starts_with("bad-txns-premature-spend-of-coinbase")
                        {
                            BroadcastTxError::PrematureSpendOfCoinbase
                        } else if rpc_error.message.starts_with("txn-mempool-conflict") {
                            BroadcastTxError::ConflictsWithMempool
                        } else if let Some(remaining) = rpc_error
                            .message
                            .strip_prefix("non-mandatory-script-verify-flag")
                        {
                            let remaining =
                                remaining.trim_start_matches(" (").trim_end_matches(")");
                            BroadcastTxError::ScriptPubkeyNotSatisfied(remaining.into())
                        } else {
                            BroadcastTxError::VerifyRejected(rpc_error.message)
                        }
                    }
                    -27 => BroadcastTxError::AlreadyInChain,
                    _ => return None,
                }),
                Err(_e) => None,
            })
    }
}

#[derive(serde::Deserialize, Debug)]
struct RpcError {
    code: i32,
    message: String,
}

/// Trait representing the capability to broadcast a transaction
#[maybe_async]
pub trait Broadcast: Blockchain {
    /// Broadcasts a transaction
    fn broadcast(&self, tx: Transaction) -> Result<(), BroadcastError>;
}

/// The state of a transaction
#[derive(Clone, Debug, PartialEq)]
pub enum TxState {
    /// Not in the mempool or chain
    NotFound,
    /// conflicts with a tx in the mempool or chain
    Conflict {
        /// The conflicting transaction id
        txid: Txid,
        /// The index of the input that conflicts with the target transaction.
        vin: u32,
        /// The vin of the target transaction that is being spent by the conflicting transaction.
        vin_target: u32,
        /// Whether it is confirmed
        height: Option<u32>,
    },
    /// It is in the mempool or chain
    Present {
        /// Whether it is confirmed
        height: Option<u32>,
    },
}

#[maybe_async]
/// TransactionState
pub trait TransactionState {
    /// Get the state of a transaction given its inputs and txid
    fn tx_input_state(&self, inputs: &[OutPoint], txid: Txid) -> Result<TxState, Error>;
    /// Get the state of a transaction
    fn tx_state(&self, tx: &Transaction) -> Result<TxState, Error> {
        let inputs = tx
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect::<Vec<_>>();
        maybe_await!(self.tx_input_state(&inputs, tx.txid()))
    }
}

#[maybe_async]
/// GetInputState
pub trait GetInputState {
    /// Get the "state" of a set of utxos i.e. has any of them been spent.
    fn input_state(&self, inputs: &[OutPoint]) -> Result<InputState, Error>;
}

#[derive(Clone, Debug, PartialEq)]
/// The state of a set of inputs
pub enum InputState {
    /// One of the group of inputs was spent
    Spent {
        /// The index of the spent input in the input array
        index: u32,
        /// The txid of the spending tx
        txid: Txid,
        /// The vin of the spending tx that spends the input
        vin: u32,
        /// The height of the block that confirmed the tx
        height: Option<u32>,
    },
    /// None of them has been spent
    Unspent,
}
