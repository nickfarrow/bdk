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

//! Wallet
//!
//! This module defines the [`Wallet`] structure.

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use bitcoin::secp256k1::Secp256k1;

use bitcoin::consensus::encode::serialize;
use bitcoin::util::base58;
use bitcoin::util::psbt::raw::Key as PsbtKey;
use bitcoin::util::psbt::Input;
use bitcoin::util::psbt::PartiallySignedTransaction as Psbt;
use bitcoin::{Address, Network, OutPoint, Script, SigHashType, Transaction, TxOut, Txid};

use miniscript::descriptor::DescriptorTrait;
use miniscript::psbt::PsbtInputSatisfier;

#[allow(unused_imports)]
use log::{debug, error, info, trace};

pub mod address_validator;
pub mod coin_selection;
pub mod export;
pub mod signer;
pub mod time;
pub mod tx_builder;
pub(crate) mod utils;
#[cfg(feature = "verify")]
#[cfg_attr(docsrs, doc(cfg(feature = "verify")))]
pub mod verify;

#[cfg(test)]
pub mod test;

pub use utils::IsDust;

use address_validator::AddressValidator;
use coin_selection::DefaultCoinSelectionAlgorithm;
use signer::{SignOptions, Signer, SignerOrdering, SignersContainer};
use tx_builder::{BumpFee, CreateTx, FeePolicy, TxBuilder, TxParams};
use utils::{check_nlocktime, check_nsequence_rbf, After, Older, SecpCtx, DUST_LIMIT_SATOSHI};

use crate::blockchain::{Blockchain, Progress};
use crate::database::{BatchDatabase, BatchOperations, DatabaseUtils};
use crate::descriptor::derived::AsDerived;
use crate::descriptor::policy::BuildSatisfaction;
use crate::descriptor::{
    get_checksum, into_wallet_descriptor_checked, DerivedDescriptor, DerivedDescriptorMeta,
    DescriptorMeta, DescriptorScripts, ExtendedDescriptor, ExtractPolicy, IntoWalletDescriptor,
    Policy, XKeyUtils,
};
use crate::error::Error;
use crate::psbt::PsbtUtils;
use crate::signer::SignerError;
use crate::types::*;

const CACHE_ADDR_BATCH_SIZE: u32 = 100;

/// A Bitcoin wallet
///
/// A wallet takes descriptors, a [`database`](trait@crate::database::Database) and a
/// [`blockchain`](trait@crate::blockchain::Blockchain) and implements the basic functions that a Bitcoin wallets
/// needs to operate, like [generating addresses](Wallet::get_address), [returning the balance](Wallet::get_balance),
/// [creating transactions](Wallet::build_tx), etc.
///
/// A wallet can be either "online" if the [`blockchain`](crate::blockchain) type provided
/// implements [`Blockchain`], or "offline" if it is the unit type `()`. Offline wallets only expose
/// methods that don't need any interaction with the blockchain to work.
#[derive(Debug)]
pub struct Wallet<B, D> {
    descriptor: ExtendedDescriptor,
    change_descriptor: Option<ExtendedDescriptor>,

    signers: Arc<SignersContainer>,
    change_signers: Arc<SignersContainer>,

    address_validators: Vec<Arc<dyn AddressValidator>>,

    network: Network,

    current_height: Option<u32>,

    client: B,
    database: RefCell<D>,

    secp: SecpCtx,
}

impl<D> Wallet<(), D>
where
    D: BatchDatabase,
{
    /// Create a new "offline" wallet
    pub fn new_offline<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: Option<E>,
        network: Network,
        database: D,
    ) -> Result<Self, Error> {
        Self::_new(descriptor, change_descriptor, network, database, (), None)
    }
}

impl<B, D> Wallet<B, D>
where
    D: BatchDatabase,
{
    fn _new<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: Option<E>,
        network: Network,
        mut database: D,
        client: B,
        current_height: Option<u32>,
    ) -> Result<Self, Error> {
        let secp = Secp256k1::new();

        let (descriptor, keymap) = into_wallet_descriptor_checked(descriptor, &secp, network)?;
        database.check_descriptor_checksum(
            KeychainKind::External,
            get_checksum(&descriptor.to_string())?.as_bytes(),
        )?;
        let signers = Arc::new(SignersContainer::from(keymap));
        let (change_descriptor, change_signers) = match change_descriptor {
            Some(desc) => {
                let (change_descriptor, change_keymap) =
                    into_wallet_descriptor_checked(desc, &secp, network)?;
                database.check_descriptor_checksum(
                    KeychainKind::Internal,
                    get_checksum(&change_descriptor.to_string())?.as_bytes(),
                )?;

                let change_signers = Arc::new(SignersContainer::from(change_keymap));
                // if !parsed.same_structure(descriptor.as_ref()) {
                //     return Err(Error::DifferentDescriptorStructure);
                // }

                (Some(change_descriptor), change_signers)
            }
            None => (None, Arc::new(SignersContainer::new())),
        };

        Ok(Wallet {
            descriptor,
            change_descriptor,
            signers,
            change_signers,
            address_validators: Vec::new(),
            network,
            current_height,
            client,
            database: RefCell::new(database),
            secp,
        })
    }
}

/// The address index selection strategy to use to derived an address from the wallet's external
/// descriptor. See [`Wallet::get_address`]. If you're unsure which one to use use `WalletIndex::New`.
#[derive(Debug)]
pub enum AddressIndex {
    /// Return a new address after incrementing the current descriptor index.
    New,
    /// Return the address for the current descriptor index if it has not been used in a received
    /// transaction. Otherwise return a new address as with [`AddressIndex::New`].
    ///
    /// Use with caution, if the wallet has not yet detected an address has been used it could
    /// return an already used address. This function is primarily meant for situations where the
    /// caller is untrusted; for example when deriving donation addresses on-demand for a public
    /// web page.
    LastUnused,
    /// Return the address for a specific descriptor index. Does not change the current descriptor
    /// index used by `AddressIndex::New` and `AddressIndex::LastUsed`.
    ///
    /// Use with caution, if an index is given that is less than the current descriptor index
    /// then the returned address may have already been used.
    Peek(u32),
    /// Return the address for a specific descriptor index and reset the current descriptor index
    /// used by `AddressIndex::New` and `AddressIndex::LastUsed` to this value.
    ///
    /// Use with caution, if an index is given that is less than the current descriptor index
    /// then the returned address and subsequent addresses returned by calls to `AddressIndex::New`
    /// and `AddressIndex::LastUsed` may have already been used. Also if the index is reset to a
    /// value earlier than the [`crate::blockchain::Blockchain`] stop_gap (default is 20) then a
    /// larger stop_gap should be used to monitor for all possibly used addresses.
    Reset(u32),
}

/// A derived address and the index it was found at
/// For convenience this automatically derefs to `Address`
#[derive(Debug, PartialEq)]
pub struct AddressInfo {
    /// Child index of this address
    pub index: u32,
    /// Address
    pub address: Address,
}

impl Deref for AddressInfo {
    type Target = Address;

    fn deref(&self) -> &Self::Target {
        &self.address
    }
}

impl fmt::Display for AddressInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.address)
    }
}

// offline actions, always available
impl<B, D> Wallet<B, D>
where
    D: BatchDatabase,
{
    // Return a newly derived address using the external descriptor
    fn get_new_address(&self, keychain: KeychainKind) -> Result<AddressInfo, Error> {
        let incremented_index = self.fetch_and_increment_index(keychain)?;

        let address_result = self
            .get_descriptor_for_keychain(keychain)
            .as_derived(incremented_index, &self.secp)
            .address(self.network);

        address_result
            .map(|address| AddressInfo {
                address,
                index: incremented_index,
            })
            .map_err(|_| Error::ScriptDoesntHaveAddressForm)
    }

    // Return the the last previously derived address if it has not been used in a received
    // transaction. Otherwise return a new address using [`Wallet::get_new_address`].
    fn get_unused_address(&self, keychain: KeychainKind) -> Result<AddressInfo, Error> {
        let current_index = self.fetch_index(keychain)?;

        let derived_key = self
            .get_descriptor_for_keychain(keychain)
            .as_derived(current_index, &self.secp);

        let script_pubkey = derived_key.script_pubkey();

        let found_used = self
            .list_transactions(true)?
            .iter()
            .flat_map(|tx_details| tx_details.transaction.as_ref())
            .flat_map(|tx| tx.output.iter())
            .any(|o| o.script_pubkey == script_pubkey);

        if found_used {
            self.get_new_address(keychain)
        } else {
            derived_key
                .address(self.network)
                .map(|address| AddressInfo {
                    address,
                    index: current_index,
                })
                .map_err(|_| Error::ScriptDoesntHaveAddressForm)
        }
    }

    // Return derived address for the external descriptor at a specific index
    fn peek_address(&self, index: u32, keychain: KeychainKind) -> Result<AddressInfo, Error> {
        self.get_descriptor_for_keychain(keychain)
            .as_derived(index, &self.secp)
            .address(self.network)
            .map(|address| AddressInfo { index, address })
            .map_err(|_| Error::ScriptDoesntHaveAddressForm)
    }

    // Return derived address for the external descriptor at a specific index and reset current
    // address index
    fn reset_address(&self, index: u32, keychain: KeychainKind) -> Result<AddressInfo, Error> {
        self.set_index(keychain, index)?;

        self.get_descriptor_for_keychain(keychain)
            .as_derived(index, &self.secp)
            .address(self.network)
            .map(|address| AddressInfo { index, address })
            .map_err(|_| Error::ScriptDoesntHaveAddressForm)
    }

    /// Return a derived address using the external descriptor, see [`AddressIndex`] for
    /// available address index selection strategies. If none of the keys in the descriptor are derivable
    /// (ie. does not end with /*) then the same address will always be returned for any [`AddressIndex`].
    pub fn get_address(&self, address_index: AddressIndex) -> Result<AddressInfo, Error> {
        self._get_address(address_index, KeychainKind::External)
    }

    /// Return a derived address using the internal (change) descriptor, see [`AddressIndex`] for
    /// available address index selection strategies. If none of the keys in the descriptor are derivable
    /// (ie. does not end with /*) then the same address will always be returned for any [`AddressIndex`].
    pub fn get_change_address(&self, address_index: AddressIndex) -> Result<AddressInfo, Error> {
        self._get_address(address_index, KeychainKind::Internal)
    }

    fn _get_address(
        &self,
        address_index: AddressIndex,
        keychain: KeychainKind,
    ) -> Result<AddressInfo, Error> {
        match address_index {
            AddressIndex::New => self.get_new_address(keychain),
            AddressIndex::LastUnused => self.get_unused_address(keychain),
            AddressIndex::Peek(index) => self.peek_address(index, keychain),
            AddressIndex::Reset(index) => self.reset_address(index, keychain),
        }
    }

    /// Return whether or not a `script` is part of this wallet (either internal or external)
    pub fn is_mine(&self, script: &Script) -> Result<bool, Error> {
        self.database.borrow().is_mine(script)
    }

    /// Return the list of unspent outputs of this wallet
    ///
    /// Note that this methods only operate on the internal database, which first needs to be
    /// [`Wallet::sync`] manually.
    pub fn list_unspent(&self) -> Result<Vec<LocalUtxo>, Error> {
        self.database.borrow().iter_utxos()
    }

    /// Returns the `UTXO` owned by this wallet corresponding to `outpoint` if it exists in the
    /// wallet's database.
    pub fn get_utxo(&self, outpoint: OutPoint) -> Result<Option<LocalUtxo>, Error> {
        self.database.borrow().get_utxo(&outpoint)
    }

    /// Return the list of transactions made and received by the wallet
    ///
    /// Optionally fill the [`TransactionDetails::transaction`] field with the raw transaction if
    /// `include_raw` is `true`.
    ///
    /// Note that this methods only operate on the internal database, which first needs to be
    /// [`Wallet::sync`] manually.
    pub fn list_transactions(&self, include_raw: bool) -> Result<Vec<TransactionDetails>, Error> {
        self.database.borrow().iter_txs(include_raw)
    }

    /// Return the balance, meaning the sum of this wallet's unspent outputs' values
    ///
    /// Note that this methods only operate on the internal database, which first needs to be
    /// [`Wallet::sync`] manually.
    pub fn get_balance(&self) -> Result<u64, Error> {
        Ok(self
            .list_unspent()?
            .iter()
            .fold(0, |sum, i| sum + i.txout.value))
    }

    /// Add an external signer
    ///
    /// See [the `signer` module](signer) for an example.
    pub fn add_signer(
        &mut self,
        keychain: KeychainKind,
        ordering: SignerOrdering,
        signer: Arc<dyn Signer>,
    ) {
        let signers = match keychain {
            KeychainKind::External => Arc::make_mut(&mut self.signers),
            KeychainKind::Internal => Arc::make_mut(&mut self.change_signers),
        };

        signers.add_external(signer.id(&self.secp), ordering, signer);
    }

    /// Add an address validator
    ///
    /// See [the `address_validator` module](address_validator) for an example.
    pub fn add_address_validator(&mut self, validator: Arc<dyn AddressValidator>) {
        self.address_validators.push(validator);
    }

    /// Start building a transaction.
    ///
    /// This returns a blank [`TxBuilder`] from which you can specify the parameters for the transaction.
    ///
    /// ## Example
    ///
    /// ```
    /// # use std::str::FromStr;
    /// # use bitcoin::*;
    /// # use bdk::*;
    /// # use bdk::database::*;
    /// # let descriptor = "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/*)";
    /// # let wallet = doctest_wallet!();
    /// # let to_address = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt").unwrap();
    /// let (psbt, details) = {
    ///    let mut builder =  wallet.build_tx();
    ///    builder
    ///        .add_recipient(to_address.script_pubkey(), 50_000);
    ///    builder.finish()?
    /// };
    ///
    /// // sign and broadcast ...
    /// # Ok::<(), bdk::Error>(())
    /// ```
    ///
    /// [`TxBuilder`]: crate::TxBuilder
    pub fn build_tx(&self) -> TxBuilder<'_, B, D, DefaultCoinSelectionAlgorithm, CreateTx> {
        TxBuilder {
            wallet: self,
            params: TxParams::default(),
            coin_selection: DefaultCoinSelectionAlgorithm::default(),
            phantom: core::marker::PhantomData,
        }
    }

    pub(crate) fn create_tx<Cs: coin_selection::CoinSelectionAlgorithm<D>>(
        &self,
        coin_selection: Cs,
        params: TxParams,
    ) -> Result<(Psbt, TransactionDetails), Error> {
        let external_policy = self
            .descriptor
            .extract_policy(&self.signers, BuildSatisfaction::None, &self.secp)?
            .unwrap();
        let internal_policy = self
            .change_descriptor
            .as_ref()
            .map(|desc| {
                Ok::<_, Error>(
                    desc.extract_policy(&self.change_signers, BuildSatisfaction::None, &self.secp)?
                        .unwrap(),
                )
            })
            .transpose()?;

        // The policy allows spending external outputs, but it requires a policy path that hasn't been
        // provided
        if params.change_policy != tx_builder::ChangeSpendPolicy::OnlyChange
            && external_policy.requires_path()
            && params.external_policy_path.is_none()
        {
            return Err(Error::SpendingPolicyRequired(KeychainKind::External));
        };
        // Same for the internal_policy path, if present
        if let Some(internal_policy) = &internal_policy {
            if params.change_policy != tx_builder::ChangeSpendPolicy::ChangeForbidden
                && internal_policy.requires_path()
                && params.internal_policy_path.is_none()
            {
                return Err(Error::SpendingPolicyRequired(KeychainKind::Internal));
            };
        }

        let external_requirements = external_policy.get_condition(
            params
                .external_policy_path
                .as_ref()
                .unwrap_or(&BTreeMap::new()),
        )?;
        let internal_requirements = internal_policy
            .map(|policy| {
                Ok::<_, Error>(
                    policy.get_condition(
                        params
                            .internal_policy_path
                            .as_ref()
                            .unwrap_or(&BTreeMap::new()),
                    )?,
                )
            })
            .transpose()?;

        let requirements =
            external_requirements.merge(&internal_requirements.unwrap_or_default())?;
        debug!("Policy requirements: {:?}", requirements);

        let version = match params.version {
            Some(tx_builder::Version(0)) => {
                return Err(Error::Generic("Invalid version `0`".into()))
            }
            Some(tx_builder::Version(1)) if requirements.csv.is_some() => {
                return Err(Error::Generic(
                    "TxBuilder requested version `1`, but at least `2` is needed to use OP_CSV"
                        .into(),
                ))
            }
            Some(tx_builder::Version(x)) => x,
            None if requirements.csv.is_some() => 2,
            _ => 1,
        };

        let lock_time = match params.locktime {
            // No nLockTime, default to 0
            None => requirements.timelock.unwrap_or(0),
            // Specific nLockTime required and we have no constraints, so just set to that value
            Some(x) if requirements.timelock.is_none() => x,
            // Specific nLockTime required and it's compatible with the constraints
            Some(x) if check_nlocktime(x, requirements.timelock.unwrap()) => x,
            // Invalid nLockTime required
            Some(x) => return Err(Error::Generic(format!("TxBuilder requested timelock of `{}`, but at least `{}` is required to spend from this script", x, requirements.timelock.unwrap())))
        };

        let n_sequence = match (params.rbf, requirements.csv) {
            // No RBF or CSV but there's an nLockTime, so the nSequence cannot be final
            (None, None) if lock_time != 0 => 0xFFFFFFFE,
            // No RBF, CSV or nLockTime, make the transaction final
            (None, None) => 0xFFFFFFFF,

            // No RBF requested, use the value from CSV. Note that this value is by definition
            // non-final, so even if a timelock is enabled this nSequence is fine, hence why we
            // don't bother checking for it here. The same is true for all the other branches below
            (None, Some(csv)) => csv,

            // RBF with a specific value but that value is too high
            (Some(tx_builder::RbfValue::Value(rbf)), _) if rbf >= 0xFFFFFFFE => {
                return Err(Error::Generic(
                    "Cannot enable RBF with a nSequence >= 0xFFFFFFFE".into(),
                ))
            }
            // RBF with a specific value requested, but the value is incompatible with CSV
            (Some(tx_builder::RbfValue::Value(rbf)), Some(csv))
                if !check_nsequence_rbf(rbf, csv) =>
            {
                return Err(Error::Generic(format!(
                    "Cannot enable RBF with nSequence `{}` given a required OP_CSV of `{}`",
                    rbf, csv
                )))
            }

            // RBF enabled with the default value with CSV also enabled. CSV takes precedence
            (Some(tx_builder::RbfValue::Default), Some(csv)) => csv,
            // Valid RBF, either default or with a specific value. We ignore the `CSV` value
            // because we've already checked it before
            (Some(rbf), _) => rbf.get_value(),
        };

        let (fee_rate, mut fee_amount) = match params
            .fee_policy
            .as_ref()
            .unwrap_or(&FeePolicy::FeeRate(FeeRate::default()))
        {
            //FIXME: see https://github.com/bitcoindevkit/bdk/issues/256
            FeePolicy::FeeAmount(fee) => {
                if let Some(previous_fee) = params.bumping_fee {
                    if *fee < previous_fee.absolute {
                        return Err(Error::FeeTooLow {
                            required: previous_fee.absolute,
                        });
                    }
                }
                (FeeRate::from_sat_per_vb(0.0), *fee as f32)
            }
            FeePolicy::FeeRate(rate) => {
                if let Some(previous_fee) = params.bumping_fee {
                    let required_feerate = FeeRate::from_sat_per_vb(previous_fee.rate + 1.0);
                    if *rate < required_feerate {
                        return Err(Error::FeeRateTooLow {
                            required: required_feerate,
                        });
                    }
                }
                (*rate, 0.0)
            }
        };

        let mut tx = Transaction {
            version,
            lock_time,
            input: vec![],
            output: vec![],
        };

        if params.manually_selected_only && params.utxos.is_empty() {
            return Err(Error::NoUtxosSelected);
        }

        // we keep it as a float while we accumulate it, and only round it at the end
        let mut outgoing: u64 = 0;
        let mut received: u64 = 0;

        let calc_fee_bytes = |wu| (wu as f32) * fee_rate.as_sat_vb() / 4.0;
        fee_amount += calc_fee_bytes(tx.get_weight());

        let recipients = params.recipients.iter().map(|(r, v)| (r, *v));

        for (index, (script_pubkey, value)) in recipients.enumerate() {
            if value.is_dust() {
                return Err(Error::OutputBelowDustLimit(index));
            }

            if self.is_mine(script_pubkey)? {
                received += value;
            }

            let new_out = TxOut {
                script_pubkey: script_pubkey.clone(),
                value,
            };
            fee_amount += calc_fee_bytes(serialize(&new_out).len() * 4);

            tx.output.push(new_out);

            outgoing += value;
        }

        if params.change_policy != tx_builder::ChangeSpendPolicy::ChangeAllowed
            && self.change_descriptor.is_none()
        {
            return Err(Error::Generic(
                "The `change_policy` can be set only if the wallet has a change_descriptor".into(),
            ));
        }

        let (required_utxos, optional_utxos) = self.preselect_utxos(
            params.change_policy,
            &params.unspendable,
            params.utxos.clone(),
            params.drain_wallet,
            params.manually_selected_only,
            params.bumping_fee.is_some(), // we mandate confirmed transactions if we're bumping the fee
        )?;

        let coin_selection = coin_selection.coin_select(
            self.database.borrow().deref(),
            required_utxos,
            optional_utxos,
            fee_rate,
            outgoing,
            fee_amount,
        )?;
        let mut fee_amount = coin_selection.fee_amount;

        tx.input = coin_selection
            .selected
            .iter()
            .map(|u| bitcoin::TxIn {
                previous_output: u.outpoint(),
                script_sig: Script::default(),
                sequence: n_sequence,
                witness: vec![],
            })
            .collect();

        // prepare the drain output
        let mut drain_output = {
            let script_pubkey = match params.drain_to {
                Some(ref drain_recipient) => drain_recipient.clone(),
                None => self
                    .get_change_address(AddressIndex::New)?
                    .address
                    .script_pubkey(),
            };

            TxOut {
                script_pubkey,
                value: 0,
            }
        };

        fee_amount += calc_fee_bytes(serialize(&drain_output).len() * 4);

        let mut fee_amount = fee_amount.ceil() as u64;
        let mut drain_val =
            (coin_selection.selected_amount() - outgoing).saturating_sub(fee_amount);

        if tx.output.is_empty() {
            if params.drain_to.is_some() || params.split_change.is_some() {
                if drain_val.is_dust() {
                    return Err(Error::InsufficientFunds {
                        needed: DUST_LIMIT_SATOSHI,
                        available: drain_val,
                    });
                }
            } else {
                return Err(Error::NoRecipients);
            }
        }

        if let Some((shard_value, n)) = params.split_change {
            let mut i = 0;
            let utxo_overhead = {
                let tmp_output = TxOut {
                    script_pubkey: self
                        .get_change_address(AddressIndex::LastUnused)?
                        .address
                        .script_pubkey(),
                    value: shard_value,
                };
                calc_fee_bytes(serialize(&tmp_output).len() * 4).ceil() as u64
            };
            while drain_val >= shard_value + utxo_overhead && i < n {
                let change_txo = TxOut {
                    script_pubkey: self
                        .get_change_address(AddressIndex::New)?
                        .address
                        .script_pubkey(),
                    value: shard_value,
                };
                tx.output.push(change_txo);
                drain_val -= shard_value + utxo_overhead;
                fee_amount += utxo_overhead;
                received += shard_value;
                i += 1
            }
        }

        if drain_val.is_dust() {
            fee_amount += drain_val;
        } else {
            drain_output.value = drain_val;
            if self.is_mine(&drain_output.script_pubkey)? {
                received += drain_val;
            }
            tx.output.push(drain_output);
        }

        // sort input/outputs according to the chosen algorithm
        params.ordering.sort_tx(&mut tx);

        let txid = tx.txid();
        let sent = coin_selection.local_selected_amount();
        let psbt = self.complete_transaction(tx, coin_selection.selected, params)?;

        let transaction_details = TransactionDetails {
            transaction: None,
            txid,
            confirmation_time: None,
            received,
            sent,
            fee: Some(fee_amount),
            verified: true,
        };

        Ok((psbt, transaction_details))
    }

    /// Bump the fee of a transaction previously created with this wallet.
    ///
    /// Returns an error if the transaction is already confirmed or doesn't explicitly signal
    /// *repalce by fee* (RBF). If the transaction can be fee bumped then it returns a [`TxBuilder`]
    /// pre-populated with the inputs and outputs of the original transaction.
    ///
    /// ## Example
    ///
    /// ```no_run
    /// # // TODO: remove norun -- bumping fee seems to need the tx in the wallet database first.
    /// # use std::str::FromStr;
    /// # use bitcoin::*;
    /// # use bdk::*;
    /// # use bdk::database::*;
    /// # let descriptor = "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/*)";
    /// # let wallet = doctest_wallet!();
    /// # let to_address = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt").unwrap();
    /// let (mut psbt, _) = {
    ///     let mut builder = wallet.build_tx();
    ///     builder
    ///         .add_recipient(to_address.script_pubkey(), 50_000)
    ///         .enable_rbf();
    ///     builder.finish()?
    /// };
    /// let _ = wallet.sign(&mut psbt, SignOptions::default())?;
    /// let tx = psbt.extract_tx();
    /// // broadcast tx but it's taking too long to confirm so we want to bump the fee
    /// let (mut psbt, _) =  {
    ///     let mut builder = wallet.build_fee_bump(tx.txid())?;
    ///     builder
    ///         .fee_rate(FeeRate::from_sat_per_vb(5.0));
    ///     builder.finish()?
    /// };
    ///
    /// let _ = wallet.sign(&mut psbt, SignOptions::default())?;
    /// let fee_bumped_tx = psbt.extract_tx();
    /// // broadcast fee_bumped_tx to replace original
    /// # Ok::<(), bdk::Error>(())
    /// ```
    // TODO: support for merging multiple transactions while bumping the fees
    // TODO: option to force addition of an extra output? seems bad for privacy to update the
    // change
    pub fn build_fee_bump(
        &self,
        txid: Txid,
    ) -> Result<TxBuilder<'_, B, D, DefaultCoinSelectionAlgorithm, BumpFee>, Error> {
        let mut details = match self.database.borrow().get_tx(&txid, true)? {
            None => return Err(Error::TransactionNotFound),
            Some(tx) if tx.transaction.is_none() => return Err(Error::TransactionNotFound),
            Some(tx) if tx.confirmation_time.is_some() => return Err(Error::TransactionConfirmed),
            Some(tx) => tx,
        };
        let mut tx = details.transaction.take().unwrap();
        if !tx.input.iter().any(|txin| txin.sequence <= 0xFFFFFFFD) {
            return Err(Error::IrreplaceableTransaction);
        }

        let vbytes = tx.get_weight().vbytes();
        let feerate = details.fee.ok_or(Error::FeeRateUnavailable)? as f32 / vbytes;

        // remove the inputs from the tx and process them
        let original_txin = tx.input.drain(..).collect::<Vec<_>>();
        let original_utxos = original_txin
            .iter()
            .map(|txin| -> Result<_, Error> {
                let txout = self
                    .database
                    .borrow()
                    .get_previous_output(&txin.previous_output)?
                    .ok_or(Error::UnknownUtxo)?;

                let (weight, keychain) = match self
                    .database
                    .borrow()
                    .get_path_from_script_pubkey(&txout.script_pubkey)?
                {
                    Some((keychain, _)) => (
                        self._get_descriptor_for_keychain(keychain)
                            .0
                            .max_satisfaction_weight()
                            .unwrap(),
                        keychain,
                    ),
                    None => {
                        // estimate the weight based on the scriptsig/witness size present in the
                        // original transaction
                        let weight =
                            serialize(&txin.script_sig).len() * 4 + serialize(&txin.witness).len();
                        (weight, KeychainKind::External)
                    }
                };

                let utxo = LocalUtxo {
                    outpoint: txin.previous_output,
                    txout,
                    keychain,
                };

                Ok(WeightedUtxo {
                    satisfaction_weight: weight,
                    utxo: Utxo::Local(utxo),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        if tx.output.len() > 1 {
            let mut change_index = None;
            for (index, txout) in tx.output.iter().enumerate() {
                let (_, change_type) = self._get_descriptor_for_keychain(KeychainKind::Internal);
                match self
                    .database
                    .borrow()
                    .get_path_from_script_pubkey(&txout.script_pubkey)?
                {
                    Some((keychain, _)) if keychain == change_type => change_index = Some(index),
                    _ => {}
                }
            }

            if let Some(change_index) = change_index {
                tx.output.remove(change_index);
            }
        }

        let params = TxParams {
            // TODO: figure out what rbf option should be?
            version: Some(tx_builder::Version(tx.version)),
            recipients: tx
                .output
                .into_iter()
                .map(|txout| (txout.script_pubkey, txout.value))
                .collect(),
            utxos: original_utxos,
            bumping_fee: Some(tx_builder::PreviousFee {
                absolute: details.fee.ok_or(Error::FeeRateUnavailable)?,
                rate: feerate,
            }),
            ..Default::default()
        };

        Ok(TxBuilder {
            wallet: self,
            params,
            coin_selection: DefaultCoinSelectionAlgorithm::default(),
            phantom: core::marker::PhantomData,
        })
    }

    /// Sign a transaction with all the wallet's signers, in the order specified by every signer's
    /// [`SignerOrdering`]
    ///
    /// The [`SignOptions`] can be used to tweak the behavior of the software signers, and the way
    /// the transaction is finalized at the end. Note that it can't be guaranteed that *every*
    /// signers will follow the options, but the "software signers" (WIF keys and `xprv`) defined
    /// in this library will.
    ///
    /// ## Example
    ///
    /// ```
    /// # use std::str::FromStr;
    /// # use bitcoin::*;
    /// # use bdk::*;
    /// # use bdk::database::*;
    /// # let descriptor = "wpkh(tpubD6NzVbkrYhZ4Xferm7Pz4VnjdcDPFyjVu5K4iZXQ4pVN8Cks4pHVowTBXBKRhX64pkRyJZJN5xAKj4UDNnLPb5p2sSKXhewoYx5GbTdUFWq/*)";
    /// # let wallet = doctest_wallet!();
    /// # let to_address = Address::from_str("2N4eQYCbKUHCCTUjBJeHcJp9ok6J2GZsTDt").unwrap();
    /// let (mut psbt, _) = {
    ///     let mut builder = wallet.build_tx();
    ///     builder.add_recipient(to_address.script_pubkey(), 50_000);
    ///     builder.finish()?
    /// };
    /// let  finalized = wallet.sign(&mut psbt, SignOptions::default())?;
    /// assert!(finalized, "we should have signed all the inputs");
    /// # Ok::<(), bdk::Error>(())
    pub fn sign(&self, psbt: &mut Psbt, sign_options: SignOptions) -> Result<bool, Error> {
        // this helps us doing our job later
        self.add_input_hd_keypaths(psbt)?;

        // If we aren't allowed to use `witness_utxo`, ensure that every input but finalized one
        // has the `non_witness_utxo`
        if !sign_options.trust_witness_utxo
            && psbt
                .inputs
                .iter()
                .filter(|i| i.final_script_witness.is_none() && i.final_script_sig.is_none())
                .any(|i| i.non_witness_utxo.is_none())
        {
            return Err(Error::Signer(signer::SignerError::MissingNonWitnessUtxo));
        }

        // If the user hasn't explicitly opted-in, refuse to sign the transaction unless every input
        // is using `SIGHASH_ALL`
        if !sign_options.allow_all_sighashes
            && !psbt
                .inputs
                .iter()
                .all(|i| i.sighash_type.is_none() || i.sighash_type == Some(SigHashType::All))
        {
            return Err(Error::Signer(signer::SignerError::NonStandardSighash));
        }

        for signer in self
            .signers
            .signers()
            .iter()
            .chain(self.change_signers.signers().iter())
        {
            if signer.sign_whole_tx() {
                signer.sign(psbt, None, &self.secp)?;
            } else {
                for index in 0..psbt.inputs.len() {
                    signer.sign(psbt, Some(index), &self.secp)?;
                }
            }
        }

        // attempt to finalize
        self.finalize_psbt(psbt, sign_options)
    }

    /// Return the spending policies for the wallet's descriptor
    pub fn policies(&self, keychain: KeychainKind) -> Result<Option<Policy>, Error> {
        match (keychain, self.change_descriptor.as_ref()) {
            (KeychainKind::External, _) => Ok(self.descriptor.extract_policy(
                &self.signers,
                BuildSatisfaction::None,
                &self.secp,
            )?),
            (KeychainKind::Internal, None) => Ok(None),
            (KeychainKind::Internal, Some(desc)) => Ok(desc.extract_policy(
                &self.change_signers,
                BuildSatisfaction::None,
                &self.secp,
            )?),
        }
    }

    /// Return the "public" version of the wallet's descriptor, meaning a new descriptor that has
    /// the same structure but with every secret key removed
    ///
    /// This can be used to build a watch-only version of a wallet
    pub fn public_descriptor(
        &self,
        keychain: KeychainKind,
    ) -> Result<Option<ExtendedDescriptor>, Error> {
        match (keychain, self.change_descriptor.as_ref()) {
            (KeychainKind::External, _) => Ok(Some(self.descriptor.clone())),
            (KeychainKind::Internal, None) => Ok(None),
            (KeychainKind::Internal, Some(desc)) => Ok(Some(desc.clone())),
        }
    }

    /// Try to finalize a PSBT
    ///
    /// The [`SignOptions`] can be used to tweak the behavior of the finalizer.
    pub fn finalize_psbt(&self, psbt: &mut Psbt, sign_options: SignOptions) -> Result<bool, Error> {
        let tx = &psbt.global.unsigned_tx;
        let mut finished = true;

        for (n, input) in tx.input.iter().enumerate() {
            let psbt_input = &psbt
                .inputs
                .get(n)
                .ok_or(Error::Signer(SignerError::InputIndexOutOfRange))?;
            if psbt_input.final_script_sig.is_some() || psbt_input.final_script_witness.is_some() {
                continue;
            }
            // if the height is None in the database it means it's still unconfirmed, so consider
            // that as a very high value
            let create_height = self
                .database
                .borrow()
                .get_tx(&input.previous_output.txid, false)?
                .map(|tx| tx.confirmation_time.map(|c| c.height).unwrap_or(u32::MAX));
            let current_height = sign_options.assume_height.or(self.current_height);

            debug!(
                "Input #{} - {}, using `create_height` = {:?}, `current_height` = {:?}",
                n, input.previous_output, create_height, current_height
            );

            // - Try to derive the descriptor by looking at the txout. If it's in our database, we
            //   know exactly which `keychain` to use, and which derivation index it is
            // - If that fails, try to derive it by looking at the psbt input: the complete logic
            //   is in `src/descriptor/mod.rs`, but it will basically look at `bip32_derivation`,
            //   `redeem_script` and `witness_script` to determine the right derivation
            // - If that also fails, it will try it on the internal descriptor, if present
            let desc = psbt
                .get_utxo_for(n)
                .map(|txout| self.get_descriptor_for_script_pubkey(&txout.script_pubkey))
                .transpose()?
                .flatten()
                .or_else(|| {
                    self.descriptor.derive_from_psbt_input(
                        psbt_input,
                        psbt.get_utxo_for(n),
                        &self.secp,
                    )
                })
                .or_else(|| {
                    self.change_descriptor.as_ref().and_then(|desc| {
                        desc.derive_from_psbt_input(psbt_input, psbt.get_utxo_for(n), &self.secp)
                    })
                });

            match desc {
                Some(desc) => {
                    let mut tmp_input = bitcoin::TxIn::default();
                    match desc.satisfy(
                        &mut tmp_input,
                        (
                            PsbtInputSatisfier::new(psbt, n),
                            After::new(current_height, false),
                            Older::new(current_height, create_height, false),
                        ),
                    ) {
                        Ok(_) => {
                            let psbt_input = &mut psbt.inputs[n];
                            psbt_input.final_script_sig = Some(tmp_input.script_sig);
                            psbt_input.final_script_witness = Some(tmp_input.witness);
                        }
                        Err(e) => {
                            debug!("satisfy error {:?} for input {}", e, n);
                            finished = false
                        }
                    }
                }
                None => finished = false,
            }
        }

        Ok(finished)
    }

    /// Return the secp256k1 context used for all signing operations
    pub fn secp_ctx(&self) -> &SecpCtx {
        &self.secp
    }

    /// Returns the descriptor used to create adddresses for a particular `keychain`.
    pub fn get_descriptor_for_keychain(&self, keychain: KeychainKind) -> &ExtendedDescriptor {
        let (descriptor, _) = self._get_descriptor_for_keychain(keychain);
        descriptor
    }

    /// Get the descriptor for a given `script_pubkey` (if it exists in the wallet's database).
    pub fn get_descriptor_for_script_pubkey(
        &self,
        script_pubkey: &Script,
    ) -> Result<Option<DerivedDescriptor<'_>>, Error> {
        Ok(self
            .database
            .borrow()
            .get_path_from_script_pubkey(script_pubkey)?
            .map(|(keychain, child)| (self.get_descriptor_for_keychain(keychain), child))
            .map(|(desc, child)| desc.as_derived(child, &self.secp)))
    }

    /// Get a temporary refernce to the wallet's database to run querties against
    pub fn query_db<R>(&self, f: impl FnOnce(&D) -> R) -> R {
        let db = self.database.borrow();
        f(&*db)
    }

    // Internals

    fn _get_descriptor_for_keychain(
        &self,
        keychain: KeychainKind,
    ) -> (&ExtendedDescriptor, KeychainKind) {
        match keychain {
            KeychainKind::Internal if self.change_descriptor.is_some() => (
                self.change_descriptor.as_ref().unwrap(),
                KeychainKind::Internal,
            ),
            _ => (&self.descriptor, KeychainKind::External),
        }
    }

    fn fetch_and_increment_index(&self, keychain: KeychainKind) -> Result<u32, Error> {
        let (descriptor, keychain) = self._get_descriptor_for_keychain(keychain);
        let index = match descriptor.is_deriveable() {
            false => 0,
            true => self.database.borrow_mut().increment_last_index(keychain)?,
        };

        if self
            .database
            .borrow()
            .get_script_pubkey_from_path(keychain, index)?
            .is_none()
        {
            self.cache_addresses(keychain, index, CACHE_ADDR_BATCH_SIZE)?;
        }

        let derived_descriptor = descriptor.as_derived(index, &self.secp);

        let hd_keypaths = derived_descriptor.get_hd_keypaths(&self.secp)?;
        let script = derived_descriptor.script_pubkey();

        for validator in &self.address_validators {
            validator.validate(keychain, &hd_keypaths, &script)?;
        }

        Ok(index)
    }

    fn fetch_index(&self, keychain: KeychainKind) -> Result<u32, Error> {
        let (descriptor, keychain) = self._get_descriptor_for_keychain(keychain);
        let index = match descriptor.is_deriveable() {
            false => Some(0),
            true => self.database.borrow_mut().get_last_index(keychain)?,
        };

        if let Some(i) = index {
            Ok(i)
        } else {
            self.fetch_and_increment_index(keychain)
        }
    }

    fn set_index(&self, keychain: KeychainKind, index: u32) -> Result<(), Error> {
        self.database.borrow_mut().set_last_index(keychain, index)?;
        Ok(())
    }

    fn cache_addresses(
        &self,
        keychain: KeychainKind,
        from: u32,
        mut count: u32,
    ) -> Result<(), Error> {
        let (descriptor, keychain) = self._get_descriptor_for_keychain(keychain);
        if !descriptor.is_deriveable() {
            if from > 0 {
                return Ok(());
            }

            count = 1;
        }

        let mut address_batch = self.database.borrow().begin_batch();

        let start_time = time::Instant::new();
        for i in from..(from + count) {
            address_batch.set_script_pubkey(
                &descriptor.as_derived(i, &self.secp).script_pubkey(),
                keychain,
                i,
            )?;
        }

        info!(
            "Derivation of {} addresses from {} took {} ms",
            count,
            from,
            start_time.elapsed().as_millis()
        );

        self.database.borrow_mut().commit_batch(address_batch)?;

        Ok(())
    }

    fn get_available_utxos(&self) -> Result<Vec<(LocalUtxo, usize)>, Error> {
        Ok(self
            .list_unspent()?
            .into_iter()
            .map(|utxo| {
                let keychain = utxo.keychain;
                (
                    utxo,
                    self.get_descriptor_for_keychain(keychain)
                        .max_satisfaction_weight()
                        .unwrap(),
                )
            })
            .collect())
    }

    /// Given the options returns the list of utxos that must be used to form the
    /// transaction and any further that may be used if needed.
    #[allow(clippy::type_complexity)]
    fn preselect_utxos(
        &self,
        change_policy: tx_builder::ChangeSpendPolicy,
        unspendable: &HashSet<OutPoint>,
        manually_selected: Vec<WeightedUtxo>,
        must_use_all_available: bool,
        manual_only: bool,
        must_only_use_confirmed_tx: bool,
    ) -> Result<(Vec<WeightedUtxo>, Vec<WeightedUtxo>), Error> {
        //    must_spend <- manually selected utxos
        //    may_spend  <- all other available utxos
        let mut may_spend = self.get_available_utxos()?;

        may_spend.retain(|may_spend| {
            !manually_selected
                .iter()
                .any(|manually_selected| manually_selected.utxo.outpoint() == may_spend.0.outpoint)
        });
        let mut must_spend = manually_selected;

        // NOTE: we are intentionally ignoring `unspendable` here. i.e manual
        // selection overrides unspendable.
        if manual_only {
            return Ok((must_spend, vec![]));
        }

        let satisfies_confirmed = match must_only_use_confirmed_tx {
            true => {
                let database = self.database.borrow();
                may_spend
                    .iter()
                    .map(|u| {
                        database
                            .get_tx(&u.0.outpoint.txid, true)
                            .map(|tx| match tx {
                                None => false,
                                Some(tx) => tx.confirmation_time.is_some(),
                            })
                    })
                    .collect::<Result<Vec<_>, _>>()?
            }
            false => vec![true; may_spend.len()],
        };

        let mut i = 0;
        may_spend.retain(|u| {
            let retain = change_policy.is_satisfied_by(&u.0)
                && !unspendable.contains(&u.0.outpoint)
                && satisfies_confirmed[i];
            i += 1;
            retain
        });

        let mut may_spend = may_spend
            .into_iter()
            .map(|(local_utxo, satisfaction_weight)| WeightedUtxo {
                satisfaction_weight,
                utxo: Utxo::Local(local_utxo),
            })
            .collect();

        if must_use_all_available {
            must_spend.append(&mut may_spend);
        }

        Ok((must_spend, may_spend))
    }

    fn complete_transaction(
        &self,
        tx: Transaction,
        selected: Vec<Utxo>,
        params: TxParams,
    ) -> Result<Psbt, Error> {
        use bitcoin::util::psbt::serialize::Serialize;

        let mut psbt = Psbt::from_unsigned_tx(tx)?;

        if params.add_global_xpubs {
            let mut all_xpubs = self.descriptor.get_extended_keys()?;
            if let Some(change_descriptor) = &self.change_descriptor {
                all_xpubs.extend(change_descriptor.get_extended_keys()?);
            }

            for xpub in all_xpubs {
                let serialized_xpub = base58::from_check(&xpub.xkey.to_string())
                    .expect("Internal serialization error");
                let key = PsbtKey {
                    type_value: 0x01,
                    key: serialized_xpub,
                };

                let origin = match xpub.origin {
                    Some(origin) => origin,
                    None if xpub.xkey.depth == 0 => {
                        (xpub.root_fingerprint(&self.secp), vec![].into())
                    }
                    _ => return Err(Error::MissingKeyOrigin(xpub.xkey.to_string())),
                };

                psbt.global.unknown.insert(key, origin.serialize());
            }
        }

        let mut lookup_output = selected
            .into_iter()
            .map(|utxo| (utxo.outpoint(), utxo))
            .collect::<HashMap<_, _>>();

        // add metadata for the inputs
        for (psbt_input, input) in psbt
            .inputs
            .iter_mut()
            .zip(psbt.global.unsigned_tx.input.iter())
        {
            let utxo = match lookup_output.remove(&input.previous_output) {
                Some(utxo) => utxo,
                None => continue,
            };

            match utxo {
                Utxo::Local(utxo) => {
                    *psbt_input =
                        match self.get_psbt_input(utxo, params.sighash, params.only_witness_utxo) {
                            Ok(psbt_input) => psbt_input,
                            Err(e) => match e {
                                Error::UnknownUtxo => Input {
                                    sighash_type: params.sighash,
                                    ..Input::default()
                                },
                                _ => return Err(e),
                            },
                        }
                }
                Utxo::Foreign {
                    psbt_input: foreign_psbt_input,
                    outpoint,
                } => {
                    if !params.only_witness_utxo && foreign_psbt_input.non_witness_utxo.is_none() {
                        return Err(Error::Generic(format!(
                            "Missing non_witness_utxo on foreign utxo {}",
                            outpoint
                        )));
                    }
                    *psbt_input = *foreign_psbt_input;
                }
            }
        }

        // probably redundant but it doesn't hurt...
        self.add_input_hd_keypaths(&mut psbt)?;

        // add metadata for the outputs
        for (psbt_output, tx_output) in psbt
            .outputs
            .iter_mut()
            .zip(psbt.global.unsigned_tx.output.iter())
        {
            if let Some((keychain, child)) = self
                .database
                .borrow()
                .get_path_from_script_pubkey(&tx_output.script_pubkey)?
            {
                let (desc, _) = self._get_descriptor_for_keychain(keychain);
                let derived_descriptor = desc.as_derived(child, &self.secp);

                psbt_output.bip32_derivation = derived_descriptor.get_hd_keypaths(&self.secp)?;
                if params.include_output_redeem_witness_script {
                    psbt_output.witness_script = derived_descriptor.psbt_witness_script();
                    psbt_output.redeem_script = derived_descriptor.psbt_redeem_script();
                };
            }
        }

        Ok(psbt)
    }

    /// get the corresponding PSBT Input for a LocalUtxo
    pub fn get_psbt_input(
        &self,
        utxo: LocalUtxo,
        sighash_type: Option<SigHashType>,
        only_witness_utxo: bool,
    ) -> Result<Input, Error> {
        // Try to find the prev_script in our db to figure out if this is internal or external,
        // and the derivation index
        let (keychain, child) = self
            .database
            .borrow()
            .get_path_from_script_pubkey(&utxo.txout.script_pubkey)?
            .ok_or(Error::UnknownUtxo)?;

        let mut psbt_input = Input {
            sighash_type,
            ..Input::default()
        };

        let desc = self.get_descriptor_for_keychain(keychain);
        let derived_descriptor = desc.as_derived(child, &self.secp);
        psbt_input.bip32_derivation = derived_descriptor.get_hd_keypaths(&self.secp)?;

        psbt_input.redeem_script = derived_descriptor.psbt_redeem_script();
        psbt_input.witness_script = derived_descriptor.psbt_witness_script();

        let prev_output = utxo.outpoint;
        if let Some(prev_tx) = self.database.borrow().get_raw_tx(&prev_output.txid)? {
            if desc.is_witness() {
                psbt_input.witness_utxo = Some(prev_tx.output[prev_output.vout as usize].clone());
            }
            if !desc.is_witness() || !only_witness_utxo {
                psbt_input.non_witness_utxo = Some(prev_tx);
            }
        }
        Ok(psbt_input)
    }

    fn add_input_hd_keypaths(&self, psbt: &mut Psbt) -> Result<(), Error> {
        let mut input_utxos = Vec::with_capacity(psbt.inputs.len());
        for n in 0..psbt.inputs.len() {
            input_utxos.push(psbt.get_utxo_for(n).clone());
        }

        // try to add hd_keypaths if we've already seen the output
        for (psbt_input, out) in psbt.inputs.iter_mut().zip(input_utxos.iter()) {
            if let Some(out) = out {
                if let Some((keychain, child)) = self
                    .database
                    .borrow()
                    .get_path_from_script_pubkey(&out.script_pubkey)?
                {
                    debug!("Found descriptor {:?}/{}", keychain, child);

                    // merge hd_keypaths
                    let desc = self.get_descriptor_for_keychain(keychain);
                    let mut hd_keypaths = desc
                        .as_derived(child, &self.secp)
                        .get_hd_keypaths(&self.secp)?;
                    psbt_input.bip32_derivation.append(&mut hd_keypaths);
                }
            }
        }

        Ok(())
    }
}

impl<B, D> Wallet<B, D>
where
    B: Blockchain,
    D: BatchDatabase,
{
    /// Create a new "online" wallet
    #[maybe_async]
    pub fn new<E: IntoWalletDescriptor>(
        descriptor: E,
        change_descriptor: Option<E>,
        network: Network,
        database: D,
        client: B,
    ) -> Result<Self, Error> {
        let current_height = Some(maybe_await!(client.get_height())? as u32);
        Self::_new(
            descriptor,
            change_descriptor,
            network,
            database,
            client,
            current_height,
        )
    }

    /// Sync the internal database with the blockchain
    #[maybe_async]
    pub fn sync<P: 'static + Progress>(
        &self,
        progress_update: P,
        max_address_param: Option<u32>,
    ) -> Result<(), Error> {
        debug!("Begin sync...");

        let mut run_setup = false;

        let max_address = match self.descriptor.is_deriveable() {
            false => 0,
            true => max_address_param.unwrap_or(CACHE_ADDR_BATCH_SIZE),
        };
        debug!("max_address {}", max_address);
        if self
            .database
            .borrow()
            .get_script_pubkey_from_path(KeychainKind::External, max_address.saturating_sub(1))?
            .is_none()
        {
            debug!("caching external addresses");
            run_setup = true;
            self.cache_addresses(KeychainKind::External, 0, max_address)?;
        }

        if let Some(change_descriptor) = &self.change_descriptor {
            let max_address = match change_descriptor.is_deriveable() {
                false => 0,
                true => max_address_param.unwrap_or(CACHE_ADDR_BATCH_SIZE),
            };

            if self
                .database
                .borrow()
                .get_script_pubkey_from_path(KeychainKind::Internal, max_address.saturating_sub(1))?
                .is_none()
            {
                debug!("caching internal addresses");
                run_setup = true;
                self.cache_addresses(KeychainKind::Internal, 0, max_address)?;
            }
        }

        debug!("run_setup: {}", run_setup);
        // TODO: what if i generate an address first and cache some addresses?
        // TODO: we should sync if generating an address triggers a new batch to be stored
        if run_setup {
            maybe_await!(self
                .client
                .setup(self.database.borrow_mut().deref_mut(), progress_update,))?;
        } else {
            maybe_await!(self
                .client
                .sync(self.database.borrow_mut().deref_mut(), progress_update,))?;
        }

        #[cfg(feature = "verify")]
        {
            debug!("Verifying transactions...");
            for mut tx in self.database.borrow().iter_txs(true)? {
                if !tx.verified {
                    verify::verify_tx(
                        tx.transaction.as_ref().ok_or(Error::TransactionNotFound)?,
                        self.database.borrow().deref(),
                        &self.client,
                    )?;

                    tx.verified = true;
                    self.database.borrow_mut().set_tx(&tx)?;
                }
            }
        }

        Ok(())
    }

    /// Return a reference to the internal blockchain client
    pub fn client(&self) -> &B {
        &self.client
    }

    /// Get the Bitcoin network the wallet is using.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Broadcast a transaction to the network
    #[maybe_async]
    pub fn broadcast(&self, tx: Transaction) -> Result<Txid, Error> {
        maybe_await!(self.client.broadcast(&tx))?;

        Ok(tx.txid())
    }
}

/// Trait implemented by types that can be used to measure weight units.
pub trait Vbytes {
    /// Convert weight units to virtual bytes.
    fn vbytes(self) -> f32;
}

impl Vbytes for usize {
    fn vbytes(self) -> f32 {
        self as f32 / 4.0
    }
}
