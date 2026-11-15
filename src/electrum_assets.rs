//! ElectrumX-neurai asset, qualifier-tag, restricted-asset and messaging RPCs.
//!
//! Replies and subscription statuses follow `electrumx/server/session.py` of
//! electrumx-neurai byte for byte (field names, `{}` for "no data", heights of
//! `-1` for mempool entries, base58 for IPFS/TXID references, the exact
//! strings hashed into statuses), because electrum-neurai recomputes those
//! statuses locally and SPV-verifies the `source` / `tx_pos` it is given.
//!
//! Known ElectrumX bugs are not reproduced where clients don't depend on them:
//! asset names are always strings, `*.unsubscribe` returns whether the item
//! was subscribed, `tag.check` reports the real tag location, mempool tags are
//! merged into `tag.h160.list`, and association notifications echo `#NAME`.

use anyhow::{bail, Result};
use bitcoin::{
    hashes::{sha256, Hash},
    BlockHash, Transaction, Txid,
};
use serde_json::{json, Map, Value};

use std::collections::{BTreeMap, HashMap};

use crate::{
    electrum::{check_asset, check_h160, notification, py_str, truthy, Args, Client, Rpc},
    neurai::asset::parse_asset_script,
    types::{
        verifier_qualifiers, AssetEventKind, AssetEventPayload, AssetEventRow, AssetMetadata,
        AssetSource, ScriptHash,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AssetMethod {
    GetMeta,
    GetAssetsWithPrefix,
    ListAddressesByAsset,
    Broadcasts,
    IsFrozen,
    VerifierString,
    RestrictedAssociations,
    Subscribe,
    Unsubscribe,
    BroadcastsSubscribe,
    BroadcastsUnsubscribe,
    IsFrozenSubscribe,
    IsFrozenUnsubscribe,
    VerifierStringSubscribe,
    VerifierStringUnsubscribe,
    AssociationsSubscribe,
    AssociationsUnsubscribe,
    TagCheck,
    TagQualifierList,
    TagH160List,
    TagQualifierSubscribe,
    TagQualifierUnsubscribe,
    TagH160Subscribe,
    TagH160Unsubscribe,
    /// electrs-neurai extension
    GetHistory,
}

impl AssetMethod {
    /// Method, ElectrumX parameter names and number of required parameters.
    pub(crate) fn lookup(name: &str) -> Option<(AssetMethod, &'static [&'static str], usize)> {
        use AssetMethod::*;
        Some(match name {
            "blockchain.asset.get_meta" => (GetMeta, &["name", "include_mempool"], 1),
            "blockchain.asset.get_assets_with_prefix" => (GetAssetsWithPrefix, &["prefix"], 1),
            "blockchain.asset.list_addresses_by_asset" => (
                ListAddressesByAsset,
                &["asset", "onlytotal", "count", "start"],
                1,
            ),
            "blockchain.asset.broadcasts" => (Broadcasts, &["name"], 1),
            "blockchain.asset.is_frozen" => (IsFrozen, &["asset", "include_mempool"], 1),
            "blockchain.asset.verifier_string" => {
                (VerifierString, &["asset", "include_mempool"], 1)
            }
            "blockchain.asset.restricted_associations" => {
                (RestrictedAssociations, &["asset", "include_mempool"], 1)
            }
            "blockchain.asset.subscribe" => (Subscribe, &["asset"], 1),
            "blockchain.asset.unsubscribe" => (Unsubscribe, &["asset"], 1),
            "blockchain.asset.broadcasts.subscribe" => (BroadcastsSubscribe, &["asset"], 1),
            "blockchain.asset.broadcasts.unsubscribe" => (BroadcastsUnsubscribe, &["asset"], 1),
            "blockchain.asset.is_frozen.subscribe" => (IsFrozenSubscribe, &["asset"], 1),
            "blockchain.asset.is_frozen.unsubscribe" => (IsFrozenUnsubscribe, &["asset"], 1),
            "blockchain.asset.verifier_string.subscribe" => {
                (VerifierStringSubscribe, &["asset"], 1)
            }
            "blockchain.asset.verifier_string.unsubscribe" => {
                (VerifierStringUnsubscribe, &["asset"], 1)
            }
            "blockchain.asset.restricted_associations.subscribe" => {
                (AssociationsSubscribe, &["asset"], 1)
            }
            "blockchain.asset.restricted_associations.unsubscribe" => {
                (AssociationsUnsubscribe, &["asset"], 1)
            }
            "blockchain.tag.check" => (TagCheck, &["h160", "asset"], 2),
            "blockchain.tag.qualifier.list" => (TagQualifierList, &["asset", "include_mempool"], 1),
            "blockchain.tag.h160.list" => (TagH160List, &["h160", "include_mempool"], 1),
            "blockchain.tag.qualifier.subscribe" => (TagQualifierSubscribe, &["qualifier"], 1),
            "blockchain.tag.qualifier.unsubscribe" => (TagQualifierUnsubscribe, &["qualifier"], 1),
            "blockchain.tag.h160.subscribe" => (TagH160Subscribe, &["h160"], 1),
            "blockchain.tag.h160.unsubscribe" => (TagH160Unsubscribe, &["h160"], 1),
            "blockchain.asset.get_history" => (GetHistory, &["name"], 1),
            _ => return None,
        })
    }
}

/// Asset-related subscriptions of one client, with the last value sent.
#[derive(Default)]
pub(crate) struct AssetSubscriptions {
    assets: HashMap<String, Value>,
    qualifier_tags: HashMap<String, Value>,
    h160_tags: HashMap<[u8; 20], Value>,
    broadcasts: HashMap<String, Value>,
    frozen: HashMap<String, Value>,
    verifiers: HashMap<String, Value>,
    associations: HashMap<String, Value>,
    /// (tip, mempool generation) the stored values were computed at
    computed_at: Option<(BlockHash, u64)>,
}

impl AssetSubscriptions {
    fn is_empty(&self) -> bool {
        self.assets.is_empty()
            && self.qualifier_tags.is_empty()
            && self.h160_tags.is_empty()
            && self.broadcasts.is_empty()
            && self.frozen.is_empty()
            && self.verifiers.is_empty()
            && self.associations.is_empty()
    }
}

/// `sha256(s.encode()).hex()` — ElectrumX status hashes are *not* reversed.
fn status_hash(s: &str) -> Value {
    json!(sha256::Hash::hash(s.as_bytes()).to_string())
}

fn py_bool(b: bool) -> &'static str {
    if b {
        "True"
    } else {
        "False"
    }
}

fn source_json(source: &AssetSource) -> Value {
    json!({"tx_hash": source.txid, "tx_pos": source.vout, "height": source.height})
}

/// Height of an `asset_events` row as ElectrumX reports it (`-1` in mempool).
fn event_height(row: &AssetEventRow, mempool: bool) -> i64 {
    if mempool {
        -1
    } else {
        i64::from(row.height)
    }
}

fn tag_json(row: &AssetEventRow, flag: bool, mempool: bool) -> Value {
    json!({
        "flag": flag,
        "height": event_height(row, mempool),
        "tx_hash": row.txid,
        "tx_pos": row.vout,
    })
}

fn verifier_json(row: &AssetEventRow, string: &str, restricted_vout: u32, mempool: bool) -> Value {
    json!({
        "string": string,
        "height": event_height(row, mempool),
        "tx_hash": row.txid,
        "restricted_tx_pos": restricted_vout,
        "qualifying_tx_pos": row.vout,
    })
}

impl Rpc {
    pub(crate) fn asset_call(
        &self,
        client: &mut Client,
        method: AssetMethod,
        args: &Args,
    ) -> Result<Value> {
        use AssetMethod::*;
        let subs = &mut client.assets;
        match method {
            GetMeta => {
                let name = check_asset(args.req(0))?;
                Ok(self.asset_meta_json(&name, truthy(args.get(1), true)))
            }
            GetAssetsWithPrefix => {
                let prefix = check_asset(args.req(0))?.to_uppercase();
                Ok(json!(self
                    .tracker
                    .index()
                    .assets_with_prefix(prefix.as_bytes())))
            }
            ListAddressesByAsset => self.list_addresses_by_asset(args),
            Broadcasts => {
                let name = check_asset(args.req(0))?;
                Ok(json!(self.broadcasts(&name)))
            }
            IsFrozen => {
                let name = check_asset(args.req(0))?;
                Ok(self.frozen_json(&name, truthy(args.get(1), true)))
            }
            VerifierString => {
                let name = check_asset(args.req(0))?;
                self.verifier_json(&name, truthy(args.get(1), true))
            }
            RestrictedAssociations => {
                let name = check_asset(args.req(0))?;
                Ok(Value::Object(
                    self.associations(&name, truthy(args.get(1), true))?,
                ))
            }
            TagCheck => {
                let h160 = check_h160_after_asset(args)?;
                let name = check_asset(args.req(1))?;
                Ok(self.tag_check(&h160, &name))
            }
            TagQualifierList => {
                let name = check_asset(args.req(0))?;
                Ok(Value::Object(
                    self.qualifier_tags(&name, truthy(args.get(1), true)),
                ))
            }
            TagH160List => {
                let h160 = check_h160(args.req(0))?;
                Ok(Value::Object(
                    self.h160_tags(&h160, truthy(args.get(1), true)),
                ))
            }
            Subscribe => {
                let name = check_asset(args.req(0))?;
                let status = self.asset_status(&name);
                subs.assets.insert(name, status.clone());
                Ok(status)
            }
            Unsubscribe => {
                let name = check_asset(args.req(0))?;
                Ok(json!(subs.assets.remove(&name).is_some()))
            }
            BroadcastsSubscribe => {
                let name = check_asset(args.req(0))?;
                let status = self.broadcasts_status(&name);
                subs.broadcasts.insert(name, status.clone());
                Ok(status)
            }
            BroadcastsUnsubscribe => {
                let name = check_asset(args.req(0))?;
                Ok(json!(subs.broadcasts.remove(&name).is_some()))
            }
            IsFrozenSubscribe => {
                let name = check_asset(args.req(0))?;
                let result = self.frozen_json(&name, true);
                subs.frozen.insert(name, result.clone());
                Ok(result)
            }
            IsFrozenUnsubscribe => {
                let name = check_asset(args.req(0))?;
                Ok(json!(subs.frozen.remove(&name).is_some()))
            }
            VerifierStringSubscribe => {
                let name = check_asset(args.req(0))?;
                let result = self.verifier_json(&name, true)?;
                subs.verifiers.insert(name, result.clone());
                Ok(result)
            }
            VerifierStringUnsubscribe => {
                let name = check_asset(args.req(0))?;
                Ok(json!(subs.verifiers.remove(&name).is_some()))
            }
            AssociationsSubscribe => {
                let name = check_asset(args.req(0))?;
                require_qualifier(&name)?;
                let status = self.associations_status(&name)?;
                subs.associations.insert(name, status.clone());
                Ok(status)
            }
            AssociationsUnsubscribe => {
                let name = check_asset(args.req(0))?;
                require_qualifier(&name)?;
                Ok(json!(subs.associations.remove(&name).is_some()))
            }
            TagQualifierSubscribe => {
                let name = check_asset(args.req(0))?;
                let status = self.qualifier_tags_status(&name)?;
                subs.qualifier_tags.insert(name, status.clone());
                Ok(status)
            }
            TagQualifierUnsubscribe => {
                let name = check_asset(args.req(0))?;
                Ok(json!(subs.qualifier_tags.remove(&name).is_some()))
            }
            TagH160Subscribe => {
                let h160 = check_h160(args.req(0))?;
                let status = self.h160_tags_status(&h160);
                subs.h160_tags.insert(h160, status.clone());
                Ok(status)
            }
            TagH160Unsubscribe => {
                let h160 = check_h160(args.req(0))?;
                Ok(json!(subs.h160_tags.remove(&h160).is_some()))
            }
            GetHistory => {
                let name = check_asset(args.req(0))?;
                Ok(self.asset_history_json(&name))
            }
        }
    }

    /// Re-evaluate a client's asset subscriptions after a new block or a
    /// mempool change, returning a notification for every changed value.
    pub(crate) fn update_asset_subscriptions(
        &self,
        subs: &mut AssetSubscriptions,
    ) -> Result<Vec<Value>> {
        if subs.is_empty() {
            return Ok(vec![]);
        }
        let now = (
            self.tracker.chain().tip(),
            self.tracker.mempool().generation(),
        );
        if subs.computed_at == Some(now) {
            return Ok(vec![]);
        }
        subs.computed_at = Some(now);
        let mut notifications = vec![];
        let mut check = |method: &str, param: Value, old: &mut Value, new: Value| {
            if *old != new {
                *old = new.clone();
                notifications.push(notification(method, &[param, new]));
            }
        };
        for (name, old) in subs.assets.iter_mut() {
            check(
                "blockchain.asset.subscribe",
                json!(name),
                old,
                self.asset_status(name),
            );
        }
        for (name, old) in subs.qualifier_tags.iter_mut() {
            let new = self.qualifier_tags_status(name)?;
            check("blockchain.tag.qualifier.subscribe", json!(name), old, new);
        }
        for (h160, old) in subs.h160_tags.iter_mut() {
            let new = self.h160_tags_status(h160);
            check(
                "blockchain.tag.h160.subscribe",
                json!(hex_lower(h160)),
                old,
                new,
            );
        }
        for (name, old) in subs.broadcasts.iter_mut() {
            check(
                "blockchain.asset.broadcasts.subscribe",
                json!(name),
                old,
                self.broadcasts_status(name),
            );
        }
        for (name, old) in subs.frozen.iter_mut() {
            check(
                "blockchain.asset.is_frozen.subscribe",
                json!(name),
                old,
                self.frozen_json(name, true),
            );
        }
        for (name, old) in subs.verifiers.iter_mut() {
            let new = self.verifier_json(name, true)?;
            check(
                "blockchain.asset.verifier_string.subscribe",
                json!(name),
                old,
                new,
            );
        }
        for (name, old) in subs.associations.iter_mut() {
            let new = self.associations_status(name)?;
            check(
                "blockchain.asset.restricted_associations.subscribe",
                json!(name),
                old,
                new,
            );
        }
        Ok(notifications)
    }

    // ─── metadata ────────────────────────────────────────────────────────────

    pub(crate) fn asset_meta(&self, name: &str, include_mempool: bool) -> Option<AssetMetadata> {
        let mut state =
            AssetMetadata::fold(&self.tracker.index().asset_meta_events(name.as_bytes()));
        if include_mempool {
            for event in self.tracker.mempool().assets().meta(name.as_bytes()) {
                AssetMetadata::apply(&mut state, event, -1);
            }
        }
        state
    }

    /// `blockchain.asset.get_meta` (ElectrumX `asset_get_meta`); `{}` if unknown.
    fn asset_meta_json(&self, name: &str, include_mempool: bool) -> Value {
        let meta = match self.asset_meta(name, include_mempool) {
            Some(meta) => meta,
            None => return json!({}),
        };
        let mut result = Map::new();
        result.insert("sats_in_circulation".into(), json!(meta.amount));
        result.insert("divisions".into(), json!(meta.units));
        result.insert("reissuable".into(), json!(meta.reissuable));
        result.insert("has_ipfs".into(), json!(meta.has_ipfs()));
        if meta.has_ipfs() {
            result.insert(
                "ipfs".into(),
                json!(bitcoin::base58::encode(&meta.ipfs_data())),
            );
        }
        result.insert("source".into(), source_json(&meta.source));
        if meta.divisions_source != meta.source {
            result.insert(
                "source_divisions".into(),
                source_json(&meta.divisions_source),
            );
        }
        if let Some(ipfs_source) = meta
            .ipfs_source
            .filter(|s| meta.has_ipfs() && *s != meta.source)
        {
            result.insert("source_ipfs".into(), source_json(&ipfs_source));
        }
        if name.starts_with('&') {
            // electrs-neurai extension, like the daemon's `getassetdata`
            result.insert("transfer_state".into(), json!(self.depin_transfer_state(name)));
        }
        Value::Object(result)
    }

    /// Transfer state of a DePIN asset at the tip, as `getassetdata` reports it:
    /// the last confirmed state operation (the daemon validated each change),
    /// "closed" before any.
    fn depin_transfer_state(&self, name: &str) -> &'static str {
        let state = self
            .events(AssetEventKind::DepinState, name.as_bytes())
            .last()
            .and_then(|row| match row.payload {
                AssetEventPayload::DepinState { state, .. } => Some(state),
                _ => None,
            });
        match state {
            Some(1) => "open",
            Some(2) => "sealed",
            _ => "closed",
        }
    }

    /// ElectrumX `asset_status`.
    fn asset_status(&self, name: &str) -> Value {
        match self.asset_meta(name, true) {
            None => Value::Null,
            Some(meta) => {
                let mut s = format!(
                    "{}{}{}{}",
                    meta.amount,
                    meta.units,
                    py_bool(meta.reissuable),
                    py_bool(meta.has_ipfs())
                );
                if meta.has_ipfs() {
                    s.push_str(&bitcoin::base58::encode(&meta.ipfs_data()));
                }
                status_hash(&s)
            }
        }
    }

    fn list_addresses_by_asset(&self, args: &Args) -> Result<Value> {
        let asset = match args.req(0) {
            Value::String(asset) => asset.clone(),
            _ => bail!("\"asset\" must be a string"),
        };
        let onlytotal = match args.get(1) {
            None => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => bail!("\"onlytotal\" must be a boolean"),
        };
        // Python `isinstance(x, int)` (bools included)
        let python_int = |v: &Value| match v {
            Value::Bool(b) => Some(i64::from(*b)),
            Value::Number(n) => n.as_i64(),
            _ => None,
        };
        let count = match args.get(2) {
            None => 1000,
            Some(v) => match python_int(v) {
                Some(c) if (1..=1000).contains(&c) => c,
                _ => bail!("\"count\" must be an integer with a maximum value of 1000 and a minimum value of 1"),
            },
        };
        let start = match args.get(3) {
            None => 0,
            Some(v) => match python_int(v) {
                Some(s) if s >= 0 => s,
                _ => bail!("\"start\" must be an integer and 0 or greater"),
            },
        };
        let result = self.daemon.call(
            "listaddressesbyasset",
            &[json!(asset), json!(onlytotal), json!(count), json!(start)],
        )?;
        Ok(if onlytotal {
            json!({ "unique_addresses": result })
        } else {
            result
        })
    }

    // ─── qualifier tags and per-address freezes ─────────────────────────────

    fn events(&self, kind: AssetEventKind, key: &[u8]) -> Vec<AssetEventRow> {
        self.tracker.index().asset_events(kind, key)
    }

    fn mempool_events(&self, kind: AssetEventKind, key: &[u8]) -> Vec<AssetEventRow> {
        self.tracker.mempool().assets().events(kind, key).to_vec()
    }

    /// `blockchain.tag.qualifier.list`: latest tag per h160 (`#QUALIFIER`) or
    /// per-address freeze (`$RESTRICTED`).
    fn qualifier_tags(&self, name: &str, include_mempool: bool) -> Map<String, Value> {
        let mut result = BTreeMap::new();
        let mut apply = |row: &AssetEventRow, mempool: bool| {
            if let AssetEventPayload::Tag { h160, flag, .. } = &row.payload {
                result.insert(hex_lower(h160), tag_json(row, *flag, mempool));
            }
        };
        for row in self.events(AssetEventKind::TagByAsset, name.as_bytes()) {
            apply(&row, false);
        }
        if include_mempool {
            for row in self.mempool_events(AssetEventKind::TagByAsset, name.as_bytes()) {
                apply(&row, true);
            }
        }
        result.into_iter().collect()
    }

    /// `blockchain.tag.h160.list`: latest tag/freeze per asset for an h160.
    fn h160_tags(&self, h160: &[u8; 20], include_mempool: bool) -> Map<String, Value> {
        let mut result = BTreeMap::new();
        let mut apply = |row: &AssetEventRow, mempool: bool| {
            if let AssetEventPayload::Tag { asset, flag, .. } = &row.payload {
                result.insert(asset.clone(), tag_json(row, *flag, mempool));
            }
        };
        for row in self.events(AssetEventKind::TagByH160, h160) {
            apply(&row, false);
        }
        if include_mempool {
            for row in self.mempool_events(AssetEventKind::TagByH160, h160) {
                apply(&row, true);
            }
        }
        result.into_iter().collect()
    }

    /// `blockchain.tag.check` (confirmed state only, like ElectrumX).
    fn tag_check(&self, h160: &[u8; 20], name: &str) -> Value {
        self.events(AssetEventKind::TagByAsset, name.as_bytes())
            .iter()
            .rev()
            .find_map(|row| match &row.payload {
                AssetEventPayload::Tag {
                    h160: tagged, flag, ..
                } if tagged == h160 => Some(tag_json(row, *flag, false)),
                _ => None,
            })
            .unwrap_or_else(|| json!({}))
    }

    fn qualifier_tags_status(&self, name: &str) -> Result<Value> {
        if !name.starts_with('#') && !name.starts_with('$') {
            bail!("{} is not a qualifier nor a restricted asset", name);
        }
        let tags = self.qualifier_tags(name, true);
        Ok(tags_status(&tags))
    }

    fn h160_tags_status(&self, h160: &[u8; 20]) -> Value {
        tags_status(&self.h160_tags(h160, true))
    }

    // ─── restricted assets ───────────────────────────────────────────────────

    /// `blockchain.asset.is_frozen` (global freeze); `{}` if never frozen.
    fn frozen_json(&self, name: &str, include_mempool: bool) -> Value {
        let to_json = |row: &AssetEventRow, mempool: bool| match &row.payload {
            AssetEventPayload::Freeze { flag, .. } => Some(json!({
                "frozen": flag,
                "height": event_height(row, mempool),
                "tx_hash": row.txid,
                "tx_pos": row.vout,
            })),
            _ => None,
        };
        if include_mempool {
            if let Some(result) = self
                .mempool_events(AssetEventKind::Freeze, name.as_bytes())
                .first()
                .and_then(|row| to_json(row, true))
            {
                return result;
            }
        }
        self.events(AssetEventKind::Freeze, name.as_bytes())
            .last()
            .and_then(|row| to_json(row, false))
            .unwrap_or_else(|| json!({}))
    }

    /// `blockchain.asset.verifier_string`; `{}` if none.
    fn verifier_json(&self, name: &str, include_mempool: bool) -> Result<Value> {
        if !name.starts_with('$') {
            bail!("{} is not a restricted asset", name);
        }
        let to_json = |row: &AssetEventRow, mempool: bool| match &row.payload {
            AssetEventPayload::Verifier {
                string,
                restricted_vout,
                ..
            } => Some(verifier_json(row, string, *restricted_vout, mempool)),
            _ => None,
        };
        if include_mempool {
            if let Some(result) = self
                .mempool_events(AssetEventKind::Verifier, name.as_bytes())
                .first()
                .and_then(|row| to_json(row, true))
            {
                return Ok(result);
            }
        }
        Ok(self
            .events(AssetEventKind::Verifier, name.as_bytes())
            .last()
            .and_then(|row| to_json(row, false))
            .unwrap_or_else(|| json!({})))
    }

    /// `blockchain.asset.restricted_associations` for `#QUALIFIER`: for every
    /// restricted asset whose verifier ever mentioned it, the latest verifier
    /// change that added (`associated: true`) or removed (`false`) it.
    fn associations(&self, qualifier: &str, include_mempool: bool) -> Result<Map<String, Value>> {
        require_qualifier(qualifier)?;
        let mut candidates: Vec<String> = self
            .events(AssetEventKind::Association, qualifier.as_bytes())
            .into_iter()
            .chain(if include_mempool {
                self.mempool_events(AssetEventKind::Association, qualifier.as_bytes())
            } else {
                vec![]
            })
            .filter_map(|row| match row.payload {
                AssetEventPayload::Association { restricted, .. } => Some(restricted),
                _ => None,
            })
            .collect();
        candidates.sort();
        candidates.dedup();

        let wanted = qualifier.trim_start_matches('#');
        let mut result = Map::new();
        for restricted in candidates {
            let mut history: Vec<(AssetEventRow, bool)> = self
                .events(AssetEventKind::Verifier, restricted.as_bytes())
                .into_iter()
                .map(|row| (row, false))
                .collect();
            if include_mempool {
                history.extend(
                    self.mempool_events(AssetEventKind::Verifier, restricted.as_bytes())
                        .into_iter()
                        .take(1)
                        .map(|row| (row, true)),
                );
            }
            let mut previous: Vec<String> = vec![];
            let mut state: Option<(bool, &AssetEventRow, bool, u32)> = None;
            for (row, mempool) in &history {
                if let AssetEventPayload::Verifier {
                    string,
                    restricted_vout,
                    ..
                } = &row.payload
                {
                    let current = verifier_qualifiers(string);
                    let now = current.iter().any(|q| q == wanted);
                    let before = previous.iter().any(|q| q == wanted);
                    if now || before {
                        state = Some((now, row, *mempool, *restricted_vout));
                    }
                    previous = current;
                }
            }
            if let Some((associated, row, mempool, restricted_vout)) = state {
                result.insert(
                    restricted,
                    json!({
                        "associated": associated,
                        "height": event_height(row, mempool),
                        "tx_hash": row.txid,
                        "restricted_tx_pos": restricted_vout,
                        "qualifying_tx_pos": row.vout,
                    }),
                );
            }
        }
        Ok(result)
    }

    fn associations_status(&self, qualifier: &str) -> Result<Value> {
        let data = self.associations(qualifier, true)?;
        if data.is_empty() {
            return Ok(Value::Null);
        }
        let s = data
            .iter()
            .map(|(asset, d)| {
                format!(
                    "{}:{}{}{}{}{}",
                    asset,
                    d["height"],
                    py_str(&d["tx_hash"]),
                    d["restricted_tx_pos"],
                    d["qualifying_tx_pos"],
                    py_bool(d["associated"].as_bool().unwrap_or(false))
                )
            })
            .collect::<Vec<_>>()
            .join(";");
        Ok(status_hash(&s))
    }

    // ─── broadcasts ──────────────────────────────────────────────────────────

    /// `blockchain.asset.broadcasts`: messages on owner-token / channel
    /// transfers whose transaction spent that asset from the same script,
    /// newest first (ElectrumX sorts by `(height, tx_hash)` descending).
    fn broadcasts(&self, name: &str) -> Vec<Value> {
        let mut items: Vec<(u32, String, Value)> = self
            .events(AssetEventKind::Broadcast, name.as_bytes())
            .into_iter()
            .filter(|row| self.broadcast_is_valid(row))
            .filter_map(|row| match &row.payload {
                AssetEventPayload::Broadcast {
                    data, expiration, ..
                } => Some((
                    row.height,
                    row.txid.to_string(),
                    json!({
                        "tx_hash": row.txid,
                        "data": bitcoin::base58::encode(data),
                        "expiration": expiration,
                        "height": row.height,
                        "tx_pos": row.vout,
                    }),
                )),
                _ => None,
            })
            .collect();
        items.sort_by(|a, b| (b.0, &b.1).cmp(&(a.0, &a.1)));
        items.into_iter().map(|(_, _, v)| v).collect()
    }

    fn broadcasts_status(&self, name: &str) -> Value {
        let mut items = self.broadcasts(name);
        if items.is_empty() {
            return Value::Null;
        }
        items.sort_by(|a, b| {
            let key = |v: &Value| {
                (
                    v["height"].as_i64(),
                    py_str(&v["tx_hash"]),
                    v["tx_pos"].as_u64(),
                )
            };
            key(a).cmp(&key(b))
        });
        let s = items
            .iter()
            .map(|d| {
                format!(
                    "{}:{}{}{}{}",
                    py_str(&d["tx_hash"]),
                    d["height"],
                    d["tx_pos"],
                    py_str(&d["data"]),
                    match d["expiration"].as_u64() {
                        Some(t) => t.to_string(),
                        None => "None".into(),
                    }
                )
            })
            .collect::<Vec<_>>()
            .join(";");
        status_hash(&s)
    }

    /// ElectrumX only records a broadcast when the same transaction spends an
    /// output of that asset from the same script (`inputHashXs`).
    fn broadcast_is_valid(&self, row: &AssetEventRow) -> bool {
        let (asset, scripthash) = match &row.payload {
            AssetEventPayload::Broadcast {
                asset, scripthash, ..
            } => (asset, *scripthash),
            _ => return false,
        };
        let key = (row.txid, row.vout);
        if let Some(valid) = self.broadcast_checks.lock().get(&key) {
            return *valid;
        }
        let valid = match self.transaction(row.txid) {
            Some((tx, _)) => tx.input.iter().any(|input| {
                let prevout = input.previous_output;
                self.transaction(prevout.txid)
                    .and_then(|(prev, fork)| Some((prev.output.get(prevout.vout as usize)?.clone(), fork)))
                    .and_then(|(output, fork)| parse_asset_script(output.script_pubkey.as_bytes(), fork))
                    .is_some_and(|spent| {
                        crate::index::asset_name_of(&spent.data) == asset
                            && ScriptHash::hash(&spent.base_script) == scripthash
                    })
            }),
            None => false,
        };
        self.broadcast_checks.lock().insert(key, valid);
        valid
    }

    /// A transaction, and whether the unified fork's rules applied to it.
    fn transaction(&self, txid: Txid) -> Option<(Transaction, bool)> {
        if let Some(entry) = self.tracker.mempool().get(&txid) {
            return Some((entry.tx.clone(), entry.fork));
        }
        let (blockhash, bytes) = self.tracker.lookup_transaction(&self.daemon, txid).ok()??;
        let chain = self.tracker.chain();
        let fork = chain
            .get_block_height(&blockhash)
            .is_some_and(|height| chain.params().fork_active(height));
        Some((crate::neurai::tx::decode_transaction(&bytes).ok()?.tx, fork))
    }

    // ─── electrs-neurai extension ────────────────────────────────────────────

    fn asset_history_json(&self, name: &str) -> Value {
        use bitcoin::hex::DisplayHex;
        let history = self.tracker.get_asset_history(name.as_bytes());
        let mut items: Vec<Value> = history
            .confirmed
            .into_iter()
            .map(|entry| {
                // The stored prefix is `txid.as_byte_array()[..8]` — the *first*
                // 8 bytes in consensus order. Electrum clients display txids
                // reversed, so the prefix is reversed too: the emitted string is
                // the *last* 16 hex characters of the displayed txid.
                let mut disp = entry.tx_prefix;
                disp.reverse();
                json!({
                    "height": entry.height,
                    "block_hash": entry.block_hash,
                    "tx_prefix": disp.to_lower_hex_string(),
                })
            })
            .collect();
        for entry in history.mempool {
            let height: i64 = if entry.has_unconfirmed_inputs { -1 } else { 0 };
            items.push(json!({
                "height": height,
                "tx_hash": entry.txid,
                "fee": entry.fee.to_sat(),
            }));
        }
        json!(items)
    }
}

fn require_qualifier(name: &str) -> Result<()> {
    if !name.starts_with('#') {
        bail!("{} is not a qualifier", name);
    }
    Ok(())
}

/// ElectrumX `is_qualified` checks the asset before the h160.
fn check_h160_after_asset(args: &Args) -> Result<[u8; 20]> {
    check_asset(args.req(1))?;
    check_h160(args.req(0))
}

fn hex_lower(bytes: &[u8]) -> String {
    use bitcoin::hex::DisplayHex;
    bytes.to_lower_hex_string()
}

/// ElectrumX `tags_for_qualifier_status` / `tags_for_h160_status` over an
/// already key-sorted map: `"{key}:{height}{tx_hash}{tx_pos}{flag}"` joined by `;`.
fn tags_status(tags: &Map<String, Value>) -> Value {
    if tags.is_empty() {
        return Value::Null;
    }
    let s = tags
        .iter()
        .map(|(key, d)| {
            format!(
                "{}:{}{}{}{}",
                key,
                d["height"],
                py_str(&d["tx_hash"]),
                d["tx_pos"],
                py_bool(d["flag"].as_bool().unwrap_or(false))
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    status_hash(&s)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Status strings hashed exactly like ElectrumX (`sha256(s.encode()).hex()`).
    #[test]
    fn tags_status_format() {
        let mut tags = Map::new();
        tags.insert(
            "9b312db54c03455177cc6bf4e5364f5191b7a308".into(),
            json!({"flag": true, "height": 1103, "tx_hash": "d787b3b189d0ce389b3ac08c8e5671f6b9edaba653eb657e9968130f6cacf4dd", "tx_pos": 1}),
        );
        let expected = "9b312db54c03455177cc6bf4e5364f5191b7a308:1103d787b3b189d0ce389b3ac08c8e5671f6b9edaba653eb657e9968130f6cacf4dd1True";
        assert_eq!(tags_status(&tags), status_hash(expected));
        assert_eq!(tags_status(&Map::new()), Value::Null);
        // not reversed, plain hex sha256
        assert_eq!(
            status_hash("abc"),
            json!("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn method_table_covers_asset_methods() {
        assert_eq!(AssetMethod::lookup("blockchain.tag.check").unwrap().2, 2);
        assert_eq!(
            AssetMethod::lookup("blockchain.asset.list_addresses_by_asset")
                .unwrap()
                .1,
            &["asset", "onlytotal", "count", "start"]
        );
        assert!(AssetMethod::lookup("blockchain.asset.check_tag").is_none()); // not an ElectrumX method
    }
}
