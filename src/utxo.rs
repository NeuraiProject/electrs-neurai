//! Chunked UTXO sets (`doc/utxo-chunks.md`): the hashes of UTXOs and of
//! their changes, and the replies of `blockchain.scripthash.utxo_sync`
//! split into chunks of at most `CHUNK_BYTES`.

use bitcoin::{
    hashes::{sha256, Hash},
    BlockHash, OutPoint, Txid,
};
use parking_lot::Mutex;
use serde_json::{json, Value};

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use crate::types::ScriptHash;

/// Version of `doc/utxo-chunks.md`, advertised in `server.features`.
pub(crate) const PROTOCOL_VERSION: u32 = 1;
/// Most JSON of the UTXOs of a chunk: with the JSON-RPC reply around them,
/// a chunk stays under 128 KiB.
pub(crate) const CHUNK_BYTES: usize = 127 * 1024;
/// Replies of several chunks are kept at least this long after their last use.
pub(crate) const REPLY_TTL: Duration = Duration::from_secs(600);
/// Most memory used by the kept replies.
const MAX_REPLIES_BYTES: usize = 256 << 20;
/// Approximate memory of a UTXO and of an outpoint in a kept reply.
const UTXO_BYTES: usize = 96;
const OUTPOINT_BYTES: usize = 48;

/// A 256-bit number, for sums modulo 2²⁵⁶ (limbs least significant first).
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub(crate) struct Sum256([u64; 4]);

impl Sum256 {
    pub(crate) fn from_be_bytes(bytes: [u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, limb) in limbs.iter_mut().enumerate() {
            let end = 32 - 8 * i;
            *limb = u64::from_be_bytes(bytes[end - 8..end].try_into().expect("8 bytes"));
        }
        Sum256(limbs)
    }

    #[must_use]
    pub(crate) fn add(self, other: Self) -> Self {
        let mut limbs = [0u64; 4];
        let mut carry = false;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let (sum, c1) = self.0[i].overflowing_add(other.0[i]);
            let (sum, c2) = sum.overflowing_add(u64::from(carry));
            *limb = sum;
            carry = c1 || c2;
        }
        Sum256(limbs)
    }

    #[must_use]
    pub(crate) fn sub(self, other: Self) -> Self {
        let mut limbs = [0u64; 4];
        let mut borrow = false;
        for (i, limb) in limbs.iter_mut().enumerate() {
            let (diff, b1) = self.0[i].overflowing_sub(other.0[i]);
            let (diff, b2) = diff.overflowing_sub(u64::from(borrow));
            *limb = diff;
            borrow = b1 || b2;
        }
        Sum256(limbs)
    }

    /// 64 lowercase hex characters, big-endian.
    pub(crate) fn to_hex(self) -> String {
        format!(
            "{:016x}{:016x}{:016x}{:016x}",
            self.0[3], self.0[2], self.0[1], self.0[0]
        )
    }
}

impl std::iter::Sum for Sum256 {
    fn sum<I: Iterator<Item = Sum256>>(iter: I) -> Self {
        iter.fold(Sum256::default(), Sum256::add)
    }
}

/// A UTXO as `listunspent` shows it (`height` 0 in the mempool).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Utxo {
    pub txid: Txid,
    pub vout: u32,
    pub height: usize,
    /// XNA satoshis, or the asset's smallest units.
    pub value: u64,
    pub asset: Option<String>,
}

#[derive(Serialize)]
struct UtxoJson<'a> {
    height: usize,
    tx_hash: &'a Txid,
    tx_pos: u32,
    value: u64,
    asset: Option<&'a str>,
}

#[derive(Serialize)]
struct OutPointJson<'a> {
    tx_hash: &'a Txid,
    tx_pos: u32,
}

impl Utxo {
    pub(crate) fn outpoint(&self) -> OutPoint {
        OutPoint::new(self.txid, self.vout)
    }

    /// SHA-256 of `"{tx_hash}:{tx_pos}:{height}:{value}:{asset}"`.
    pub(crate) fn hash(&self) -> Sum256 {
        let text = format!(
            "{}:{}:{}:{}:{}",
            self.txid,
            self.vout,
            self.height,
            self.value,
            self.asset.as_deref().unwrap_or("")
        );
        Sum256::from_be_bytes(sha256::Hash::hash(text.as_bytes()).to_byte_array())
    }

    fn json(&self) -> UtxoJson<'_> {
        UtxoJson {
            height: self.height,
            tx_hash: &self.txid,
            tx_pos: self.vout,
            value: self.value,
            asset: self.asset.as_deref(),
        }
    }

    /// `(height, tx_hash, tx_pos)`, `tx_hash` compared as displayed.
    fn sort_key(&self) -> (usize, [u8; 32], u32) {
        (self.height, display_bytes(&self.txid), self.vout)
    }
}

fn display_bytes(txid: &Txid) -> [u8; 32] {
    let mut bytes = txid.to_byte_array();
    bytes.reverse();
    bytes
}

fn outpoint_json(outpoint: &OutPoint) -> OutPointJson<'_> {
    OutPointJson {
        tx_hash: &outpoint.txid,
        tx_pos: outpoint.vout,
    }
}

/// Sum of the hashes of `utxos`.
pub(crate) fn set_hash<'a>(utxos: impl IntoIterator<Item = &'a Utxo>) -> Sum256 {
    utxos.into_iter().map(Utxo::hash).sum()
}

/// How a confirmed set changed between two blocks, or from an empty set.
#[derive(Default, Debug)]
pub(crate) struct Changes {
    /// UTXOs of the old set that are not in the new one.
    pub removed: Vec<Utxo>,
    /// UTXOs of the new set that were not in the old one.
    pub added: Vec<Utxo>,
}

impl Changes {
    /// The changes from `old` to `new`.
    pub(crate) fn between(old: &HashMap<OutPoint, Utxo>, new: &HashMap<OutPoint, Utxo>) -> Self {
        let removed = old
            .iter()
            .filter(|(outpoint, utxo)| new.get(outpoint) != Some(utxo))
            .map(|(_, utxo)| utxo.clone())
            .collect();
        let added = new
            .iter()
            .filter(|(outpoint, utxo)| old.get(outpoint) != Some(utxo))
            .map(|(_, utxo)| utxo.clone())
            .collect();
        Changes { removed, added }
    }

    #[cfg(test)]
    pub(crate) fn hash(&self) -> Sum256 {
        set_hash(&self.added).sub(set_hash(&self.removed))
    }
}

/// What the mempool does to a confirmed set.
#[derive(Default, Debug)]
pub(crate) struct MempoolPart {
    /// Outputs of mempool transactions that no other mempool transaction spends.
    pub added: Vec<Utxo>,
    /// UTXOs of the confirmed set spent by mempool transactions.
    pub spent: Vec<Utxo>,
}

impl MempoolPart {
    pub(crate) fn sort(&mut self) {
        self.added.sort_by_key(Utxo::sort_key);
        self.spent.sort_by_key(Utxo::sort_key);
    }

    fn to_json(&self) -> Value {
        json!({
            "added": self.added.iter().map(Utxo::json).collect::<Vec<_>>(),
            "spent": self
                .spent
                .iter()
                .map(|u| OutPointJson { tx_hash: &u.txid, tx_pos: u.vout })
                .collect::<Vec<_>>(),
        })
    }
}

/// Status of `utxo_subscribe`: the hash of the spendable view.
pub(crate) fn status(set_hash: Sum256, mempool: &MempoolPart) -> Sum256 {
    set_hash
        .add(self::set_hash(&mempool.added))
        .sub(self::set_hash(&mempool.spent))
}

/// The confirmed set a `utxo_sync` reply leads to, and where it starts from.
#[derive(Clone, Debug)]
pub(crate) struct SyncState {
    /// `None`: the reply is the whole set.
    pub from_block: Option<BlockHash>,
    pub height: usize,
    pub block_hash: BlockHash,
    pub count: usize,
    pub set_hash: Sum256,
}

/// A chunk of changes.
#[derive(Default, Debug)]
pub(crate) struct Chunk {
    pub removed: Vec<OutPoint>,
    pub added: Vec<Utxo>,
}

impl Chunk {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "added": self.added.iter().map(Utxo::json).collect::<Vec<_>>(),
            "removed": self.removed.iter().map(outpoint_json).collect::<Vec<_>>(),
        })
    }
}

/// The changes of a reply, in chunks of at most `max_bytes` of JSON each:
/// every removed outpoint first, then the added UTXOs by `(height, tx_hash,
/// tx_pos)`. Returns the chunks and their hashes; there is always one.
pub(crate) fn split(changes: Changes, max_bytes: usize) -> (Vec<Chunk>, Vec<Sum256>) {
    let Changes {
        mut removed,
        mut added,
    } = changes;
    removed.sort_by_key(Utxo::sort_key);
    added.sort_by_key(Utxo::sort_key);

    let mut chunks = vec![Chunk::default()];
    let mut hashes = vec![Sum256::default()];
    let mut bytes = 0;
    let mut room_for = |size: usize, chunks: &mut Vec<Chunk>, hashes: &mut Vec<Sum256>| {
        let last = chunks.last().expect("a chunk");
        let empty = last.removed.is_empty() && last.added.is_empty();
        if !empty && bytes + size > max_bytes {
            chunks.push(Chunk::default());
            hashes.push(Sum256::default());
            bytes = 0;
        }
        bytes += size;
    };
    for utxo in removed {
        let outpoint = utxo.outpoint();
        let size = serde_json::to_vec(&outpoint_json(&outpoint))
            .expect("JSON")
            .len()
            + 1;
        room_for(size, &mut chunks, &mut hashes);
        let hash = hashes.last_mut().expect("a hash");
        *hash = hash.sub(utxo.hash());
        chunks.last_mut().expect("a chunk").removed.push(outpoint);
    }
    for utxo in added {
        let size = serde_json::to_vec(&utxo.json()).expect("JSON").len() + 1;
        room_for(size, &mut chunks, &mut hashes);
        let hash = hashes.last_mut().expect("a hash");
        *hash = hash.add(utxo.hash());
        chunks.last_mut().expect("a chunk").added.push(utxo);
    }
    (chunks, hashes)
}

/// Identifies a reply: the same scripthash, starting block and tip always
/// give the same changes, so clients asking for them share it.
pub(crate) fn reply_id(
    scripthash: ScriptHash,
    from_block: Option<BlockHash>,
    tip: BlockHash,
) -> String {
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(&scripthash.to_byte_array());
    data.extend_from_slice(&from_block.map_or([0; 32], |b| b.to_byte_array()));
    data.extend_from_slice(&tip.to_byte_array());
    let hash = sha256::Hash::hash(&data).to_byte_array();
    hash[..16].iter().map(|b| format!("{:02x}", b)).collect()
}

/// A reply of several chunks, kept for `utxo_chunk`.
#[derive(Debug)]
pub(crate) struct Chunked {
    pub id: String,
    pub scripthash: ScriptHash,
    pub state: SyncState,
    pub chunks: Vec<Chunk>,
    pub hashes: Vec<Sum256>,
}

impl Chunked {
    fn bytes(&self) -> usize {
        self.chunks
            .iter()
            .map(|c| c.added.len() * UTXO_BYTES + c.removed.len() * OUTPOINT_BYTES)
            .sum::<usize>()
            + self.hashes.len() * 32
    }
}

/// The JSON of a `utxo_sync` reply: `inline` holds the changes when there is
/// a single chunk, `id` names the kept reply otherwise.
pub(crate) fn sync_reply(
    state: &SyncState,
    id: Option<&str>,
    hashes: &[Sum256],
    inline: Option<&Chunk>,
    mempool: &MempoolPart,
) -> Value {
    let mut reply = json!({
        "from_block": state.from_block,
        "height": state.height,
        "block_hash": state.block_hash,
        "count": state.count,
        "set_hash": state.set_hash.to_hex(),
        "id": id,
        "chunks": hashes.iter().map(|h| h.to_hex()).collect::<Vec<_>>(),
        "mempool": mempool.to_json(),
    });
    if let Some(chunk) = inline {
        let map = reply.as_object_mut().expect("an object");
        map.insert(
            "added".into(),
            json!(chunk.added.iter().map(Utxo::json).collect::<Vec<_>>()),
        );
        map.insert(
            "removed".into(),
            json!(chunk.removed.iter().map(outpoint_json).collect::<Vec<_>>()),
        );
    }
    reply
}

/// Replies of several chunks, shared by every client, until `REPLY_TTL`
/// after their last use, the least recently used dropped first beyond
/// `MAX_REPLIES_BYTES`.
#[derive(Default)]
pub(crate) struct Replies {
    entries: Mutex<HashMap<String, (Instant, Arc<Chunked>)>>,
}

impl Replies {
    pub(crate) fn get(&self, id: &str) -> Option<Arc<Chunked>> {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        entries.retain(|_, (used, _)| now.duration_since(*used) < REPLY_TTL);
        let (used, reply) = entries.get_mut(id)?;
        *used = now;
        Some(Arc::clone(reply))
    }

    pub(crate) fn put(&self, reply: Arc<Chunked>) {
        let now = Instant::now();
        let mut entries = self.entries.lock();
        entries.retain(|_, (used, _)| now.duration_since(*used) < REPLY_TTL);
        entries.insert(reply.id.clone(), (now, reply));
        let mut total: usize = entries.values().map(|(_, r)| r.bytes()).sum();
        while total > MAX_REPLIES_BYTES && entries.len() > 1 {
            let oldest = entries
                .iter()
                .min_by_key(|(_, (used, _))| *used)
                .map(|(id, _)| id.clone())
                .expect("not empty");
            if let Some((_, dropped)) = entries.remove(&oldest) {
                total -= dropped.bytes();
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn utxo(n: u8, vout: u32, height: usize, value: u64, asset: Option<&str>) -> Utxo {
        Utxo {
            txid: Txid::from_byte_array([n; 32]),
            vout,
            height,
            value,
            asset: asset.map(str::to_owned),
        }
    }

    #[test]
    fn sums_wrap_modulo_2_256() {
        let max = Sum256::from_be_bytes([0xff; 32]);
        let one = Sum256::from_be_bytes({
            let mut b = [0; 32];
            b[31] = 1;
            b
        });
        assert_eq!(max.add(one), Sum256::default());
        assert_eq!(Sum256::default().sub(one), max);
        assert_eq!(max.to_hex(), "f".repeat(64));
        let carry = Sum256::from_be_bytes({
            let mut b = [0; 32];
            b[24..].copy_from_slice(&[0xff; 8]);
            b
        });
        assert_eq!(
            carry.add(one).to_hex(),
            format!("{}1{}", "0".repeat(47), "0".repeat(16))
        );
        assert_eq!(carry.add(one).sub(one), carry);
    }

    /// The same values as the Python example of `doc/utxo-chunks.md`.
    #[test]
    fn hashes_match_the_spec() {
        let u = Utxo {
            txid: Txid::from_str(
                "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b",
            )
            .unwrap(),
            vout: 1,
            height: 123456,
            value: 5000000,
            asset: None,
        };
        // sha256("5b75…685b:1:123456:5000000:")
        let text =
            "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b:1:123456:5000000:";
        let expected = sha256::Hash::hash(text.as_bytes()).to_string();
        assert_eq!(u.hash().to_hex(), expected);
        let a = Utxo {
            asset: Some("TOKEN/SUB".into()),
            ..u.clone()
        };
        let text = "5b75086dafeede555fc8f9a810d8b10df57c46f9f176ccc3dd8d2fa20edd685b:1:123456:5000000:TOKEN/SUB";
        assert_eq!(
            a.hash().to_hex(),
            sha256::Hash::hash(text.as_bytes()).to_string()
        );
        // the order doesn't matter, the empty set is zero
        assert_eq!(set_hash([&u, &a]), set_hash([&a, &u]));
        assert_eq!(set_hash([]).to_hex(), "0".repeat(64));
    }

    #[test]
    fn changes_between_sets() {
        let set = |utxos: &[Utxo]| -> HashMap<OutPoint, Utxo> {
            utxos.iter().map(|u| (u.outpoint(), u.clone())).collect()
        };
        let a = utxo(1, 0, 10, 100, None);
        let b = utxo(2, 0, 11, 200, Some("TOKEN"));
        let c = utxo(3, 1, 12, 300, None);
        // `b` moved to another height after a reorg
        let b2 = Utxo {
            height: 13,
            ..b.clone()
        };
        let old = set(&[a.clone(), b.clone()]);
        let new = set(&[a.clone(), b2.clone(), c.clone()]);
        let changes = Changes::between(&old, &new);
        assert_eq!(changes.removed, vec![b.clone()]);
        let mut added = changes.added.clone();
        added.sort_by_key(Utxo::sort_key);
        assert_eq!(added, vec![c.clone(), b2.clone()]);
        assert_eq!(
            set_hash(old.values()).add(changes.hash()),
            set_hash(new.values())
        );
    }

    #[test]
    fn split_in_chunks() {
        let added: Vec<Utxo> = (0..1000u32)
            .map(|i| utxo((i % 200) as u8, i, 1000 - i as usize, 1, None))
            .collect();
        let removed: Vec<Utxo> = (0..300u32).map(|i| utxo(250, i, 5, 7, Some("T"))).collect();
        let changes = Changes {
            removed: removed.clone(),
            added: added.clone(),
        };
        let total = changes.hash();
        let (chunks, hashes) = split(changes, 10_000);
        assert!(chunks.len() > 10);
        assert_eq!(chunks.len(), hashes.len());
        for chunk in &chunks {
            let json = serde_json::to_string(&chunk.to_json()).unwrap();
            assert!(json.len() <= 10_000 + 40, "{}", json.len());
        }
        // removed first, then added in order
        let order: Vec<bool> = chunks
            .iter()
            .flat_map(|c| {
                c.removed
                    .iter()
                    .map(|_| true)
                    .chain(c.added.iter().map(|_| false))
            })
            .collect();
        assert!(order.windows(2).all(|w| w[0] >= w[1]));
        let listed: Vec<&Utxo> = chunks.iter().flat_map(|c| &c.added).collect();
        assert!(listed
            .windows(2)
            .all(|w| w[0].sort_key() <= w[1].sort_key()));
        assert_eq!(listed.len(), 1000);
        assert_eq!(chunks.iter().map(|c| c.removed.len()).sum::<usize>(), 300);
        assert_eq!(hashes.iter().copied().sum::<Sum256>(), total);

        // no changes: one empty chunk
        let (chunks, hashes) = split(Changes::default(), 10_000);
        assert_eq!(chunks.len(), 1);
        assert_eq!(hashes, vec![Sum256::default()]);
    }

    #[test]
    fn status_is_the_hash_of_the_spendable_view() {
        let a = utxo(1, 0, 10, 100, None);
        let b = utxo(2, 0, 11, 200, None);
        let m = utxo(3, 0, 0, 50, None);
        let mempool = MempoolPart {
            added: vec![m.clone()],
            spent: vec![a.clone()],
        };
        assert_eq!(status(set_hash([&a, &b]), &mempool), set_hash([&b, &m]));
    }

    #[test]
    fn replies_expire_and_are_bounded() {
        let replies = Replies::default();
        let reply = |id: &str| {
            Arc::new(Chunked {
                id: id.into(),
                scripthash: ScriptHash::hash(&[1]),
                state: SyncState {
                    from_block: None,
                    height: 1,
                    block_hash: BlockHash::all_zeros(),
                    count: 0,
                    set_hash: Sum256::default(),
                },
                chunks: vec![Chunk::default(), Chunk::default()],
                hashes: vec![Sum256::default(); 2],
            })
        };
        replies.put(reply("a"));
        replies.put(reply("b"));
        assert!(replies.get("a").is_some());
        assert!(replies.get("c").is_none());
        assert_eq!(replies.len(), 2);
    }

    #[test]
    fn reply_ids() {
        let sh = ScriptHash::hash(&[1]);
        let tip = BlockHash::from_byte_array([2; 32]);
        let id = reply_id(sh, None, tip);
        assert_eq!(id.len(), 32);
        assert_eq!(id, reply_id(sh, None, tip));
        assert_ne!(
            id,
            reply_id(sh, Some(BlockHash::from_byte_array([3; 32])), tip)
        );
        assert_ne!(id, reply_id(ScriptHash::hash(&[2]), None, tip));
    }

    #[test]
    fn json_shapes() {
        let u = utxo(1, 2, 3, 4, None);
        let chunk = Chunk {
            removed: vec![utxo(5, 6, 7, 8, None).outpoint()],
            added: vec![u],
        };
        let json = chunk.to_json();
        assert_eq!(json["added"][0]["height"], 3);
        assert_eq!(json["added"][0]["tx_pos"], 2);
        assert_eq!(json["added"][0]["value"], 4);
        assert_eq!(json["added"][0]["asset"], Value::Null);
        assert_eq!(json["added"][0]["tx_hash"], "01".repeat(32));
        assert_eq!(
            json["removed"][0],
            json!({"tx_hash": "05".repeat(32), "tx_pos": 6})
        );
    }
}
