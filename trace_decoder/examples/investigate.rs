use std::{
    collections::{BTreeMap, HashSet},
    fs::File,
    iter,
    path::Path,
};

use alloy::rpc::types::Header;
use anyhow::{ensure, Context as _};
use camino::Utf8Path;
use copyvec::CopyVec;
use either::Either;
use ethereum_types::Address;
use evm_arithmetization::generation::mpt::AccountRlp;
use glob::glob;
use keccak_hash::{keccak, H256};
use mpt_trie::partial_trie::PartialTrie as _;
use mpt_trie::partial_trie::{HashedPartialTrie, Node};
use prover::BlockProverInput;
use serde::de::DeserializeOwned;
use trace_decoder::{
    BlockTraceTriePreImages, CombinedPreImages, SeparateStorageTriesPreImage, SeparateTriePreImage,
    SeparateTriePreImages,
};
use u4::U4;

/// This is the dream StateTrie representation
struct StateTrie {
    /// items actually in the trie
    full: BTreeMap<H256, AccountRlp>,
    deferred_subtries: BTreeMap<CopyVec<U4, 64>, H256>,
    deferred_accounts: BTreeMap<H256, AccountRlp>,
}

impl StateTrie {
    /// Defer accounts in `locations`.
    /// Absent values are not an error.
    fn trim_to(&mut self, locations: impl IntoIterator<Item = H256>) {
        let want = locations.into_iter().collect::<HashSet<_>>();
        let have = self.full.keys().copied().collect();
        for hash in HashSet::difference(&have, &want) {
            let (k, v) = self.full.remove_entry(hash).expect("key is in `have`");
            self.deferred_accounts.insert(k, v);
        }
    }
    fn insert_by_address(&mut self, address: Address, account: AccountRlp) {
        self.full.insert(keccak(address), account);
    }
    fn insert_hash_by_key(&mut self, key: CopyVec<U4, 64>, hash: H256) {
        self.deferred_subtries.insert(key, hash);
    }
    fn get_by_address(&self, address: Address) -> Option<AccountRlp> {
        self.full.get(&keccak(address)).copied()
    }
}
impl StateTrie {
    fn from_mpt(_: HashedPartialTrie) -> anyhow::Result<Self> {
        todo!()
    }
    fn to_mpt(&self) -> anyhow::Result<HashedPartialTrie> {
        todo!()
    }
    fn to_smt(&self) -> smt_trie::smt::Smt<smt_trie::db::MemoryDb> {
        todo!()
    }
}

fn _discuss(src: HashedPartialTrie) -> anyhow::Result<()> {
    // the goal is, of course, for the following to hold
    assert_eq!(src.hash(), StateTrie::from_mpt(src)?.to_mpt()?.hash());

    Ok(())
}

/// Test cases come in pairs of files, `foo_header.json` and `foo.json`.
struct FilePair {
    /// `foo`, in the above example.
    pub name: String,
    pub cases: Vec<(Header, BlockProverInput)>,
}

impl FilePair {
    fn load(header_path: &Path) -> anyhow::Result<Self> {
        let header_path = Utf8Path::from_path(header_path).context("non-UTF-8 path")?;
        let base = Utf8Path::new(
            header_path
                .as_str()
                .strip_suffix("_header.json")
                .context("inconsistent header name")?, // sync with glob call
        );
        let headers = json::<Vec<Header>>(header_path)?;
        let bodies = json::<Vec<BlockProverInput>>(base.with_extension("json"))?;
        ensure!(headers.len() == bodies.len(), "inconsistent file pair");
        anyhow::Ok(FilePair {
            name: base.file_name().context("inconsistent base name")?.into(),
            cases: headers.into_iter().zip(bodies).collect(),
        })
    }
}

fn json<T: DeserializeOwned>(path: impl AsRef<Path>) -> anyhow::Result<T> {
    fn _imp<T: DeserializeOwned>(path: impl AsRef<Path>) -> anyhow::Result<T> {
        let file = File::open(path)?;
        Ok(serde_path_to_error::deserialize(
            &mut serde_json::Deserializer::from_reader(file),
        )?)
    }

    _imp(&path).context(format!("couldn't load {}", path.as_ref().display()))
}

fn main() -> anyhow::Result<()> {
    eprint!("loading test cases...");
    let file_pairs = glob(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/data/witnesses/zero_jerigon/*_header.json"
    ))
    .expect("valid glob pattern")
    .map(|res| {
        let header_path = res.expect("filesystem error discovering test vectors");
        FilePair::load(&header_path).context(format!(
            "couldn't load case for header {}",
            header_path.display()
        ))
    })
    .collect::<Result<Vec<_>, _>>()?;
    eprintln!("done.");

    let mut total = 0;

    for FilePair { name, cases } in file_pairs {
        for (case_ix, (_header, bpi)) in cases.into_iter().enumerate() {
            for (hpt_ix, hpt) in mpts(bpi)?.enumerate() {
                total += 1;
                let count = count_non_minimal(&hpt);
                if count != 0 {
                    println!("{name}/{case_ix}/{hpt_ix}\t{}", count)
                }
            }
        }
    }
    eprintln!("tested {total} tries");
    Ok(())
}

/// Iterate the state and storage tries in `bpi`
fn mpts(bpi: BlockProverInput) -> anyhow::Result<impl Iterator<Item = HashedPartialTrie>> {
    Ok(match bpi.block_trace.trie_pre_images {
        BlockTraceTriePreImages::Separate(SeparateTriePreImages {
            state: SeparateTriePreImage::Direct(state),
            storage: SeparateStorageTriesPreImage::MultipleTries(hash2trie),
        }) => Either::Left(
            iter::once(state).chain(
                hash2trie
                    .into_values()
                    .map(|SeparateTriePreImage::Direct(it)| it),
            ),
        ),
        BlockTraceTriePreImages::Combined(CombinedPreImages { compact }) => {
            let fe =
                trace_decoder::wire::parse(&compact).and_then(trace_decoder::type1::frontend)?;
            Either::Right(
                iter::once(fe.state.as_hashed_partial_trie().clone()).chain(
                    fe.storage
                        .into_values()
                        .map(|it| it.as_hashed_partial_trie().clone()),
                ),
            )
        }
    })
}

/// Count cases like `branch -> branch` or `branch -> extension`
fn count_non_minimal(node: &Node<HashedPartialTrie>) -> usize {
    let mut count = 0;
    match node {
        Node::Empty | Node::Hash(_) | Node::Leaf { .. } => {}
        Node::Branch { children, .. } => {
            let mut nonempty_children =
                children.iter().filter(|it| !matches!(*****it, Node::Empty));

            if let (1, Some(Node::Branch { .. } | Node::Extension { .. })) = (
                nonempty_children.clone().count(),
                nonempty_children.next().map(|it| &****it),
            ) {
                count += 1
            }

            count += children
                .iter()
                .map(|it| count_non_minimal(it))
                .sum::<usize>()
        }
        Node::Extension { child, .. } => count += count_non_minimal(child),
    };
    count
}

/// Create [`Node::Branch`] with a single child, `child`.
#[cfg(test)]
fn branch0(child: HashedPartialTrie) -> HashedPartialTrie {
    let mut child = Some(child);

    HashedPartialTrie::new(Node::Branch {
        children: std::array::from_fn(|ix| {
            std::sync::Arc::new(Box::new(match ix {
                0 => child.take().unwrap(),
                _ => HashedPartialTrie::new(Node::Empty),
            }))
        }),
        value: vec![],
    })
}

#[test]
fn test_count_non_minimal() {
    // root -> branch -> branch -> leaf
    let subject = branch0(branch0(HashedPartialTrie::new(Node::Leaf {
        nibbles: Default::default(),
        value: vec![],
    })));
    assert_eq!(count_non_minimal(&subject), 1);
}

#[test]
fn test_badhash() {
    let leaf = HashedPartialTrie::new(Node::Leaf {
        nibbles: Default::default(),
        value: b"hello".into(),
    });
    let ext = HashedPartialTrie::new(Node::Extension {
        nibbles: {
            let mut nibbles = mpt_trie::nibbles::Nibbles::new();
            nibbles.push_nibble_back(0);
            nibbles.push_nibble_back(0);
            nibbles
        },
        child: std::sync::Arc::new(Box::new(leaf.clone())),
    });
    let branchy = branch0(branch0(leaf));

    // two above representations are semantically equivalent
    itertools::assert_equal(ext.items(), branchy.items());

    // but have different hashes
    assert_ne!(ext.hash(), branchy.hash());
}
