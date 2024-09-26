use std::{fs::File, path::Path};

use alloy::rpc::types::Header;
use anyhow::{ensure, Context as _};
use camino::Utf8Path;
use serde::de::DeserializeOwned;
use zero::prover::BlockProverInput;
use zero::trace_decoder::{BlockTrace, OtherBlockData};

pub fn cases() -> anyhow::Result<Vec<Case>> {
    print!("loading test vectors...");
    let ret = glob::glob(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/cases/*_header.json"
    ))
    .expect("valid glob pattern")
    .map(|res| {
        let header_path = res.context("filesystem error discovering test vectors")?;
        Case::load(&header_path).context(format!(
            "couldn't load case for header {}",
            header_path.display()
        ))
    })
    .collect();
    println!("done");
    ret
}

/// Test cases consist of [`BlockProverInput`] collected from `zero_bin`'s `rpc`
/// command, and the corresponding block header, fetched directly over RPC.
///
/// In directory above, the files are stored alongside one another, as, for
/// example:
/// - `b4_dev.json`
/// - `b4_dev_header.json`
pub struct Case {
    /// `b4_dev`, in the above example.
    ///
    /// Used as a test identifier.
    pub name: String,
    #[allow(unused)] // only used by one of the test binaries
    pub header: Header,
    pub trace: BlockTrace,
    pub other: OtherBlockData,
}

impl Case {
    fn load(header_path: &Path) -> anyhow::Result<Self> {
        let header_path = Utf8Path::from_path(header_path).context("non-UTF-8 path")?;
        let base = Utf8Path::new(
            header_path
                .as_str()
                .strip_suffix("_header.json")
                .context("inconsistent header name")?, // sync with glob call
        );
        // for some reason these are lists...
        let mut headers = json::<Vec<Header>>(header_path)?;
        let mut bpis = json::<Vec<BlockProverInput>>(base.with_extension("json"))?;
        ensure!(headers.len() == 1, "bad header file");
        ensure!(bpis.len() == 1, "bad bpi file");
        let BlockProverInput {
            block_trace,
            other_data,
        } = bpis.remove(0);
        anyhow::Ok(Case {
            name: base.file_name().context("inconsistent base name")?.into(),
            header: headers.remove(0),
            trace: block_trace,
            other: other_data,
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
