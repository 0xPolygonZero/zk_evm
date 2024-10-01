use std::fs;

use anyhow::Context as _;
use camino::Utf8Path;
use evm_arithmetization::cpu::kernel::ast2;
use libtest_mimic::{Arguments, Failed, Trial};
use pretty_assertions::StrComparison;
use proc_macro2::TokenStream;
use quote::ToTokens;

fn main() -> anyhow::Result<()> {
    let mut trials = vec![];
    let asm_folder = Utf8Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/cpu/kernel/asm/",));
    for entry in glob::glob(&format!("{asm_folder}/**/*.asm"))? {
        let path = entry?;
        let path = Utf8Path::from_path(&path).context("invalid path")?;
        let friendly = path.strip_prefix(asm_folder).unwrap_or(path);
        let source = fs::read_to_string(path)?;

        trials.push(Trial::test(
            friendly.to_owned(),
            move || match syn::parse_str::<ast2::File>(&source) {
                Ok(file) => {
                    let source_tokens = source
                        .parse::<TokenStream>()
                        .expect("lexing must have succeeded if parsing succeeded")
                        .to_string();
                    let parsed_tokens = file.to_token_stream().to_string();
                    match source_tokens == parsed_tokens {
                        true => Ok(()),
                        false => Err(Failed::from(StrComparison::new(
                            &source_tokens,
                            &parsed_tokens,
                        ))),
                    }
                }
                Err(e) => Err(Failed::from(syn_miette::Error::new(e, source).render())),
            },
        ));
    }
    libtest_mimic::run(&Arguments::from_args(), trials).exit()
}
