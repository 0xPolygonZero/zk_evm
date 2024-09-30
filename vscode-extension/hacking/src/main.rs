use std::{
    borrow::Cow,
    cell::OnceCell,
    collections::{hash_map::Entry, HashMap},
    iter,
    sync::{Mutex, MutexGuard},
};

use line_index::{LineIndex, TextRange, TextSize, WideEncoding, WideLineCol};
use pest::{iterators::Pairs, Parser as _, RuleType};
use serde_json::{json, Value};
use tower_lsp::{
    jsonrpc,
    lsp_types::{
        DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
        InitializeParams, InitializeResult, PartialResultParams, Position, Range, SemanticToken,
        SemanticTokenType, SemanticTokens, SemanticTokensFullOptions, SemanticTokensLegend,
        SemanticTokensOptions, SemanticTokensParams, SemanticTokensResult,
        SemanticTokensServerCapabilities, ServerCapabilities, TextDocumentContentChangeEvent,
        TextDocumentIdentifier, TextDocumentItem, TextDocumentSyncCapability, TextDocumentSyncKind,
        VersionedTextDocumentIdentifier, WorkDoneProgressOptions, WorkDoneProgressParams,
    },
    LspService, Server,
};
use tracing::{debug, warn};
use url::Url;

fn main() -> anyhow::Result<()> {
    let (svc, socket) = LspService::new(|_client| {
        LanguageServer(Mutex::new(State {
            documents: HashMap::new(),
        }))
    });
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(Server::new(tokio::io::stdin(), tokio::io::stdout(), socket).serve(svc));
    Ok(())
}

struct State {
    /// Stores the latest version of a document.
    documents: HashMap<Url, (i32, SourceFile)>,
}

struct LanguageServer(Mutex<State>);

impl LanguageServer {
    fn state(&self) -> MutexGuard<State> {
        self.0.lock().unwrap()
    }
}

#[tower_lsp::async_trait]
impl tower_lsp::LanguageServer for LanguageServer {
    // lifecycle
    // ---------

    async fn initialize(
        &self,
        _params: InitializeParams,
    ) -> Result<InitializeResult, jsonrpc::Error> {
        Ok(InitializeResult {
            capabilities: ServerCapabilities {
                text_document_sync: Some(TextDocumentSyncCapability::Kind(
                    TextDocumentSyncKind::FULL,
                )),
                semantic_tokens_provider: Some(
                    SemanticTokensServerCapabilities::SemanticTokensOptions(
                        SemanticTokensOptions {
                            work_done_progress_options: WorkDoneProgressOptions {
                                work_done_progress: None,
                            },
                            legend: SemanticTokensLegend {
                                token_types: TokenKind::legend(),
                                token_modifiers: vec![],
                            },
                            range: None,
                            full: Some(SemanticTokensFullOptions::Bool(true)),
                        },
                    ),
                ),
                ..Default::default()
            },
            server_info: None,
        })
    }
    async fn shutdown(&self) -> Result<(), jsonrpc::Error> {
        Ok(())
    }

    // text update
    // -----------

    async fn did_open(&self, params: DidOpenTextDocumentParams) {
        let DidOpenTextDocumentParams {
            text_document:
                TextDocumentItem {
                    uri,
                    language_id: _,
                    version,
                    text,
                },
        } = params;
        self.state()
            .documents
            .insert(uri, (version, SourceFile::new(text)));
    }
    async fn did_change(&self, params: DidChangeTextDocumentParams) {
        let DidChangeTextDocumentParams {
            text_document: VersionedTextDocumentIdentifier { uri, version },
            content_changes,
        } = params;
        for TextDocumentContentChangeEvent {
            range,
            range_length,
            text,
        } in content_changes
        {
            match (range, range_length) {
                (None, None) => {
                    match self.state().documents.entry(uri.clone()) {
                        Entry::Occupied(mut already) => {
                            let (existing_version, _) = already.get();
                            match version > *existing_version {
                                true => {
                                    already.insert((version, SourceFile::new(text)));
                                }
                                false => {
                                    debug!(%uri, %version, %existing_version, "ignoring stale didChange")
                                }
                            }
                        }
                        Entry::Vacant(space) => {
                            warn!(%uri, %version, "no such document on didChange");
                            space.insert((version, SourceFile::new(text)));
                        }
                    };
                }
                _ => warn!(%uri, %version, "ignoring relative didChange"),
            }
        }
    }
    async fn did_close(&self, params: DidCloseTextDocumentParams) {
        let DidCloseTextDocumentParams {
            text_document: TextDocumentIdentifier { uri },
        } = params;
        if self.state().documents.remove(&uri).is_none() {
            warn!(%uri, "no such document on didClose")
        }
    }

    // features
    // --------

    async fn semantic_tokens_full(
        &self,
        params: SemanticTokensParams,
    ) -> Result<Option<SemanticTokensResult>, jsonrpc::Error> {
        let SemanticTokensParams {
            work_done_progress_params: WorkDoneProgressParams { work_done_token },
            partial_result_params:
                PartialResultParams {
                    partial_result_token,
                },
            text_document: TextDocumentIdentifier { uri },
        } = params;
        ensure!(work_done_token.is_none());
        ensure!(partial_result_token.is_none());
        let Some((_, text)) = self.state().documents.get(&uri).cloned() else {
            bail!("no such document with uri {}", uri)
        };
        ensure!(text.string.len() <= u32::MAX as usize);
        let mut builder = SemanticTokensBuilder::default();
        colour_ast(
            &mut builder,
            &text,
            Grammar::parse(Rule::file, &text.string).map_err(conv_error)?,
            |rule| {
                Some(match rule {
                    Rule::COMMENT => TokenKind::Comment,
                    Rule::variable => TokenKind::Variable,
                    Rule::prover_input_fn => TokenKind::Function,
                    Rule::nullary_instruction => TokenKind::Keyword,
                    Rule::conditional_block => TokenKind::Decorator,
                    _ => return None,
                })
            },
        );
        Ok(Some(SemanticTokensResult::Tokens(SemanticTokens {
            result_id: None,
            data: builder.data,
        })))
    }
}

#[derive(pest_derive::Parser)]
#[grammar = "grammar.pest"]
struct Grammar;

fn colour_ast<R: RuleType>(
    builder: &mut SemanticTokensBuilder,
    source: &SourceFile,
    ast: Pairs<'_, R>,
    mut select: impl FnMut(R) -> Option<TokenKind>,
) {
    let offset2position = |offset: TextSize| {
        let lc = source.offset_lookup().try_line_col(offset)?;
        let WideLineCol { line, col } = source.offset_lookup().to_wide(WideEncoding::Utf16, lc)?;
        Some(Position {
            line,
            character: col,
        })
    };
    for pair in ast {
        match select(pair.as_rule()) {
            Some(token_kind) => {
                // A pest::Pair MAY be multiline, but an LSP token MUST NOT,
                // so break that up here.
                //
                // Going via TextSize is more reliable than through pest::Span::lines_span
                let offset = TextSize::new(pair.as_span().start().try_into().unwrap());
                let len = TextSize::of(pair.as_str());
                for text_range in source.offset_lookup().lines(TextRange::at(offset, len)) {
                    let text_range = trim_end(text_range, &source.string, "\n");
                    let (Some(start), Some(end)) = (
                        offset2position(text_range.start()),
                        offset2position(text_range.end()),
                    ) else {
                        continue;
                    };
                    builder.push(Range { start, end }, token_kind);
                }
            }
            None => colour_ast(
                builder,
                source,
                pair.into_inner(),
                // no recursive cycle
                &mut select as &mut dyn FnMut(_) -> _,
            ),
        }
    }
}

fn trim_end(text_range: TextRange, str: &str, end: &str) -> TextRange {
    match str[text_range].ends_with(end) {
        true => TextRange::new(text_range.start(), text_range.end() - TextSize::of(end)),
        false => text_range,
    }
}

/// <https://github.com/rust-lang/rust-analyzer/blob/c88ea11832277b6c010088d658965c39c1181d20/crates/rust-analyzer/src/lsp/semantic_tokens.rs#L183-L230>
#[derive(Default)]
struct SemanticTokensBuilder {
    prev_line: u32,
    prev_char: u32,
    data: Vec<SemanticToken>,
}

impl SemanticTokensBuilder {
    fn push(&mut self, range: Range, token_kind: TokenKind) {
        let mut push_line = range.start.line;
        let mut push_char = range.start.character;

        if !self.data.is_empty() {
            push_line -= self.prev_line;
            if push_line == 0 {
                push_char -= self.prev_char;
            }
        }

        assert_eq!(
            range.start.line, range.end.line,
            "a token cannot be multiline"
        );
        let token_len = range.end.character - range.start.character;

        let token = SemanticToken {
            delta_line: push_line,
            delta_start: push_char,
            length: token_len,
            token_type: token_kind as u32,
            token_modifiers_bitset: 0,
        };

        self.data.push(token);

        self.prev_line = range.start.line;
        self.prev_char = range.start.character;
    }
}

#[derive(Clone)]
struct SourceFile {
    string: String,
    /// LSP requires utf-16 offsets.
    ///
    /// Defer the work of indexing until it's actually needed.
    offset_lookup: OnceCell<LineIndex>,
}

impl SourceFile {
    fn new(source: String) -> Self {
        Self {
            string: source,
            offset_lookup: OnceCell::new(),
        }
    }
    fn offset_lookup(&self) -> &LineIndex {
        self.offset_lookup
            .get_or_init(|| LineIndex::new(&self.string))
    }
}

macro_rules! legend {
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $ident:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $token_type:expr
            ),* $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        $vis enum $ident {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
        }

        impl $ident {
            /// The discriminant of this enum is used as an index
            /// into itself given by [`Self::legend`].
            fn legend() -> ::std::vec::Vec<::tower_lsp::lsp_types::SemanticTokenType> {
                ::std::vec![
                    $($token_type,)*
                ]
            }
        }
    };
}

legend! {
#[derive(Clone, Copy)]
#[repr(u32)]
enum TokenKind {
    Comment = SemanticTokenType::COMMENT,
    Keyword = SemanticTokenType::KEYWORD,
    Function = SemanticTokenType::FUNCTION,
    Decorator = SemanticTokenType::DECORATOR,
    Variable = SemanticTokenType::VARIABLE,
}}

/// Accept [`anyhow::Error`] (`: !Error`) _and_ other error types.
fn conv_error(e: impl Into<Box<dyn std::error::Error>>) -> jsonrpc::Error {
    let e = e.into();
    jsonrpc::Error {
        code: (-1).into(),
        message: Cow::Owned(e.to_string()),
        data: e.source().map(|_| {
            json!({
                "chain": Value::Array(
                    iter::successors(Some(&*e as &dyn std::error::Error), |it| it.source())
                        .map(|e| Value::String(e.to_string())).collect())
            })
        }),
    }
}

macro_rules! ensure {
	($($tt:tt)*) => {
		::core::result::Result::map_err(
			(|| -> ::anyhow::Result<()> {::anyhow::ensure!($($tt)*); ::core::result::Result::Ok(())})(),
			$crate::conv_error
		)?;
	};
}
pub(crate) use ensure;

macro_rules! bail {
	($($tt:tt)*) => {
		return ::core::result::Result::Err($crate::conv_error(::anyhow::anyhow!($($tt)*)))
	};
}
pub(crate) use bail;
