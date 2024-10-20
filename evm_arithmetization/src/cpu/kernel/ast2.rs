//! Span-preserving AST for use by:
//! - The language server, for syntax highlighting, goto definition, etc.
//! - The rest of the compiler.
//!
//! Built on [`syn`], for simplicity.
//!
//! # Non-goals
//! - Representing trivia such as comments. This must be done in a separate step
//!   in the language server, as the implementation complexity is not worth it.
//! - A Concrete Syntax Tree for formatting.
//! - Representing invalid parse trees.

use derive_quote_to_tokens::ToTokens;
use derive_syn_parse::Parse;
use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::ext::IdentExt as _;
use syn::parse::{Parse, ParseStream, Peek};
use syn::punctuated::Punctuated;
use syn::{braced, bracketed, parenthesized, token, Token};

/// Keywords.
pub mod kw {
    macro_rules! keywords {
        ($($ident:ident),* $(,)?) => {
            $(
                ::syn::custom_keyword!($ident);
            )*

            /// This is overly strict, but doesn't cost us much.
            pub fn peek(input: ::syn::parse::ParseStream) -> bool {
                false
                $(
                    || input.peek($ident)
                )*
            }
        };
    }

    keywords! {
        all,
        any,
        BYTES,
        cfg,
        endmacro,
        endrep,
        feature,
        GLOBAL,
        JUMPTABLE,
        not,
        PROVER_INPUT,
        PUSH,
        rep,
        stack,
    }
}

/// `%`-prefixed keywords.
pub mod pc {
    use derive_quote_to_tokens::ToTokens;
    use derive_syn_parse::Parse;
    use syn::{parse::ParseStream, Token};

    macro_rules! percent_then {
        ($($ident:ident),* $(,)?) => {
            $(
                #[derive(::derive_syn_parse::Parse, ::derive_quote_to_tokens::ToTokens)]
                #[allow(non_camel_case_types, unused)]
                pub struct $ident {
                    pub percent: ::syn::Token![%],
                    pub $ident: super::kw::$ident,
                }

                impl $ident {
                    pub fn peek(input: ::syn::parse::ParseStream) -> bool {
                        input.peek(::syn::Token![%])
                            && input.peek2(super::kw::$ident)
                    }
                }
            )*
        };
    }

    percent_then! {
        endmacro,
        endrep,
        rep,
        stack,
    }

    #[derive(Parse, ToTokens)]
    pub struct Macro {
        pub percent: Token![%],
        pub macro_: Token![macro],
    }

    impl Macro {
        pub fn peek(input: ParseStream) -> bool {
            input.peek(Token![%]) && input.peek2(Token![macro])
        }
    }
}

pub mod pun {
    //! Custom punctuation.
    //!
    //! We take care to preserve round-tripping the printed tokenstream for our
    //! tests.

    use derive_quote_to_tokens::ToTokens;
    use proc_macro2::{Punct, Spacing};
    use syn::parse::{Parse, ParseStream};

    #[derive(ToTokens)]
    pub struct Percent2 {
        punct0: Punct,
        punct1: Punct,
    }

    impl Parse for Percent2 {
        fn parse(input: ParseStream) -> syn::Result<Self> {
            input.step(|cursor| {
                match cursor
                    .punct()
                    .and_then(|(p0, next)| next.punct().map(|(p1, n)| (p0, p1, n)))
                {
                    Some((punct0, punct1, n))
                        if itertools::all([&punct0, &punct1], |it| it.as_char() == '%')
                            && punct0.spacing() == Spacing::Joint =>
                    {
                        Ok((Percent2 { punct0, punct1 }, n))
                    }
                    _ => Err(input.error("expected `%%`")),
                }
            })
        }
    }

    impl Percent2 {
        pub fn peek(input: ParseStream) -> bool {
            input.fork().parse::<Self>().is_ok()
        }
    }
}

pub struct File {
    pub items: Vec<Item>,
}

impl Parse for File {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let mut items = vec![];
        while !input.is_empty() {
            items.push(input.parse()?)
        }
        Ok(Self { items })
    }
}

impl ToTokens for File {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self { items } = self;
        for item in items {
            item.to_tokens(tokens);
        }
    }
}

fn peek2<T: Peek>(token: T) -> impl Fn(ParseStream) -> bool {
    move |it| it.peek2(token)
}

#[derive(ToTokens)]
pub struct Ident(syn::Ident);

impl Parse for Ident {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if kw::peek(input) {
            return Err(input.error("keywords may not be used as identifiers"));
        }
        Ok(Self(input.call(syn::Ident::parse_any)?))
    }
}

impl Ident {
    pub fn peek(input: ParseStream) -> bool {
        input.fork().parse::<Self>().is_ok()
    }
}

pub type Literal = syn::LitInt;

#[derive(Parse, ToTokens)]
pub struct Variable {
    pub dollar: Token![$],
    pub ident: Ident,
}

#[derive(Parse, ToTokens)]
pub struct Constant {
    pub at: Token![@],
    pub ident: Ident,
}

#[derive(Parse, ToTokens)]
pub enum Item {
    #[peek(Token![#], name = "#[cfg(..)]")]
    Cfg(CfgItems),
    #[peek_with(pc::Macro::peek, name = "%macro")]
    MacroDef(MacroDef),
    #[peek_with(pc::rep::peek, name = "%rep")]
    Repeat(Repeat),
    #[peek_with(pc::stack::peek, name = "%stack")]
    Stack(Stack),
    #[peek_with(pun::Percent2::peek, name = "a `%%..` macro decl")]
    MacroDecl(MacroDecl),
    #[peek(Token![%], name = "MacroCall")]
    MacroCall(MacroCall),
    #[peek(kw::GLOBAL, name = "GLOBAL")]
    GlobalDecl(GlobalDecl),
    #[peek(kw::BYTES, name = "BYTES")]
    Bytes(Bytes),
    #[peek(kw::JUMPTABLE, name = "JUMPTABLE")]
    Jumptable(Jumptable),
    #[peek(kw::PUSH, name = "PUSH")]
    Push(Push),
    #[peek(kw::PROVER_INPUT, name = "PROVER_INPUT")]
    ProverInput(ProverInput),
    #[peek_with(peek2(Token![:]), name = "an `ident:` local decl")]
    LocalDecl(LocalDecl),
    #[peek_with(Ident::peek, name = "an `ident` instruction")]
    Instruction(Instruction),
}

#[derive(Parse, ToTokens)]
pub struct MacroLabel {
    pub percent: pun::Percent2,
    pub ident: Ident,
}

#[derive(Parse, ToTokens)]
pub struct MacroDecl {
    pub label: MacroLabel,
    pub colon: Token![:],
}

pub struct MacroDef {
    pub macro_: pc::Macro,
    pub ident: Ident,
    pub param_list: Option<ParamList>,
    pub items: Vec<Item>,
    pub end_macro: pc::endmacro,
}

impl Parse for MacroDef {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            macro_: input.parse()?,
            ident: input.parse()?,
            param_list: match input.peek(token::Paren) {
                true => Some(input.parse()?),
                false => None,
            },
            items: {
                let mut items = vec![];
                while !pc::endmacro::peek(input) {
                    items.push(input.parse()?)
                }
                items
            },
            end_macro: input.parse()?,
        })
    }
}

impl ToTokens for MacroDef {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            macro_,
            ident,
            param_list,
            items,
            end_macro,
        } = self;
        macro_.to_tokens(tokens);
        ident.to_tokens(tokens);
        if let Some(param_list) = param_list {
            param_list.to_tokens(tokens);
        }
        for item in items {
            item.to_tokens(tokens)
        }
        end_macro.to_tokens(tokens);
    }
}

#[derive(Parse)]
pub struct ParamList {
    #[paren]
    pub paren: token::Paren,
    #[inside(paren)]
    #[call(Punctuated::parse_terminated)]
    pub args: Punctuated<Ident, Token![,]>,
}

impl ToTokens for ParamList {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self { paren, args } = self;
        paren.surround(tokens, |tokens| args.to_tokens(tokens));
    }
}

#[derive(Parse, ToTokens)]
pub struct MacroCall {
    pub percent: Token![%],
    pub ident: Ident,
    #[peek(token::Paren)]
    pub macro_args: Option<MacroArgs>,
}

#[derive(Parse)]
pub struct MacroArgs {
    #[paren]
    pub paren: token::Paren,
    #[inside(paren)]
    #[call(Punctuated::parse_terminated)]
    pub args: Punctuated<Target, Token![,]>,
}

impl ToTokens for MacroArgs {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self { paren, args } = self;
        paren.surround(tokens, |tokens| args.to_tokens(tokens));
    }
}

#[derive(Parse, ToTokens)]
pub enum Target {
    #[peek(syn::LitInt, name = "Literal")]
    Literal(Literal),
    #[peek_with(Ident::peek, name = "Ident")]
    Ident(Ident),
    #[peek_with(pun::Percent2::peek, name = "a `%%..` macro label")]
    MacroLabel(MacroLabel),
    #[peek(Token![$], name = "a `$..` variable")]
    Variable(Variable),
    #[peek(Token![@], name = "a `@..` constant")]
    Constant(Constant),
}

pub struct Repeat {
    pub rep: pc::rep,
    pub literal: Literal,
    pub items: Vec<Item>,
    pub endrep: pc::endrep,
}

impl Parse for Repeat {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(Self {
            rep: input.parse()?,
            literal: input.parse()?,
            items: {
                let mut items = vec![];
                while !pc::endrep::peek(input) {
                    items.push(input.parse()?)
                }
                items
            },
            endrep: input.parse()?,
        })
    }
}

impl ToTokens for Repeat {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            rep,
            literal,
            items,
            endrep,
        } = self;
        rep.to_tokens(tokens);
        literal.to_tokens(tokens);
        for item in items {
            item.to_tokens(tokens);
        }
        endrep.to_tokens(tokens);
    }
}

#[derive(Parse)]
pub struct Stack {
    pub stack: pc::stack,
    #[paren]
    pub placeholders_paren: token::Paren,
    #[inside(placeholders_paren)]
    #[call(Punctuated::parse_terminated)]
    pub placeholders: Punctuated<Placeholder, Token![,]>,
    pub arrow: Token![->],
    #[paren]
    pub replacements_paren: token::Paren,
    #[inside(replacements_paren)]
    #[call(Punctuated::parse_terminated)]
    pub replacements: Punctuated<Target, Token![,]>,
}

impl ToTokens for Stack {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            stack,
            placeholders_paren,
            placeholders,
            arrow,
            replacements_paren,
            replacements,
        } = self;
        stack.to_tokens(tokens);
        placeholders_paren.surround(tokens, |tokens| placeholders.to_tokens(tokens));
        arrow.to_tokens(tokens);
        replacements_paren.surround(tokens, |tokens| replacements.to_tokens(tokens));
    }
}

#[derive(Parse, ToTokens)]
pub enum Placeholder {
    #[peek_with(peek2(Token![:]), name = "an `ident:` block")]
    Block(Block),
    #[peek_with(Ident::peek, name = "an ident")]
    Ident(Ident),
}

#[derive(Parse, ToTokens)]
pub struct Block {
    pub ident: Ident,
    pub colon: Token![:],
    pub number: Literal,
}

#[derive(Parse, ToTokens)]
pub struct GlobalDecl {
    pub global: kw::GLOBAL,
    pub ident: Ident,
    pub colon: Token![:],
}

#[derive(Parse, ToTokens)]
pub struct LocalDecl {
    pub ident: Ident,
    pub colon: Token![:],
}

#[derive(Parse, ToTokens)]
pub struct Bytes {
    pub bytes: kw::BYTES,
    #[call(Punctuated::parse_separated_nonempty)]
    pub components: Punctuated<LiteralOrConstant, Token![,]>,
}

#[derive(Parse, ToTokens)]
pub enum LiteralOrConstant {
    #[peek(syn::LitInt, name = "a literal")]
    Literal(Literal),
    #[peek(Token![@], name = "a `@..` constant")]
    Constant(Constant),
}

#[derive(Parse, ToTokens)]
pub struct Jumptable {
    pub jumptable: kw::JUMPTABLE,
    #[call(Punctuated::parse_separated_nonempty)]
    pub idents: Punctuated<Ident, Token![,]>,
}

#[derive(Parse, ToTokens)]
pub struct Push {
    pub push: kw::PUSH,
    pub target: Target,
}

#[derive(Parse)]
pub struct ProverInput {
    pub prover_input: kw::PROVER_INPUT,
    #[paren]
    pub paren: token::Paren,
    #[inside(paren)]
    #[call(Punctuated::parse_separated_nonempty)]
    pub function: Punctuated<Ident, Token![::]>,
}

impl ToTokens for ProverInput {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            prover_input,
            paren,
            function,
        } = self;
        prover_input.to_tokens(tokens);
        paren.surround(tokens, |tokens| function.to_tokens(tokens));
    }
}

#[derive(Parse, ToTokens)]
pub struct Instruction {
    pub ident: Ident,
}

pub struct Cfg {
    pub pound: Token![#],
    pub bracket: token::Bracket,
    pub cfg: kw::cfg,
    pub paren: token::Paren,
    pub op: Option<(CfgOp, token::Paren)>,
    pub feature: kw::feature,
    pub eq: Token![=],
    pub features: Punctuated<Ident, Token![,]>,
}

impl Parse for Cfg {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let attr;
        let mut meta;
        Ok(Self {
            pound: input.parse()?,
            bracket: bracketed!(attr in input),
            cfg: attr.parse()?,
            paren: parenthesized!(meta in attr),
            op: {
                match CfgOp::peek(&meta) {
                    true => Some((meta.parse()?, parenthesized!(meta in meta))),
                    false => None,
                }
            },
            feature: meta.parse()?,
            eq: meta.parse()?,
            features: meta.call(Punctuated::parse_separated_nonempty)?,
        })
    }
}

impl ToTokens for Cfg {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self {
            pound,
            bracket,
            cfg,
            paren,
            op,
            feature,
            eq,
            features,
        } = self;
        pound.to_tokens(tokens);
        bracket.surround(tokens, |tokens| {
            cfg.to_tokens(tokens);
            paren.surround(tokens, |tokens| {
                let inner = |tokens: &mut TokenStream| {
                    feature.to_tokens(tokens);
                    eq.to_tokens(tokens);
                    features.to_tokens(tokens);
                };
                match op {
                    Some((op, paren)) => {
                        op.to_tokens(tokens);
                        paren.surround(tokens, inner);
                    }
                    None => inner(tokens),
                }
            });
        });
    }
}

#[derive(Parse, ToTokens)]
pub enum CfgOp {
    #[peek(kw::not, name = "not")]
    Not(kw::not),
    #[peek(kw::all, name = "all")]
    All(kw::all),
    #[peek(kw::any, name = "any")]
    Any(kw::any),
}

impl CfgOp {
    pub fn peek(input: ParseStream) -> bool {
        input.fork().parse::<Self>().is_ok()
    }
}

pub struct CfgItems {
    pub cfg: Cfg,
    pub brace: token::Brace,
    pub items: Vec<Item>,
}

impl Parse for CfgItems {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let content;
        Ok(Self {
            cfg: input.parse()?,
            brace: braced!(content in input),
            items: {
                let mut items = vec![];
                while !content.is_empty() {
                    items.push(content.parse()?);
                }
                items
            },
        })
    }
}

impl ToTokens for CfgItems {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let Self { cfg, brace, items } = self;
        cfg.to_tokens(tokens);
        brace.surround(tokens, |tokens| {
            for item in items {
                item.to_tokens(tokens);
            }
        });
    }
}
