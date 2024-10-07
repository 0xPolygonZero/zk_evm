use std::{collections::HashSet, str::FromStr};

use ethereum_types::U256;
use itertools::Itertools;
use pest::iterators::{Pair, Pairs};
use pest::{Parser, Span};

use super::ast::{BytesTarget, StackPlaceholder};
use crate::cpu::kernel::ast::{File, Item, PushTarget, StackReplacement};

/// Parses EVM assembly code.
#[derive(pest_derive::Parser)]
#[grammar = "cpu/kernel/evm_asm.pest"]
pub struct AsmParser;

pub(crate) fn parse(s: &str, active_features: &HashSet<&str>) -> File {
    let s = strip_comments(s);
    let file = AsmParser::parse(Rule::file, &s)
        .expect("Parsing failed")
        .next()
        .unwrap();

    let body = file
        .into_inner()
        .map(|i| parse_item(i, active_features))
        .collect();
    File { body }
}

/// - We want one grammar to parse from.
/// - We want a comment-aware parse tree to provide syntax highlighting.
/// - The rest of the parsing code does not handle [`Rule::COMMENT`]s, and it
///   would be a pain to add.
/// - The AST doesn't track source locations, so changing positions doesn't
///   matter.
///
/// So just strip before parsing.
fn strip_comments(s: &str) -> String {
    return match AsmParser::parse(Rule::file, s) {
        Ok(tree) => {
            let mut spans = vec![];
            comment_spans(&mut spans, tree);
            spans.sort_by_key(|it| std::cmp::Reverse(it.start()));

            let mut s = String::from(s);
            for span in spans {
                s.replace_range(span.start()..span.end(), "");
            }
            s
        }
        Err(_) => String::from(s), // let the rest of the compiler bail
    };

    fn comment_spans<'a>(spans: &mut Vec<Span<'a>>, pairs: Pairs<'a, Rule>) {
        for pair in pairs {
            if let Rule::COMMENT = pair.as_rule() {
                spans.push(pair.as_span());
            }
            comment_spans(spans, pair.into_inner());
        }
    }
}

fn parse_item(item: Pair<Rule>, active_features: &HashSet<&str>) -> Item {
    assert_eq!(item.as_rule(), Rule::item);
    let item = item.into_inner().next().unwrap();
    match item.as_rule() {
        Rule::conditional_block => parse_conditional_block(item, active_features),
        Rule::macro_def => parse_macro_def(item, active_features),
        Rule::macro_call => parse_macro_call(item),
        Rule::repeat => parse_repeat(item, active_features),
        Rule::stack => parse_stack(item),
        Rule::global_label_decl => {
            Item::GlobalLabelDeclaration(item.into_inner().next().unwrap().as_str().into())
        }
        Rule::local_label_decl => {
            Item::LocalLabelDeclaration(item.into_inner().next().unwrap().as_str().into())
        }
        Rule::macro_label_decl => {
            Item::MacroLabelDeclaration(item.into_inner().next().unwrap().as_str().into())
        }
        Rule::bytes_item => Item::Bytes(item.into_inner().map(parse_bytes_target).collect()),
        Rule::jumptable_item => {
            Item::Jumptable(item.into_inner().map(|i| i.as_str().into()).collect())
        }
        Rule::push_instruction => Item::Push(parse_push_target(item.into_inner().next().unwrap())),
        Rule::prover_input_instruction => Item::ProverInput(
            item.into_inner()
                .next()
                .unwrap()
                .into_inner()
                .map(|x| x.as_str().into())
                .collect::<Vec<_>>()
                .into(),
        ),
        Rule::nullary_instruction => Item::StandardOp(item.as_str().to_uppercase()),
        _ => panic!("Unexpected {:?}", item.as_rule()),
    }
}

enum FeatureGroupRule {
    /// Ignore code if any of the listed features is active.
    Not,
    /// Include code if any of the listed features is active.
    Any,
    /// Include code if all the listed features are active.
    All,
}

impl FeatureGroupRule {
    fn from_rule(string: &str) -> Self {
        if string.starts_with("not") {
            return Self::Not;
        }
        if string.starts_with("all") {
            return Self::All;
        }

        Self::Any
    }
}

fn parse_conditional_block(item: Pair<Rule>, active_features: &HashSet<&str>) -> Item {
    /// Outputs true if any of the listed features is in the active set.
    fn is_supported(
        active_features: &HashSet<&str>,
        features_string: &str,
        group_rule: FeatureGroupRule,
    ) -> bool {
        let features = features_string
            .split(&[',', ' ']) // allows for both `foo,bar` and `foo, bar` in ASM
            .filter(|s| !s.is_empty());

        match group_rule {
            FeatureGroupRule::Not => {
                for feature in features {
                    if active_features.contains(feature) {
                        return false;
                    }
                }
                true
            }
            FeatureGroupRule::Any => {
                for feature in features {
                    if active_features.contains(feature) {
                        return true;
                    }
                }
                false
            }
            FeatureGroupRule::All => {
                for feature in features {
                    if !active_features.contains(feature) {
                        return false;
                    }
                }
                true
            }
        }
    }

    assert_eq!(item.as_rule(), Rule::conditional_block);
    let mut inner = item.into_inner().peekable();

    let mut name = inner.next().unwrap().as_str();
    let group_rule = FeatureGroupRule::from_rule(name);
    if name.contains(")") {
        // Remove last `)` char
        name = &name[..name.len() - 1];
    }
    let features = name.split(" = ").collect_vec()[1];
    let feature_supported = is_supported(active_features, features, group_rule);

    if feature_supported {
        Item::ConditionalBlock(
            name.into(),
            inner.map(|i| parse_item(i, active_features)).collect(),
        )
    } else {
        Item::ConditionalBlock(name.into(), vec![])
    }
}

fn parse_macro_def(item: Pair<Rule>, active_features: &HashSet<&str>) -> Item {
    assert_eq!(item.as_rule(), Rule::macro_def);
    let mut inner = item.into_inner().peekable();

    let name = inner.next().unwrap().as_str().into();

    // The parameter list is optional.
    let params = if let Some(Rule::paramlist) = inner.peek().map(|pair| pair.as_rule()) {
        let params = inner.next().unwrap().into_inner();
        params.map(|param| param.as_str().to_string()).collect()
    } else {
        vec![]
    };

    Item::MacroDef(
        name,
        params,
        inner.map(|i| parse_item(i, active_features)).collect(),
    )
}

fn parse_macro_call(item: Pair<Rule>) -> Item {
    assert_eq!(item.as_rule(), Rule::macro_call);
    let mut inner = item.into_inner();

    let name = inner.next().unwrap().as_str().into();

    // The arg list is optional.
    let args = if let Some(arglist) = inner.next() {
        assert_eq!(arglist.as_rule(), Rule::macro_arglist);
        arglist.into_inner().map(parse_push_target).collect()
    } else {
        vec![]
    };

    Item::MacroCall(name, args)
}

fn parse_repeat(item: Pair<Rule>, active_features: &HashSet<&str>) -> Item {
    assert_eq!(item.as_rule(), Rule::repeat);
    let mut inner = item.into_inner();
    let count = parse_literal_u256(inner.next().unwrap());
    Item::Repeat(
        count,
        inner.map(|i| parse_item(i, active_features)).collect(),
    )
}

fn parse_stack(item: Pair<Rule>) -> Item {
    assert_eq!(item.as_rule(), Rule::stack);
    let mut inner = item.into_inner();

    let placeholders = inner.next().unwrap();
    assert_eq!(placeholders.as_rule(), Rule::stack_placeholders);
    let replacements = inner.next().unwrap();
    assert_eq!(replacements.as_rule(), Rule::stack_replacements);

    let placeholders = placeholders
        .into_inner()
        .map(parse_stack_placeholder)
        .collect();
    let replacements = replacements
        .into_inner()
        .map(parse_stack_replacement)
        .collect();
    Item::StackManipulation(placeholders, replacements)
}

fn parse_stack_placeholder(target: Pair<Rule>) -> StackPlaceholder {
    assert_eq!(target.as_rule(), Rule::stack_placeholder);
    let inner = target.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::identifier => StackPlaceholder(inner.as_str().into(), 1),
        Rule::stack_block => {
            let mut block = inner.into_inner();
            let identifier = block.next().unwrap().as_str();
            let length = block.next().unwrap().as_str().parse().unwrap();
            StackPlaceholder(identifier.to_string(), length)
        }
        _ => panic!("Unexpected {:?}", inner.as_rule()),
    }
}

fn parse_stack_replacement(target: Pair<Rule>) -> StackReplacement {
    assert_eq!(target.as_rule(), Rule::stack_replacement);
    let inner = target.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::identifier => StackReplacement::Identifier(inner.as_str().into()),
        Rule::literal => StackReplacement::Literal(parse_literal_u256(inner)),
        Rule::macro_label => {
            StackReplacement::MacroLabel(inner.into_inner().next().unwrap().as_str().into())
        }
        Rule::variable => {
            StackReplacement::MacroVar(inner.into_inner().next().unwrap().as_str().into())
        }
        Rule::constant => {
            StackReplacement::Constant(inner.into_inner().next().unwrap().as_str().into())
        }
        _ => panic!("Unexpected {:?}", inner.as_rule()),
    }
}

fn parse_push_target(target: Pair<Rule>) -> PushTarget {
    assert_eq!(target.as_rule(), Rule::push_target);
    let inner = target.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::literal => PushTarget::Literal(parse_literal_u256(inner)),
        Rule::identifier => PushTarget::Label(inner.as_str().into()),
        Rule::macro_label => {
            PushTarget::MacroLabel(inner.into_inner().next().unwrap().as_str().into())
        }
        Rule::variable => PushTarget::MacroVar(inner.into_inner().next().unwrap().as_str().into()),
        Rule::constant => PushTarget::Constant(inner.into_inner().next().unwrap().as_str().into()),
        _ => panic!("Unexpected {:?}", inner.as_rule()),
    }
}

fn parse_bytes_target(target: Pair<Rule>) -> BytesTarget {
    assert_eq!(target.as_rule(), Rule::bytes_target);
    let inner = target.into_inner().next().unwrap();
    match inner.as_rule() {
        Rule::literal => BytesTarget::Literal(parse_literal_u8(inner)),
        Rule::constant => BytesTarget::Constant(inner.into_inner().next().unwrap().as_str().into()),
        _ => panic!("Unexpected {:?}", inner.as_rule()),
    }
}

fn parse_literal_u8(literal: Pair<Rule>) -> u8 {
    let literal = literal.into_inner().next().unwrap();
    match literal.as_rule() {
        Rule::literal_decimal => {
            u8::from_str(literal.as_str()).expect("Failed to parse literal decimal byte")
        }
        Rule::literal_hex => {
            u8::from_str_radix(&parse_hex(literal), 16).expect("Failed to parse literal hex byte")
        }
        _ => panic!("Unexpected {:?}", literal.as_rule()),
    }
}

fn parse_literal_u256(literal: Pair<Rule>) -> U256 {
    let literal = literal.into_inner().next().unwrap();
    match literal.as_rule() {
        Rule::literal_decimal => {
            U256::from_dec_str(literal.as_str()).expect("Failed to parse literal decimal")
        }
        Rule::literal_hex => {
            U256::from_str_radix(&parse_hex(literal), 16).expect("Failed to parse literal hex")
        }
        _ => panic!("Unexpected {:?}", literal.as_rule()),
    }
}

fn parse_hex(hex: Pair<Rule>) -> String {
    let prefix = &hex.as_str()[..2];
    debug_assert!(prefix == "0x" || prefix == "0X");
    hex.as_str()[2..].to_string()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;
    use crate::cpu::kernel::assembler::assemble;

    #[test]
    fn test_feature() {
        let code = r#"
        %macro bar_foo
            // requires any of the two features, using the default format
            #[cfg(feature = feature_1,feature_2)]
            {
                %bar
            }
            // requires any of the two features, using the `any` identifier
            #[cfg(any(feature = feature_1,feature_2))]
            {
                PUSH 3
                ADD
            }
        %endmacro

        // requires `feature_1`
        #[cfg(feature = feature_1)]
        {
            %macro bar
                PUSH 2
                MUL
            %endmacro
        }

        global foo_1:
            PUSH 1
            PUSH 2

            // requires `feature_1`
            #[cfg(feature = feature_1)]
            {
                %bar_foo
                PUSH 1
            }
            PUSH 3
            PUSH 4
            ADD

        global foo_3:
            PUSH 5
            PUSH 6
            DIV

        // requires `feature_2`
        #[cfg(feature = feature_2)]
        {
            global foo_4:
                PUSH 7
                // requires to not have `feature_1`
                #[cfg(not(feature = feature_1))]
                {
                    DUP1
                }
                #[cfg(feature = feature_1)]
                {
                    PUSH 8
                }
            MOD
        }

        // requires all features
        #[cfg(all(feature = feature_1,feature_2))]
        {
            global foo_5:
                PUSH 1
                POP
        }
        "#;

        // Test `feature_1`.
        let active_features = HashSet::from(["feature_1"]);

        let parsed_code = parse(code, &active_features);
        let final_code = assemble(vec![parsed_code], HashMap::new(), false);

        let expected_code = r#"
        %macro bar_foo
            %bar
            PUSH 3
            ADD
        %endmacro
    
        %macro bar
            PUSH 2
            MUL
        %endmacro

        global foo_1:
            PUSH 1
            PUSH 2
            %bar_foo
            PUSH 1
            PUSH 3
            PUSH 4
            ADD

        global foo_3:
            PUSH 5
            PUSH 6
            DIV
        "#;

        let parsed_expected = parse(expected_code, &HashSet::new());
        let final_expected = assemble(vec![parsed_expected], HashMap::new(), false);

        assert_eq!(final_code.code, final_expected.code);

        // Test `feature_2`.
        let active_features = HashSet::from(["feature_2"]);

        let parsed_code = parse(code, &active_features);
        let final_code = assemble(vec![parsed_code], HashMap::new(), false);

        let expected_code = r#"
        %macro bar_foo
            PUSH 3
            ADD
        %endmacro
    
        global foo_1:
            PUSH 1
            PUSH 2
            PUSH 3
            PUSH 4
            ADD

        global foo_3:
            PUSH 5
            PUSH 6
            DIV

        global foo_4:
            PUSH 7
            DUP1
            MOD
        "#;

        let parsed_expected = parse(expected_code, &HashSet::new());
        let final_expected = assemble(vec![parsed_expected], HashMap::new(), false);

        assert_eq!(final_code.code, final_expected.code);

        // Test with both features enabled.
        let active_features = HashSet::from(["feature_1", "feature_2"]);

        let parsed_code = parse(code, &active_features);
        let final_code = assemble(vec![parsed_code], HashMap::new(), false);

        let expected_code = r#"
        %macro bar_foo
            %bar
            PUSH 3
            ADD
        %endmacro
    
        %macro bar
            PUSH 2
            MUL
        %endmacro

        global foo_1:
            PUSH 1
            PUSH 2
            %bar_foo
            PUSH 1
            PUSH 3
            PUSH 4
            ADD

        global foo_3:
            PUSH 5
            PUSH 6
            DIV

        global foo_4:
            PUSH 7
            PUSH 8
            MOD
        
        global foo_5:
            PUSH 1
            POP
        "#;

        let parsed_expected = parse(expected_code, &HashSet::new());
        let final_expected = assemble(vec![parsed_expected], HashMap::new(), false);

        assert_eq!(final_code.code, final_expected.code);

        // Test with all features disabled.
        let active_features = HashSet::new();

        let parsed_code = parse(code, &active_features);
        let final_code = assemble(vec![parsed_code], HashMap::new(), false);

        let expected_code = r#"
        global foo_1:
            PUSH 1
            PUSH 2
            PUSH 3
            PUSH 4
            ADD

        global foo_3:
            PUSH 5
            PUSH 6
            DIV
        "#;

        let parsed_expected = parse(expected_code, &HashSet::new());
        let final_expected = assemble(vec![parsed_expected], HashMap::new(), false);

        assert_eq!(final_code.code, final_expected.code);
    }
}
