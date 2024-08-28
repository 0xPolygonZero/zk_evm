(function() {
    var type_impls = Object.fromEntries([["evm_arithmetization",[["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-Debug-for-StarkFrame%3CT,+U,+N,+N2%3E\" class=\"impl\"><a href=\"#impl-Debug-for-StarkFrame%3CT,+U,+N,+N2%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, U, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>, const N2: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt; <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> for StarkFrame&lt;T, U, N, N2&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,\n    U: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html\" title=\"trait core::fmt::Debug\">Debug</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle method-toggle\" open><summary><section id=\"method.fmt\" class=\"method trait-impl\"><a href=\"#method.fmt\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\" class=\"fn\">fmt</a>(&amp;self, f: &amp;mut <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Formatter.html\" title=\"struct core::fmt::Formatter\">Formatter</a>&lt;'_&gt;) -&gt; <a class=\"enum\" href=\"https://doc.rust-lang.org/nightly/core/result/enum.Result.html\" title=\"enum core::result::Result\">Result</a>&lt;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.unit.html\">()</a>, <a class=\"struct\" href=\"https://doc.rust-lang.org/nightly/core/fmt/struct.Error.html\" title=\"struct core::fmt::Error\">Error</a>&gt;</h4></section></summary><div class='docblock'>Formats the value using the given formatter. <a href=\"https://doc.rust-lang.org/nightly/core/fmt/trait.Debug.html#tymethod.fmt\">Read more</a></div></details></div></details>","Debug","evm_arithmetization::all_stark::EvmStarkFrame"],["<details class=\"toggle implementors-toggle\" open><summary><section id=\"impl-StarkEvaluationFrame%3CT,+U%3E-for-StarkFrame%3CT,+U,+N,+N2%3E\" class=\"impl\"><a href=\"#impl-StarkEvaluationFrame%3CT,+U%3E-for-StarkFrame%3CT,+U,+N,+N2%3E\" class=\"anchor\">§</a><h3 class=\"code-header\">impl&lt;T, U, const N: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>, const N2: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a>&gt; StarkEvaluationFrame&lt;T, U&gt; for StarkFrame&lt;T, U, N, N2&gt;<div class=\"where\">where\n    T: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,\n    U: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Copy.html\" title=\"trait core::marker::Copy\">Copy</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a> + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/default/trait.Default.html\" title=\"trait core::default::Default\">Default</a>,</div></h3></section></summary><div class=\"impl-items\"><details class=\"toggle\" open><summary><section id=\"associatedconstant.COLUMNS\" class=\"associatedconstant trait-impl\"><a href=\"#associatedconstant.COLUMNS\" class=\"anchor\">§</a><h4 class=\"code-header\">const <a class=\"constant\">COLUMNS</a>: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a> = N</h4></section></summary><div class='docblock'>The number of columns for the STARK table this evaluation frame views.</div></details><details class=\"toggle\" open><summary><section id=\"associatedconstant.PUBLIC_INPUTS\" class=\"associatedconstant trait-impl\"><a href=\"#associatedconstant.PUBLIC_INPUTS\" class=\"anchor\">§</a><h4 class=\"code-header\">const <a class=\"constant\">PUBLIC_INPUTS</a>: <a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.usize.html\">usize</a> = N2</h4></section></summary><div class='docblock'>The number of public inputs for the STARK.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.get_local_values\" class=\"method trait-impl\"><a href=\"#method.get_local_values\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">get_local_values</a>(&amp;self) -&gt; &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.slice.html\">[T]</a></h4></section></summary><div class='docblock'>Returns the local values (i.e. current row) for this evaluation frame.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.get_next_values\" class=\"method trait-impl\"><a href=\"#method.get_next_values\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">get_next_values</a>(&amp;self) -&gt; &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.slice.html\">[T]</a></h4></section></summary><div class='docblock'>Returns the next values (i.e. next row) for this evaluation frame.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.get_public_inputs\" class=\"method trait-impl\"><a href=\"#method.get_public_inputs\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">get_public_inputs</a>(&amp;self) -&gt; &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.slice.html\">[U]</a></h4></section></summary><div class='docblock'>Returns the public inputs for this evaluation frame.</div></details><details class=\"toggle method-toggle\" open><summary><section id=\"method.from_values\" class=\"method trait-impl\"><a href=\"#method.from_values\" class=\"anchor\">§</a><h4 class=\"code-header\">fn <a class=\"fn\">from_values</a>(lv: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.slice.html\">[T]</a>, nv: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.slice.html\">[T]</a>, pis: &amp;<a class=\"primitive\" href=\"https://doc.rust-lang.org/nightly/std/primitive.slice.html\">[U]</a>) -&gt; StarkFrame&lt;T, U, N, N2&gt;</h4></section></summary><div class='docblock'>Outputs a new evaluation frame from the provided local and next values. <a>Read more</a></div></details></div></details>","StarkEvaluationFrame<T, U>","evm_arithmetization::all_stark::EvmStarkFrame"]]]]);
    if (window.register_type_impls) {
        window.register_type_impls(type_impls);
    } else {
        window.pending_type_impls = type_impls;
    }
})()
//{"start":55,"fragment_lengths":[7835]}