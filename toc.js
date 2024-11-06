// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
var sidebarScrollbox = document.querySelector("#sidebar .sidebar-scrollbox");
sidebarScrollbox.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="../../index.html">Introduction</a></li><li class="chapter-item expanded "><a href="framework/intro.html"><strong aria-hidden="true">1.</strong> STARK framework</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="framework/field.html"><strong aria-hidden="true">1.1.</strong> Field</a></li><li class="chapter-item expanded "><a href="framework/cost_model.html"><strong aria-hidden="true">1.2.</strong> Cost model</a></li><li class="chapter-item expanded "><a href="framework/ctls.html"><strong aria-hidden="true">1.3.</strong> Cross-Table Lookups</a></li><li class="chapter-item expanded "><a href="framework/range_check.html"><strong aria-hidden="true">1.4.</strong> Range-Checks</a></li></ol></li><li class="chapter-item expanded "><a href="tables/intro.html"><strong aria-hidden="true">2.</strong> Tables</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="tables/cpu.html"><strong aria-hidden="true">2.1.</strong> CPU</a></li><li class="chapter-item expanded "><a href="tables/arithmetic.html"><strong aria-hidden="true">2.2.</strong> Arithmetic</a></li><li class="chapter-item expanded "><a href="tables/byte_packing.html"><strong aria-hidden="true">2.3.</strong> BytePacking</a></li><li class="chapter-item expanded "><a href="tables/keccak.html"><strong aria-hidden="true">2.4.</strong> Keccak</a></li><li class="chapter-item expanded "><a href="tables/keccak_sponge.html"><strong aria-hidden="true">2.5.</strong> KeccakSponge</a></li><li class="chapter-item expanded "><a href="tables/logic.html"><strong aria-hidden="true">2.6.</strong> Logic</a></li><li class="chapter-item expanded "><a href="tables/memory.html"><strong aria-hidden="true">2.7.</strong> Memory</a></li><li class="chapter-item expanded "><a href="tables/mem_continuations.html"><strong aria-hidden="true">2.8.</strong> MemBefore &amp; MemAfter</a></li></ol></li><li class="chapter-item expanded "><a href="mpt/intro.html"><strong aria-hidden="true">3.</strong> Merkle Patricia Tries</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="mpt/memory_format.html"><strong aria-hidden="true">3.1.</strong> Memory format</a></li><li class="chapter-item expanded "><a href="mpt/prover_input_format.html"><strong aria-hidden="true">3.2.</strong> Prover input format</a></li><li class="chapter-item expanded "><a href="mpt/encoding_hashing.html"><strong aria-hidden="true">3.3.</strong> Encoding and hashing</a></li><li class="chapter-item expanded "><a href="mpt/linked_lists.html"><strong aria-hidden="true">3.4.</strong> Linked lists</a></li></ol></li><li class="chapter-item expanded "><a href="cpu_execution/intro.html"><strong aria-hidden="true">4.</strong> CPU Execution</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="cpu_execution/kernel.html"><strong aria-hidden="true">4.1.</strong> Kernel</a></li><li class="chapter-item expanded "><a href="cpu_execution/opcodes_syscalls.html"><strong aria-hidden="true">4.2.</strong> Opcodes &amp; Syscalls</a></li><li class="chapter-item expanded "><a href="cpu_execution/privileged_instructions.html"><strong aria-hidden="true">4.3.</strong> Privileged Instructions</a></li><li class="chapter-item expanded "><a href="cpu_execution/stack_handling.html"><strong aria-hidden="true">4.4.</strong> Stack handling</a></li><li class="chapter-item expanded "><a href="cpu_execution/gas_handling.html"><strong aria-hidden="true">4.5.</strong> Gas handling</a></li><li class="chapter-item expanded "><a href="cpu_execution/exceptions.html"><strong aria-hidden="true">4.6.</strong> Exceptions</a></li></ol></li><li class="chapter-item expanded "><a href="bibliography.html">Bibliography</a></li></ol>';
(function() {
    let current_page = document.location.href.toString();
    if (current_page.endsWith("/")) {
        current_page += "index.html";
    }
    var links = sidebarScrollbox.querySelectorAll("a");
    var l = links.length;
    for (var i = 0; i < l; ++i) {
        var link = links[i];
        var href = link.getAttribute("href");
        if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
            link.href = path_to_root + href;
        }
        // The "index" page is supposed to alias the first chapter in the book.
        if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
            link.classList.add("active");
            var parent = link.parentElement;
            while (parent) {
                if (parent.tagName === "LI" && parent.previousElementSibling) {
                    if (parent.previousElementSibling.classList.contains("chapter-item")) {
                        parent.previousElementSibling.classList.add("expanded");
                    }
                }
                parent = parent.parentElement;
            }
        }
    }
})();

// Track and set sidebar scroll position
sidebarScrollbox.addEventListener('click', function(e) {
    if (e.target.tagName === 'A') {
        sessionStorage.setItem('sidebar-scroll', sidebarScrollbox.scrollTop);
    }
}, { passive: true });
var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
sessionStorage.removeItem('sidebar-scroll');
if (sidebarScrollTop) {
    // preserve sidebar scroll position when navigating via links within sidebar
    sidebarScrollbox.scrollTop = sidebarScrollTop;
} else {
    // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
    var activeSection = document.querySelector('#sidebar .active');
    if (activeSection) {
        activeSection.scrollIntoView({ block: 'center' });
    }
}
