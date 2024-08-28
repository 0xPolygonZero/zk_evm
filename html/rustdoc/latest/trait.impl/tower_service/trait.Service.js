(function() {
    var implementors = Object.fromEntries([["rpc",[["impl&lt;S&gt; Service&lt;RequestPacket&gt; for <a class=\"struct\" href=\"rpc/retry/struct.RetryService.html\" title=\"struct rpc::retry::RetryService\">RetryService</a>&lt;S&gt;<div class=\"where\">where\n    S: Service&lt;RequestPacket, Response = ResponsePacket, Error = TransportError&gt; + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + 'static + <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/clone/trait.Clone.html\" title=\"trait core::clone::Clone\">Clone</a>,\n    S::Future: <a class=\"trait\" href=\"https://doc.rust-lang.org/nightly/core/marker/trait.Send.html\" title=\"trait core::marker::Send\">Send</a> + 'static,</div>"]]]]);
    if (window.register_implementors) {
        window.register_implementors(implementors);
    } else {
        window.pending_implementors = implementors;
    }
})()
//{"start":57,"fragment_lengths":[757]}