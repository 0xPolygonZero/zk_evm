# Usage Diagrams
These are some hacked together diagrams showing how the protocol will (likely) be used. Also included what the old Edge proof generation process looked like as a reference.

## Proof Protocol

```mermaid
sequenceDiagram
    proof protocol client->>proof scheduler: protocol_payload
    proof scheduler->>protocol decoder (lib): protolcol_payload
    Note over proof scheduler,protocol decoder (lib): "txn_proof_gen_ir" are the payloads sent to Paladin for a txn
    protocol decoder (lib)->>proof scheduler: [txn_proof_gen_ir]
    proof scheduler->>paladin: [txn_proof_gen_ir]
    Note over proof scheduler,paladin: Paladin schedules jobs on mulitple machines and returns a block proof
    loop txn_proof_gen_ir
        paladin->>worker machine: proof_gen_payload (txn, agg, block)
        worker machine->>paladin: generated_proof (txn, agg, block)
    end
    paladin->>proof scheduler: block_proof
    Note over proof scheduler,checkpoint contract: Note: Might send to an external service instead that compresses the proof
    proof scheduler->>checkpoint contract: block_proof
```

## Edge Proof Generation

```mermaid
sequenceDiagram
    edge->>zero provers (leader): block_trace
    zero provers (leader)->>trace parsing lib: block_trace
    Note over zero provers (leader),trace parsing lib: "txn_proof_gen_ir" are the payloads sent to each worker for a txn
    trace parsing lib->>zero provers (leader): [txn_proof_gen_ir]
    loop txn_proof_gen_ir
        zero provers (leader)->>zero provers (worker): proof_gen_payload (txn, agg, block)
        zero provers (worker)->>zero provers (leader): generated_proof (txn, agg, block)
    end
    zero provers (leader)->>checkpoint contract: block_proof
```
