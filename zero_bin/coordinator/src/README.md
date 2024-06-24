

# Module Descsriptions

- benchmarking -> Contains the necessities of storing and outputting the benchmark statistics in the app-layer gathered during the proving process
- fetch -> Our means of "fetching" blocks as prover_input
- input -> Some data structures used for the input to the http server endpoint.  Note, some of the structures are distributed to other modules if they better relate to that module.
- manyprover -> Contains the function that runs the proving process for many blocks.  Most of the logic happens here.
- proofout -> Contains the necessities of outputting the proofs.
- psm -> Creates a ProverStateManager from the env, should only really be necessary when operating InMemory rather than using AMQP
