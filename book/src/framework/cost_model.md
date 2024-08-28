## Cost model

Our zkEVM is designed for efficient verification by STARKs @@stark, particularly by an AIR with degree 3 constraints. In this model, the prover bottleneck is typically constructing Merkle trees, particularly constructing the tree containing low-degree extensions of witness polynomials.