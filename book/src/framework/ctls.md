## Cross-Table Lookups

The various STARK tables carry out independent operations, but on shared values. We need to check that the shared values are identical in all the STARKs that require them. This is where cross-table lookups (CTLs) come in handy.

Suppose STARK $S_1$ requires an operation -- say $Op$ -- that is carried out by another STARK $S_2$. Then $S_1$ writes the input and output of $Op$ in its own table, and provides the inputs to $S_2$. $S_2$ also writes the inputs and outputs in its rows, and the table's constraints check that $Op$ is carried out correctly. We then need to ensure that the inputs and outputs are the same in $S_1$ and $S_2$.

In other words, we need to ensure that the rows -- reduced to the input and output columns -- of $S_1$ calling $Op$ are permutations of the rows of $S_2$ that carry out $Op$. Our CTL protocol is based on logUp and is similar to our range-checks.

To prove this, the first step is to only select the rows of interest in $S_1$ and $S_2$, and filter out the rest. Let $f^1$ be the filter for $S_1$ and $f^2$ the filter for $S_2$. $f^1$ and $f^2$ are constrained to be in $\{0, 1\}$. $f^1 = 1$ (resp. $f^2 = 1$) whenever the row at hand carries out $Op$ in $S_1$ (resp. in $S_2$), and 0 otherwise. Let also $(\alpha, \beta)$ be two random challenges.

The idea is to create subtables $S_1'$ and $S_2'$ of $S_1$ and $S_2$ respectively, such that $f^1 = 1$ and $f^2 = 1$ for all their rows. The columns in the subtables are limited to the ones whose values must be identical (the inputs and outputs of $Op$ in our example).

Note that for design and constraint reasons, filters are limited to (at most) degree 2 combinations of columns.

Let $\{c^{1, i}\}_{i=1}^m$ be the columns in $S_1'$ an $\{c^{2,i}\}_{i=1}^m$ be the columns in $S_2'$.

The prover defines a "running sum" $Z$ for $S_1'$ such that:
$$\begin{gathered}
  Z^{S_1}_{n-1} = \frac{1}{\sum_{j=0}^{m-1} \alpha^j \cdot c^{1, j}_{n-1} + \beta} \\
  Z^{S_1}_{i+1} = Z^{S_1}_i + f^1_i \cdot \frac{1}{\sum_{j=0}^{m-1} \alpha^j \cdot c^{1, j}_i + \beta}
\end{gathered}$$

The second equation "selects" the terms of interest thanks to $f^1$ and filters out the rest.

Similarly, the prover constructs a running sum $Z^{S_2}$for $S_2$. Note that $Z$ is computed "upside down": we start with $Z_{n-1}$ and the final sum is in $Z_0$.

On top of the constraints to check that the running sums were correctly constructed, the verifier checks that $Z^{S_1}_0 = Z^{S_2}_0$. This ensures that the columns in $S_1'$ and the columns in $S_2'$ are permutations of each other.

In other words, the CTL argument is a logUp lookup argument where $S_1'$ is the looking table, $S_2'$ is the looked table, and $S_1' = S_2'$ (all the multiplicities are 1). For more details about logUp, see the next section.

To sum up, for each STARK $S$, the prover:

1.  constructs a running sum $Z_i^l$ for each table looking into $S$
    (called looking sums here),

2.  constructs a running sum $Z^S$ for $S$ (called looked sum here),

3.  sends the final value for each running sum $Z_{i, 0}^l$ and $Z^S_0$
    to the verifier,

4.  sends a commitment to $Z_i^l$ and $Z^S$ to the verifier.

Then, for each STARK $S$, the verifier:

1.  computes the sum $Z = \sum_i Z_{i, 0}^l$,

2.  checks that $Z = Z^S_0$,

3.  checks that each $Z_i^l$ and $Z^S$ was correctly constructed.