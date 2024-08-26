## Range-checks {#rc}

In most cases, tables deal with U256 words, split into 32-bit limbs (to avoid overflowing the field). To prevent a malicious prover from cheating, it is crucial to range-check those limbs.

### What to range-check?

One can note that every element that ever appears on the stack has been pushed. Therefore, enforcing a range-check on pushed elements is enough to range-check all elements on the stack. Similarly, all elements in memory must have been written prior, and therefore it is enough to range-check memory writes. However, range-checking the PUSH and MSTORE opcodes is not sufficient.

1.  Pushes and memory writes for "MSTORE_32BYTES" are range-checked in
    "BytePackingStark", except PUSH operations happening in privileged
    mode. See
    [\[push_general_view\]](#push_general_view){reference-type="ref"
    reference="push_general_view"}.

2.  Syscalls, exceptions and prover inputs are range-checked in
    "ArithmeticStark".

3.  The inputs and outputs of binary and ternary arithmetic operations
    are range-checked in "ArithmeticStark".

4.  The inputs' bits of logic operations are checked to be either 1 or 0
    in "LogicStark". Since "LogicStark" only deals with bitwise
    operations, this is enough to have range-checked outputs as well.

5.  The inputs of Keccak operations are range-checked in "KeccakStark".
    The output digest is written as bytes in "KeccakStark". Those bytes
    are used to reconstruct the associated 32-bit limbs checked against
    the limbs in "CpuStark". This implicitly ensures that the output is
    range-checked.

Note that some operations do not require a range-check:

1.  "MSTORE_GENERAL" read the value to write from the stack. Thus, the
    written value was already range-checked by a previous push.

2.  "EQ" reads two -- already range-checked -- elements on the stack,
    and checks they are equal. The output is either 0 or 1, and does
    therefore not need to be checked.

3.  "NOT" reads one -- already range-checked -- element. The result is
    constrained to be equal to $\texttt{0xFFFFFFFF} - \texttt{input}$,
    which implicitly enforces the range check.

4.  "PC": the program counter cannot be greater than $2^{32}$ in user
    mode. Indeed, the user code cannot be longer than $2^{32}$, and
    jumps are constrained to be JUMPDESTs. Moreover, in kernel mode,
    every jump is towards a location within the kernel, and the kernel
    code is smaller than $2^{32}$. These two points implicitly enforce
    $PC$'s range check.

5.  "GET_CONTEXT", "DUP" and "SWAP" all read and push values that were
    already written in memory. The pushed values were therefore already
    range-checked.

Range-checks are performed on the range $[0, 2^{16} - 1]$, to limit the trace length.

### Lookup Argument

To enforce the range-checks, we leverage [logUp](https://eprint.iacr.org/2022/1530.pdf), a lookup argument by Ulrich Häbock. Given a looking table $s = (s_1, ..., s_n)$ and a looked table $t = (t_1, ..., t_m)$, the goal is to prove that $$\forall 1 \leq i \leq n, \exists 1 \leq j \leq r \texttt{ such that } s_i = t_j$$

In our case, $t = (0, .., 2^{16} - 1)$ and $s$ is composed of all the columns in each STARK that must be range-checked.

The logUp paper explains that proving the previous assertion is actually equivalent to proving that there exists a sequence $l$ such that:

$$\sum_{i=1}^n \frac{1}{X - s_i} = \sum_{j=1}^r \frac{l_j}{X-t_j}$$

The values of $s$ can be stored in $c$ different columns of length $n$ each. In that case, the equality becomes:

$$\sum_{k=1}^c \sum_{i=1}^n \frac{1}{X - s_i^k} = \sum_{j=1}^r \frac{l_j}{X-t_j}$$

The 'multiplicity' $m_i$ of value $t_i$ is defined as the number of times $t_i$ appears in $s$. In other words:

$$m_i = |s_j \in s; s_j = t_i|$$

Multiplicities provide a valid sequence of values in the previously stated equation. Thus, if we store the multiplicities, and are provided with a challenge $\alpha$, we can prove the lookup argument by ensuring:

$$\sum_{k=1}^c \sum_{i=1}^n \frac{1}{\alpha - s_i^k} = \sum_{j=1}^r \frac{m_j}{\alpha-t_j}$$

However, the equation is too high degree. To circumvent this issue, Häbock suggests providing helper columns $h_i$ and $d$ such that at a given row $i$:
$$\begin{gathered}
  h_i^k = \frac{1}{\alpha + s_i^k } \forall 1 \leq k \leq c \\
  d_i = \frac{1}{\alpha + t_i}
\end{gathered}$$

The $h$ helper columns can be batched together to save columns. We can batch at most $\texttt{constraint\_degree} - 1$ helper functions together. In our case, we batch them 2 by 2. At row $i$, we now have:
$$\begin{aligned}
  h_i^k = \frac{1}{\alpha + s_i^{2k}} + \frac{1}{\alpha + s_i^{2k+1}} \forall 1 \leq k \leq c/2 \\
\end{aligned}$$

If $c$ is odd, then we have one extra helper column:
$$h_i^{c/2+1} = \frac{1}{\alpha + s_i^{c}}$$

For clarity, we will assume that $c$ is even in what follows.

Let $g$ be a generator of a subgroup of order $n$. We extrapolate $h, m$ and $d$ to get polynomials such that, for $f \in \{h^k, m, g\}$: $f(g^i) = f_i$.

We can define the following polynomial:
$$Z(x) :=  \sum_{i=1}^n \big[\sum_{k=1}^{c/2} h^k(x) - m(x) * d(x)\big]$$

### Constraints

With these definitions and a challenge $\alpha$, we can finally check that the assertion holds with the following constraints:
$$\begin{gathered}
  Z(1) = 0 \\
  Z(g \alpha) = Z(\alpha) + \sum_{k=1}^{c/2} h^k(\alpha) - m(\alpha) d(\alpha)
\end{gathered}$$

These ensure that We also need to ensure that $h^k$ is well constructed for all $1 \leq k \leq c/2$:

$$h(\alpha)^k \cdot (\alpha + s_{2k}) \cdot (\alpha + s_{2k+1}) = (\alpha + s_{2k}) + (\alpha + s_{2k+1})$$

Note: if $c$ is odd, we have one unbatched helper column $h^{c/2+1}$ for which we need a last constraint:

$$h(\alpha)^{c/2+1} \cdot (\alpha + s_{c}) = 1$$

Finally, the verifier needs to ensure that the table $t$ was also correctly computed. In each STARK, $t$ is computed starting from 0 and adding at most 1 at each row. This construction is constrained as follows:

1.  $t(1) = 0$

2.  $(t(g^{i+1}) - t(g^{i})) \cdot ((t(g^{i+1}) - t(g^{i})) - 1) = 0$

3.  $t(g^{n-1}) = 2^{16} - 1$