## Arithmetic

Each row of the arithmetic table corresponds to a binary or ternary
arithmetic operation. Each of these operations has an associated flag
$f_{op}$ in the table, such that $f_{\texttt{op}} = 1$ whenever the
operation is $\texttt{op}$ and 0 otherwise. The full list of operations
carried out by the table is as follows:

#### Binary operations: {#binary-operations .unnumbered}

-   basic operations: "add", "mul", "sub" and "div",

-   comparisons: "lt" and "gt",

-   shifts: "shr" and "shl",

-   "byte": given $x_1, x_2$, returns the $x_1$-th "byte" in $x_2$,

-   modular operations: "mod", "AddFp254", "MulFp254" and "SubFp254",

-   range-check: no operation is performed, as this is only used to
    range-check the input and output limbs in the range
    \[$0, 2^{16} - 1$\].

For 'mod', the second input is the modulus. "AddFp254", "MulFp254" and
"SubFp254" are modular operations modulo "Fp254'' -- the prime for the
BN curve's base field.

#### Ternary operations: {#ternary-operations .unnumbered}

There are three ternary operations: modular addition "AddMod", modular
multiplication "MulMod" and modular subtraction "SubMod".

Besides the flags, the arithmetic table needs to store the inputs,
output and some auxiliary values necessary to constraints. The input and
output values are range-checked to ensure their canonical
representation. Inputs are 256-bits words. To avoid having too large a
range-check, inputs are therefore split into sixteen 16-bits limbs, and
range-checked in the range $[0, 2^{16}-1]$.

Overall, the table comprises the following columns:

-   17 columns for the operation flags $f_{op}$,

-   1 column $op$ containing the opcode,

-   16 columns for the 16-bit limbs $x_{0, i}$ of the first input
    $x_{0}$,

-   16 columns for the 16-bit limbs $x_{1, i}$ of the second input
    $x_{1}$,

-   16 columns for the 16-bit limbs $x_{2, i}$ of the third input
    $x_{2}$,

-   16 columns for the 16-bit limbs $r_i$ of the output $r$,

-   32 columns for auxiliary values $\texttt{aux}_i$,

-   1 column $\texttt{range\_counter}$ containing values in the range
    \[$0, 2^{16}-1$\], for the range-check,

-   1 column storing the frequency of appearance of each value in the
    range $[0, 2^{16} - 1]$.

#### Note on $op$:

The opcode column is only used for range-checks. For optimization
purposes, we check all arithmetic operations against the cpu table
together. To ensure correctness, we also check that the operation's
opcode corresponds to its behavior. But range-check is not associated to
a unique operation: any operation in the cpu table might require its
values to be checked. Thus, the arithmetic table cannot know its opcode
in advance: it needs to store the value provided by the cpu table.

### Auxiliary columns

The way auxiliary values are leveraged to efficiently check correctness
is not trivial, but it is explained in detail in each dedicated file.
Overall, five files explain the implementations of the various checks.
Refer to:

1.  "mul.rs" for details on multiplications.

2.  "addcy.rs" for details on addition, subtraction, "lt" and "gt".

3.  "modular.rs" for details on how modular operations are checked. Note
    that even though "div" and "mod" are generated and checked in a
    separate file, they leverage the logic for modular operations
    described in "modular.rs".

4.  "byte" for details on how "byte" is checked.

5.  "shift.rs" for details on how shifts are checked.

#### Note on "lt" and "gt": {#note-on-lt-and-gt .unnumbered}

For "lt" and "gt", auxiliary columns hold the difference $d$ between the
two inputs $x_1, x_2$. We can then treat them similarly to subtractions
by ensuring that $x_1 - x_2 = d$ for "lt" and $x_2 - x_1 = d$ for "gt".
An auxiliary column $cy$ is used for the carry in additions and
subtractions. In the comparisons case, it holds the overflow flag.
Contrary to subtractions, the output of "lt" and "gt" operations is not
$d$ but $cy$.

#### Note on "div": {#note-on-div .unnumbered}

It might be unclear why "div" and "mod" are dealt with in the same file.

Given numerator and denominator $n, d$, we compute, like for other
modular operations, the quotient $q$ and remainder $\texttt{rem}$:
$$div(x_1, x_2) = q * x_2 + \texttt{rem}$$. We then set the associated
auxiliary columns to $\texttt{rem}$ and the output to $q$.

This is why "div" is essentially a modulo operation, and can be
addressed in almost the same way as "mod". The only difference is that
in the "mod" case, the output is $\texttt{rem}$ and the auxiliary value
is $q$.

#### Note on shifts:

"shr" and "shl" are internally constrained as "div" and "mul"
respectively with shifted operands. Indeed, given inputs $s, x$, the
output should be $x >> s$ for "shr" (resp. $x << s$ for "shl"). Since
shifts are binary operations, we can use the third input columns to
store $s_{\texttt{shifted}} = 1 << s$. Then, we can use the "div" logic
(resp. "mul" logic) to ensure that the output is
$\frac{x}{s_{\texttt{shifted}}}$ (resp. $x * s_{\texttt{shifted}}$).