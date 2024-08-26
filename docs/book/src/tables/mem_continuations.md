## MemBefore & MemAfter {#mem-continuations}

The MemBefore (resp. MemAfter) table holds the content of the memory
before (resp. after) the execution of the current segment. For
consistency, the MemAfter trace of a segment must be identical to the
MemAfter trace of the next segment. Each row of these tables contains:

1.  $a$, the memory cell address,

2.  $v$, the initial value of the cell.

The tables should be ordered by $(a, \tau)$. Since they only hold
values, there are no constraints between the rows.

A CTL copies all of the MemBefore values in the memory trace as reads,
at timestamp $\tau = 0$. Another CTL copies the final values from memory
to MemAfter. For more details on which values are propagated, consult
[3.5.4](#final-memory){reference-type="ref" reference="final-memory"}.