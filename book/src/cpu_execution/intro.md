# CPU Execution {#cpulogic}

The CPU is in charge of coordinating the different STARKs, proving the
correct execution of the instructions it reads and guaranteeing that the
final state of the EVM corresponds to the starting state after executing
the input transactions. All design choices were made to make sure these
properties can be adequately translated into constraints of degree at
most 3 while minimizing the size of the different table traces (number
of columns and number of rows).

In this section, we will detail some of these choices.