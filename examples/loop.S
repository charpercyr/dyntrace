
.global do_inc
.type do_inc, @function
// This function will trap on every loop if there is a tracepoint at do_inc
do_inc:
    xor %rcx, %rcx
.L0:
    xchg %ax, %ax
    incq (%rdi)
    inc %rcx
    cmp $10, %rcx
    jne .L0
    ret
.size do_inc, . - do_inc

