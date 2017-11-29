
.global do_inc
.type do_inc, @function
do_inc:
    imul $2, 5(%rip), %rax
    mov %rax, (%rdi)
    ret
    .quad 0x2
.size do_inc, . - do_inc

