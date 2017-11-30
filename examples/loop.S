
.global do_inc
.type do_inc, @function
do_inc:
    imul $2, 8(%rip), %rax
    add (%rdi), %rax
    mov %rax, (%rdi)
    ret
    .quad 0x6
.size do_inc, . - do_inc

