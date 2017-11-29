
.global do_inc
.type do_inc, @function
do_inc:
    mov (%rdi), %rax
    inc %rax
    mov %rax, (%rdi)
    ret
.size do_inc, . - do_inc

