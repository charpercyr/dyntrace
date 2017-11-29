
.global do_inc
.type do_inc, @function
do_inc:
    mov -5(%rip), %rax
    mov (%rdi), %rax
    inc %rax
    mov %rax, (%rdi)
    ret
.size do_inc, . - do_inc

