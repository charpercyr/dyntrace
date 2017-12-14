
.global do_inc
.type do_inc, @function
do_inc:
    nop
.L0:
    nopl (%eax, %eax, 1)
    jmp .L0
    ret
.size do_inc, . - do_inc

