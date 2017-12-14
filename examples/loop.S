
.global do_inc
.type do_inc, @function
do_inc:
    mov $10, %rcx
    nop
.L0:
    nopl (%eax, %eax, 1)
    loop .L0
    ret
.size do_inc, . - do_inc

