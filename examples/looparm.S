
.global do_inc
.type do_inc, function
do_inc:
    push {lr}
    ldr r4, [r0]
    add r4, #10
    str r4, [r0]
    pop {pc}
.size do_inc, . - do_inc