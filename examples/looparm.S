
.global do_inc
.type do_inc, function
do_inc:
    ldr r5, [pc, #16]
    push {lr}
    ldr r4, [r0]
    add r4, r5
    str r4, [r0]
    pop {pc}
.word 10
.size do_inc, . - do_inc