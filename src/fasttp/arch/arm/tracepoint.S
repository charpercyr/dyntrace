.macro atomic_add rM, rT1, rT2, val
0:  ldrex \rT1, [\rM]
    add \rT1, \val
    strex \rT2, \rT1, [\rM]
    cmp \rT2, #0
    bne 0b
.endm

.section .text

.set PC_OFFSET, 0x3c
.global __point_tracepoint_handler
.type __point_tracepoint_handler, function
__point_tracepoint_handler:
    push {sp}
    mov r0, sp
    ldr r4, [r0, #PC_OFFSET]
    ldr r4, [r4]
    atomic_add r4, r1, r2, #1
    mov lr, pc
    ldr pc, .point_tracepoint_handler_addr
    atomic_add r4, r1, r2, #-1
    add sp, #4
    pop {r0-r12, lr, pc}
.point_tracepoint_handler_addr:
    .long point_tracepoint_handler
.size __point_tracepoint_handler, . - __point_tracepoint_handler
.__point_tracepoint_handler_end:

.section .rodata
.global __point_tracepoint_handler_size
.type __point_tracepoint_handler_size, object
__point_tracepoint_handler_size: .long .__point_tracepoint_handler_end - __point_tracepoint_handler