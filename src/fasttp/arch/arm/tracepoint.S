.macro atomic_add rM, rT1, rT2, val
0:  ldrex \rT1, [\rM]
    add \rT1, \val
    strex \rT2, \rT1, [\rM]
    cmp \rT2, #0
    bne 0b
.endm

.macro function_size name
.global \name\()_size
.type \name\()_size, object
\name\()_size: .long .\name\()_end - \name
.endm

.section .text

.set PC_IDX, 0x3c

.global __point_tracepoint_handler
.type __point_tracepoint_handler, function
__point_tracepoint_handler:
    push {sp}
    mov r0, sp
    ldr r4, [r0, #PC_IDX]
    ldr r4, [r4]
    atomic_add r4, r1, r2, #1
    mov lr, pc
    ldr pc, .__point_tracepoint_handler_addr
    atomic_add r4, r1, r2, #-1
    add sp, #4
    pop {r0-r12, lr, pc}
.__point_tracepoint_handler_addr: .long point_tracepoint_handler
.size __point_tracepoint_handler, . - __point_tracepoint_handler
.__point_tracepoint_handler_end:


.global __ee_tracepoint_entry_handler
.type __ee_tracepoint_entry_handler, function
__ee_tracepoint_entry_handler:
    push {sp}
    mov r0, sp
    ldr r4, [r0, #PC_IDX]
    ldr r4, [r4, #8]
    atomic_add r4, r1, r2, #1
    mov lr, pc
    ldr pc, .__ee_tracepoint_entry_handler_addr
    add sp, #4
    pop {r0-r12, lr, pc}
.__ee_tracepoint_entry_handler_addr: .long ee_tracepoint_entry_handler
.size __ee_tracepoint_entry_handler, . - __ee_tracepoint_entry_handler
.__ee_tracepoint_entry_handler_end:

.global __ee_tracepoint_return_handler
.type __ee_tracepoint_return_handler, function
__ee_tracepoint_return_handler:
    push {sp}
    mov r0, sp
    ldr r4, [r0, #PC_IDX]
    ldr r4, [r4]
    mov lr, pc
    ldr pc, .__ee_tracepoint_return_handler_addr
    atomic_add r4, r1, r2, #-1
    add sp, #4
    pop {r0-r12, lr, pc}
.__ee_tracepoint_return_handler_addr: .long ee_tracepoint_return_handler
.size __ee_tracepoint_return_handler, . - __ee_tracepoint_return_handler
.__ee_tracepoint_return_handler_end:

test:
    ldr lr, [pc, r0]

.section .rodata
function_size __point_tracepoint_handler
function_size __ee_tracepoint_entry_handler
function_size __ee_tracepoint_return_handler