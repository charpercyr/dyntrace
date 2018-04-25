
.section .text

.global __remote_execute
.type __remote_execute, function
__remote_execute:
    push {r4, r5}
    mov lr, pc
    mov pc, r6
    bkpt
__remote_execute_end:
.size __remote_execute, . - __remote_execute

.section .rodata

.global __remote_execute_size
.type __remote_execute_size, object
__remote_execute_size: .long __remote_execute_end - __remote_execute
.size __remote_execute_size, . - __remote_execute_size