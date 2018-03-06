
////////////////////////////////////////////////
.section .text
.align 8
////////////////////////////////////////////////

/*
 * rax: Function to call
 * rdi: Arg 0
 * rsi: Arg 1
 * rdx: Arg 2
 * rcx: Arg 3
 * r8:  Arg 4
 * r9:  Arg 5
 * rax: Return value
 */
.global __remote_execute64
.type __remote_execute64, @function
__remote_execute64:
    call *%rax
    int3
.__remote_execute64_end:
.size __remote_execute64, . - __remote_execute64

////////////////////////////////////////////////
.section .rodata
////////////////////////////////////////////////
.global __remote_execute64_size
.type __remote_execute64_size, @object
__remote_execute64_size: .quad .__remote_execute64_end - __remote_execute64
.size __remote_execute64_size, . - __remote_execute64_size