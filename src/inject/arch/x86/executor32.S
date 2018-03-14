
////////////////////////////////////////////////
.section .text
.align 4
////////////////////////////////////////////////

/*
 * eax: Function to call
 * edi: Arg 0
 * esi: Arg 1
 * edx: Arg 2
 * ecx: Arg 3
 * ebx:  Arg 4
 * ebp:  Arg 5
 * rax: Return value
 */
.global __remote_execute32
.type __remote_execute32, @function
__remote_execute32:
    push $0
    push %ebp
    push %ebx
    push %ecx
    push %edx
    push %esi
    push %edi
    call *%eax
    int3
.__remote_execute32_end:
.size __remote_execute32, . - __remote_execute32

////////////////////////////////////////////////
.section .rodata
////////////////////////////////////////////////
.global __remote_execute32_size
.type __remote_execute32_size, @object
__remote_execute32_size: .quad .__remote_execute32_end - __remote_execute32
.size __remote_execute32_size, . - __remote_execute32_size