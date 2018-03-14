
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
// Align stack to 16-byte (sysv abi)
#    mov %rsp, %r10
#    and $15, %r10
#    jnz .no_align
#    push $0
#.no_align:
    push %rbp
    call *%rax
    int3
.__remote_execute64_end:
.size __remote_execute64, . - __remote_execute64

/*
 * The registers seem to not be the right ones.
 * But when copied to a 32 bit process, it will do the right thing (since the opcodes are the same).
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
    push %rbp
    push %rbx
    push %rcx
    push %rdx
    push %rsi
    push %rdi
    call *%rax
    int3
.__remote_execute32_end:
.size __remote_execute32, . - __remote_execute32

////////////////////////////////////////////////
.section .rodata
////////////////////////////////////////////////
.global __remote_execute64_size
.type __remote_execute64_size, @object
__remote_execute64_size: .quad .__remote_execute64_end - __remote_execute64
.size __remote_execute64_size, . - __remote_execute64_size

.global __remote_execute32_size
.type __remote_execute32_size, @object
__remote_execute32_size: .quad .__remote_execute32_end - __remote_execute32
.size __remote_execute32_size, . - __remote_execute32_size