
.code64

//////////////////////////////////////////////////////
.section .text
//////////////////////////////////////////////////////

.global do_remote_call_64
.type do_remote_call_64, @function
do_remote_call_64:
    pushq %r11
    pushq %r10
    callq *%rax
    int $3
do_remote_call_64_end:
.size do_remote_call_64, do_remote_call_64_end - do_remote_call_64

//////////////////////////////////////////////////////
/// void* do_dlopen_64(dlopen_args* args);
/// rdi: struct dlopen_args
/// 0(%rdi): dlopen_ptr sizeof=8, alignof=8
/// 8(%rdi): name sizeof=8, alignof=8
/// 16(%rdi): flags sizeof=4, alignof=8
/// 24(%rdi): return value sizeof=8, alignof=8
//////////////////////////////////////////////////////
.global do_dlopen_64
.type do_dlopen_64, @function
do_dlopen_64:
    push %rbx
    mov %rdi, %rbx
    movq 0(%rbx), %rax
    movq 8(%rbx), %rdi
    xor %rsi, %rsi
    movl 16(%rbx), %esi
    call *%rax
    movq %rax, 24(%rbx)
    pop %rbx
    xor %rax, %rax
    ret
do_dlopen_64_end:
.size do_dlopen_64, do_dlopen_64_end - do_dlopen_64

//////////////////////////////////////////////////////
/// void* do_dlclose_64(dlclose_args* args);
/// rdi: struct dlclose_args
/// 0(%rdi): dlclose_ptr sizeof=8, alignof=8
/// 8(%rdi): ptr sizeof=8, alignof=8
//////////////////////////////////////////////////////
.global do_dlclose_64
.type do_dlclose_64, @function
do_dlclose_64:
    mov 0(%rdi), %rax
    mov 8(%rdi), %rdi
    call *%rax
    xor %rax, %rax
    ret
do_dlclose_64_end:
.size do_dlclose_64, do_dlclose_64_end - do_dlclose_64

//////////////////////////////////////////////////////
.section .rodata
//////////////////////////////////////////////////////

.global do_remote_call_64_size
.type do_remote_call_64_size, @object
do_remote_call_64_size: .quad do_remote_call_64_end - do_remote_call_64
.size do_remote_call_64_size, . - do_remote_call_64_size

.global do_dlopen_64_size
.type do_dlopen_64_size, @object
do_dlopen_64_size: .quad do_dlopen_64_end - do_dlopen_64
.size do_dlopen_64_size, . - do_dlopen_64_size

.global do_dlclose_64_size
.type do_dlclose_64_size, @object
do_dlclose_64_size: .quad do_dlclose_64_end - do_dlclose_64
.size do_dlclose_64_size, . - do_dlclose_64_size