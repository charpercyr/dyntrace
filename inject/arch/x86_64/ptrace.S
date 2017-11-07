
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
.section .rodata
//////////////////////////////////////////////////////

.global do_remote_call_64_size
.type do_remote_call_64_size, @object
do_remote_call_64_size: .quad do_remote_call_64_end - do_remote_call_64
.size do_remote_call_64_size, . - do_remote_call_64_size