
.section .text

.global do_remote_call
.type do_remote_call, @function
do_remote_call:
    call *%rax
    int $3
do_remote_call_end:
.size do_remote_call, do_remote_call_end - do_remote_call

.section .rodata
.global do_remote_call_size
.type do_remote_call_size, @object
do_remote_call_size: .quad do_remote_call_end - do_remote_call
.size do_remote_call_size, . - do_remote_call_size