
.global do_inc
.type do_inc, @function
// This function will trap on every loop if there is a tracepoint at do_inc
do_inc:
    nopl 1(%eax, %eax, 1)
    xor %ecx, %ecx
    mov 4(%esp), %edi
.L0:
    xchg %ax, %ax
    incl (%edi)
    inc %ecx
    cmp $10, %ecx
    jne .L0
    ret
.size do_inc, . - do_inc