// Its missing ebp and return since it is saved in the generated machine-code (see tracepoint.cpp)
.macro save_state
    push %esp
    pushf
    push %ebx
    push %ecx
    push %edx
    push %esi
    push %edi
    push %eax
.endm

.macro restore_state
    pop %eax
    pop %edi
    pop %esi
    pop %edx
    pop %ecx
    pop %ebx
    popf
    pop %esp
.endm

.macro enter_handler name, handler, disp=0
.global \name
.type \name, @function
\name\():
    save_state
    mov 0x20(%esp), %ebp
    mov \disp(%ebp), %ebp
    lock incl (%ebp)
    push %esp
    call \handler\()
    lea 4(%esp), %esp
    restore_state
    ret
.\name\()_end:
.size \name, . - \name
.endm

.macro symbol_size symbol
.global \symbol\()_size
.type \symbol\()_size, @object
\symbol\()_size: .long .\symbol\()_end - \symbol
.size \symbol\()_size, . - \symbol\()_size
.endm

/////////////////////////////////////////////////////////////////////
.section .text
/////////////////////////////////////////////////////////////////////

enter_handler __tracepoint_handler, tracepoint_handler
enter_handler __tracepoint_return_enter_handler, tracepoint_return_enter_handler, 0xc

.global __tracepoint_return_exit_handler
.type __tracepoint_return_exit_handler, @function
__tracepoint_return_exit_handler:
    save_state
    mov 0x20 (%esp), %ebp
    mov (%ebp), %ebp
    push %esp
    call tracepoint_return_exit_handler
    lea 4(%esp), %esp
    lock decl (%ebp)
    restore_state
    lea 4(%esp), %esp
    pop %ebp
    ret
.__tracepoint_return_exit_handler_end:
.size __tracepoint_return_exit_handler, . - __tracepoint_return_exit_handler

/////////////////////////////////////////////////////////////////////
.section .rodata
/////////////////////////////////////////////////////////////////////
symbol_size __tracepoint_handler
symbol_size __tracepoint_return_enter_handler
symbol_size __tracepoint_return_exit_handler