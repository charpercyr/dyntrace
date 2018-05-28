
#define R(r) r
#define SP R(1)
#define IDX(idx) (idx)*__SIZEOF_POINTER__
#define PTR(base, idx) IDX(idx)(base)
#define STACK(idx) PTR(SP, idx)

#if __SIZEOF_POINTER__ == 4
#define SIZE_T .long
#define ST stw
#define LD lwz
#else
#define SIZE_T .quad
#define ST std
#define LD ld
#endif

.macro atomic_add r, m, v
0:
    lwarx \r, 0, \m
    addi \r, \r, \v
    stwcx. \r, 0, \m
    bne- 0b
.endm

.macro save_state st
    ST R(0), STACK(\st)
    ST R(1), STACK(\st+1)
    ST R(2), STACK(\st+2)
    ST R(3), STACK(\st+3)
    ST R(4), STACK(\st+4)
    ST R(5), STACK(\st+5)
    ST R(6), STACK(\st+6)
    ST R(7), STACK(\st+7)
    ST R(8), STACK(\st+8)
    ST R(9), STACK(\st+9)
    ST R(10), STACK(\st+10)
    ST R(11), STACK(\st+11)
    ST R(12), STACK(\st+12)
    ST R(13), STACK(\st+13)
    ST R(14), STACK(\st+14)
    ST R(15), STACK(\st+15)
    ST R(16), STACK(\st+16)
    ST R(17), STACK(\st+17)
    ST R(18), STACK(\st+18)
    ST R(19), STACK(\st+19)
    ST R(20), STACK(\st+20)
    ST R(21), STACK(\st+21)
    ST R(22), STACK(\st+22)
    ST R(23), STACK(\st+23)
    ST R(24), STACK(\st+24)
    ST R(25), STACK(\st+25)
    ST R(26), STACK(\st+26)
    ST R(27), STACK(\st+27)
    ST R(28), STACK(\st+28)
    ST R(29), STACK(\st+29)
    ST R(30), STACK(\st+30)
    ST R(31), STACK(\st+31)
.endm

.macro restore_state st
    LD R(0), STACK(\st-1)
    LD R(1), STACK(\st+1)
    LD R(2), STACK(\st+2)
    LD R(3), STACK(\st+3)
    LD R(4), STACK(\st+4)
    LD R(5), STACK(\st+5)
    LD R(6), STACK(\st+6)
    LD R(7), STACK(\st+7)
    LD R(8), STACK(\st+8)
    LD R(9), STACK(\st+9)
    LD R(10), STACK(\st+10)
    LD R(11), STACK(\st+11)
    LD R(12), STACK(\st+12)
    LD R(13), STACK(\st+13)
    LD R(14), STACK(\st+14)
    LD R(15), STACK(\st+15)
    LD R(16), STACK(\st+16)
    LD R(17), STACK(\st+17)
    LD R(18), STACK(\st+18)
    LD R(19), STACK(\st+19)
    LD R(20), STACK(\st+20)
    LD R(21), STACK(\st+21)
    LD R(22), STACK(\st+22)
    LD R(23), STACK(\st+23)
    LD R(24), STACK(\st+24)
    LD R(25), STACK(\st+25)
    LD R(26), STACK(\st+26)
    LD R(27), STACK(\st+27)
    LD R(28), STACK(\st+28)
    LD R(29), STACK(\st+29)
    LD R(30), STACK(\st+30)
    LD R(31), STACK(\st+31)
.endm

/////////////////////////////////////////////////////
.section .text
/////////////////////////////////////////////////////

.global __point_tracepoint_handler
.type __point_tracepoint_handler, @function
__point_tracepoint_handler:
    save_state -34
    mfcr R(3)
    ST R(3), STACK(-35)
    mfctr R(3)
    ST R(3), STACK(-36)
    LD R(3), STACK(0)
    LD R(4), STACK(1)
    LD R(5), STACK(2)
    LD R(6), STACK(3)
    LD R(7), STACK(4)
    LD R(8), STACK(5)
    subi SP, SP, IDX(42)
    ST R(3), STACK(0)
    ST R(4), STACK(1)
    ST R(5), STACK(2)
    ST R(6), STACK(3)
    ST R(7), STACK(4)
    ST R(8), STACK(5)
    mflr R(14)
    LD R(3), 0(R(14))
    atomic_add R(4), R(3), 1
    mr R(4), SP
    bl 4
    mflr R(2)
    LD R(2), (.TOC_BASE - . + 4)(R(2))
    bl point_tracepoint_handler
    nop
    atomic_add R(4), R(14), -1
    addi SP, SP, IDX(42)
    LD R(3), STACK(-36)
    mtctr R(3)
    LD R(3), STACK(-35)
    mtcr R(3)
    addi R(14), R(14), IDX(3)
    mtlr R(14)
    restore_state -34
    blr
.TOC_BASE: SIZE_T .TOC.@tocbase
.size __point_tracepoint_handler, . - __point_tracepoint_handler

/////////////////////////////////////////////////////
.section .rodata
/////////////////////////////////////////////////////

.global __point_tracepoint_enter_code
.type __point_tracepoint_enter_code, @object
__point_tracepoint_enter_code:
    ST R(31), STACK(-1)
    mflr R(31)
    ST R(31), STACK(-2)
    bl 4
    mflr R(31)
    LD R(31), (16 + IDX(1))(R(31))
    mtlr R(31)
    blrl

.size __point_tracepoint_enter_code, . - __point_tracepoint_enter_code
.global __point_tracepoint_enter_code_size
.type __point_tracepoint_enter_code_size, @object
__point_tracepoint_enter_code_size: SIZE_T . - __point_tracepoint_enter_code
.size __point_tracepoint_enter_code_size, . - __point_tracepoint_enter_code_size

__data:
    SIZE_T 0 // Tracepoint data
    SIZE_T 0 // Handler address
    SIZE_T 0 // Return address

.global __point_tracepoint_exit_code
.type __point_tracepoint_exit_code, @object
__point_tracepoint_exit_code:
    bl 4
    mflr R(31)
    LD R(31), (-16 - IDX(1))(R(31))
    mtctr R(31)
    LD R(31), STACK(-2)
    mtlr R(31)
    LD R(31), STACK(-1)
    bctr
.size __point_tracepoint_exit_code, . - __point_tracepoint_exit_code
.global __point_tracepoint_exit_code_size
.type __point_tracepoint_exit_code_size, @object
__point_tracepoint_exit_code_size: SIZE_T . - __point_tracepoint_exit_code
.size __point_tracepoint_exit_code_size, . - __point_tracepoint_exit_code_size