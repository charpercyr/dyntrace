
.global do_safe_write8
.type do_safe_write8, @function
do_safe_write8:
    lock xchgq (%rdi), %rsi
    ret
.size do_safe_write8, . - do_safe_write8