
.global safe_write8
.type safe_write8, @function
safe_write8:
    lock xchg (%rdi), %rsi
    ret
.size safe_write8, . - safe_write8