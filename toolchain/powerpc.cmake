
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ppc64le)

set(ARCH powerpc)
set(triple ppc64le-linux-gnu)
set(ARCH_INSTALL /usr/${triple})

set(CMAKE_C_COMPILER ${triple}-gcc)
set(CMAKE_CXX_COMPILER ${triple}-g++)
set(CMAKE_ASM_COMPILER ${triple}-gcc)