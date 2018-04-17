
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)

set(ARCH arm)
set(triple ${ARCH}-linux-gnueabihf)
set(ARCH_INSTALL /usr/${triple})

set(CMAKE_C_COMPILER ${triple}-gcc)
set(CMAKE_CXX_COMPILER ${triple}-g++)
set(CMAKE_ASM_COMPILER ${triple}-gcc)