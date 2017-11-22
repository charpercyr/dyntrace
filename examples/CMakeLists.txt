
if(NOT DEFINED PATCHED_LLVM_ROOT)
    message(FATAL_ERROR "Please define PATCHED_LLVM_ROOT")
endif()

macro(add_traceable_executable name)
    add_custom_command(OUTPUT ${name}-build
        COMMAND
            make clean
            BIN_DIR=${CMAKE_CURRENT_BINARY_DIR}
            target=${name} ${name}-src=\"${ARGN}\"
        COMMAND
            make all
            BIN_DIR=${CMAKE_CURRENT_BINARY_DIR}
            PATCHED_LLVM_ROOT=${PATCHED_LLVM_ROOT}
            target=${name} ${name}-src=\"${ARGN}\"
            ${name}-ldflags=\"-L$<TARGET_FILE_DIR:loader> -Wl,-rpath $<TARGET_FILE_DIR:loader>\"
            ${name}-libs=-lloader
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        COMMAND_EXPAND_LISTS
    )
    add_custom_target(
        ${name} ALL
        SOURCES ${ARGN}
        DEPENDS loader ${name}-build
    )
endmacro()

add_traceable_executable(loop loop.c)