
if(NOT DEFINED PATCHED_LLVM_ROOT)
    message(FATAL_ERROR "Please define PATCHED_LLVM_ROOT")
endif()

function(add_traceable_executable name)
    set(lang C)
    foreach(src ${ARGN})
        if(${src} MATCHES ".*\\.S")
            list(APPEND objs ${src})
        else()
            if(${src} MATCHES ".*\\.cpp")
                set(lang CXX)
            endif()
            add_custom_command(
                OUTPUT ${src}.bc
                COMMAND clang -g -c -emit-llvm ${cflags} ${CMAKE_CURRENT_SOURCE_DIR}/${src} -o ${CMAKE_CURRENT_BINARY_DIR}/${src}.bc
                DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/${src}
            )
            add_custom_command(
                OUTPUT ${src}.o
                COMMAND ${PATCHED_LLVM_ROOT}/bin/llc
                    -filetype=obj -relocation-model=pic -dwarf-add-basic-block-info
                    ${CMAKE_CURRENT_BINARY_DIR}/${src}.bc
                    -o ${CMAKE_CURRENT_BINARY_DIR}/${src}.o
                DEPENDS ${src}.bc
            )
            list(APPEND objs ${CMAKE_CURRENT_BINARY_DIR}/${src}.o)
        endif()
    endforeach()
    add_executable(${name} ${objs})
    set_target_properties(${name} PROPERTIES LINKER_LANGUAGE ${lang})
endfunction()

add_traceable_executable(loop loop.c loop.S)
target_link_libraries(loop loader)

pkg_check_modules(BENCHMARK benchmark)

add_executable(bm_tracepoint bm_tracepoint.cpp)
target_include_directories(bm_tracepoint PRIVATE ${BENCHMARK_INCLUDE_DIRS})
target_link_libraries(bm_tracepoint ${BENCHMARK_LIBRARIES} fasttp pthread)