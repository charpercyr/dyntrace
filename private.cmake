
define_property(TARGET PROPERTY OUTPUT BRIEF_DOCS "output name" FULL_DOCS "output name")

function(dyntrace_shared_library target)
    cmake_parse_arguments(ARG "NOSOVERSION" "DESTINATION" "" ${ARGN})
    if(NOT ARG_DESTINATION)
        set(ARG_DESTINATION lib)
    endif()
    add_library(${target} SHARED ${ARG_UNPARSED_ARGUMENTS})
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME dyntrace-${target}
    )
    if(NOT ARG_NOSOVERSION)
        set_target_properties(${target} PROPERTIES
            SOVERSION ${CMAKE_VERSION}
            OUTPUT ${CMAKE_INSTALL_PREFIX}/${ARG_DESTINATION}/libdyntrace-${target}.so.${CMAKE_VERSION}
        )
    else()
        set_target_properties(${target} PROPERTIES
            OUTPUT ${CMAKE_INSTALL_PREFIX}/${ARG_DESTINATION}/libdyntrace-${target}.so
        )
    endif()
    install(
        TARGETS ${target}
        LIBRARY DESTINATION ${ARG_DESTINATION}
    )
endfunction()

if(NOT ARCH_PROTOC)
    set(ARCH_PROTOC ${ARCH_INSTALL}/bin/protoc)
endif()

macro(dyntrace_protobuf_generate_cpp SRCS HDRS)
    foreach(file ${ARGN})
        get_filename_component(file_dir ${file} DIRECTORY)
        if(NOT file_dir)
            set(file_dir .)
        endif()
        get_filename_component(file_name ${file} NAME_WE)
        add_custom_command(
            OUTPUT ${file_name}.pb.cc
            COMMAND ${ARCH_PROTOC} -I${CMAKE_CURRENT_SOURCE_DIR}/${file_dir} --cpp_out=${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${file}
            DEPENDS ${file}
        )
        list(APPEND ${SRCS} ${CMAKE_CURRENT_BINARY_DIR}/${file_name}.pb.cc)
    endforeach()
    set(${HDRS} ${CMAKE_CURRENT_BINARY_DIR})
endmacro()

macro(dyntrace_protobuf_generate_python PY)
    foreach(file ${ARGN})
        get_filename_component(file_dir ${file} DIRECTORY)
        if(NOT file_dir)
            set(file_dir .)
        endif()
        get_filename_component(file_name ${file} NAME_WE)
        add_custom_command(
            OUTPUT ${file_name}_pb2.py
            COMMAND ${ARCH_PROTOC} -I${CMAKE_CURRENT_SOURCE_DIR}/${file_dir} --python_out=${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/${file}
            DEPENDS ${file}
        )
        list(APPEND ${PY} ${CMAKE_CURRENT_BINARY_DIR}/${file_name}_pb2.py)
    endforeach()
endmacro()