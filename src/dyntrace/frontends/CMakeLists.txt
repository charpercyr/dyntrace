
macro(dyntrace_add_client name module)
    set(client-file ${CMAKE_CURRENT_BINARY_DIR}/clients/${name})
    set(file ${module}.py)
    add_custom_command(
        OUTPUT ${client-file}
        COMMAND mkdir -p ${CMAKE_CURRENT_BINARY_DIR}/clients
        COMMAND rm -f ${client-file}
        COMMAND ln -s ${DYNTRACE_INSTALL_PREFIX}/lib/dyntrace/client/client.py ${client-file}
    )
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/clients/${name} DESTINATION bin)
    configure_file(${file} ${file})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${file} DESTINATION lib/dyntrace/client)
    list(APPEND DYNTRACE_CLIENTS ${name}@${module})
    list(APPEND client-deps ${client-file})
endmacro()

dyntrace_add_client(dyntrace cli)
dyntrace_add_client(dyntrace-run run)

add_custom_target(clients ALL DEPENDS ${client-deps})
configure_file(client.py client.py)
install(FILES ${PROTO_PY_SRCS} DESTINATION lib/dyntrace/client)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/client.py DESTINATION lib/dyntrace/client)
install(DIRECTORY dyntrace DESTINATION lib/dyntrace/client)