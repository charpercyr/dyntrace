
macro(dyntrace_add_client name module)
    set(file ${module}.py)
    install(CODE "EXECUTE_PROCESS(COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/bin)")
    install(CODE "EXECUTE_PROCESS(COMMAND rm -f ${CMAKE_INSTALL_PREFIX}/bin/${name})")
    install(CODE "EXECUTE_PROCESS(COMMAND ln -s ${CMAKE_INSTALL_PREFIX}/lib/dyntrace/client/client.py ${CMAKE_INSTALL_PREFIX}/bin/${name})")
    configure_file(${file} ${file})
    install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${file} DESTINATION lib/dyntrace/client)
    install(CODE "MESSAGE(\"-- Adding dyntrace client: dyntrace client ${CMAKE_INSTALL_PREFIX}/bin/${name} -> ${CMAKE_INSTALL_PREFIX}/lib/dyntrace/client/client.py\")")
    list(APPEND DYNTRACE_CLIENTS ${name}@${module})
endmacro()

dyntrace_add_client(dyntrace cli)
dyntrace_add_client(dyntrace-run run)

configure_file(client.py client.py)
install(FILES ${PROTO_PY_SRCS} DESTINATION lib/dyntrace/client)
install(PROGRAMS ${CMAKE_CURRENT_BINARY_DIR}/client.py DESTINATION lib/dyntrace/client)
install(DIRECTORY dyntrace DESTINATION lib/dyntrace/client)