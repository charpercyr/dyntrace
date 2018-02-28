
function(dyntrace_add_client name)
    install(CODE "EXECUTE_PROCESS(COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/bin)")
    install(CODE "EXECUTE_PROCESS(COMMAND rm -f ${CMAKE_INSTALL_PREFIX}/bin/${name})")
    install(CODE "EXECUTE_PROCESS(COMMAND ln -s ${CMAKE_INSTALL_PREFIX}/lib/dyntrace/client/client.py ${CMAKE_INSTALL_PREFIX}/bin/${name})")
endfunction()

install(FILES ${PROTO_PY_SRCS} DESTINATION lib/dyntrace/client)
configure_file(cli.py cli.py)
install(PROGRAMS client.py DESTINATION lib/dyntrace/client)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/cli.py DESTINATION lib/dyntrace/client)
install(DIRECTORY dyntrace DESTINATION lib/dyntrace/client)

dyntrace_add_client(dyntrace)