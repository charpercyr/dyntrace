
install(FILES ${PROTO_PY_SRCS} DESTINATION lib/dyntrace/cli)
install(PROGRAMS dyntrace.py DESTINATION lib/dyntrace/cli)
install(CODE "EXECUTE_PROCESS(COMMAND mkdir -p ${CMAKE_INSTALL_PREFIX}/bin)")
install(CODE "EXECUTE_PROCESS(COMMAND rm -f ${CMAKE_INSTALL_PREFIX}/bin/dyntrace)")
install(CODE "EXECUTE_PROCESS(COMMAND ln -s ${CMAKE_INSTALL_PREFIX}/lib/dyntrace/cli/dyntrace.py ${CMAKE_INSTALL_PREFIX}/bin/dyntrace)")