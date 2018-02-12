
foreach(f ${PROTO_FILES})
    get_filename_component(tmp ${f} NAME)
    list(APPEND files ${f})
endforeach()
execute_process(
    COMMAND
        protoc --python_out=${CMAKE_CURRENT_SOURCE_DIR} ${files} --proto_path=${PROTO_DIR}
)