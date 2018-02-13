
foreach(f ${PROTO_FILES})
    get_filename_component(f ${f} NAME_WE)
    add_custom_command(
        OUTPUT ${f}_pb2.py
        COMMAND protoc --python_out=${CMAKE_CURRENT_SOURCE_DIR} --proto_path=${PROTO_DIR} ${f}.proto
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        DEPENDS ${PROTO_DIR}/${f}.proto
    )
    list(APPEND proto_list ${f}_pb2.py)
endforeach()
add_custom_target(
    proto_py ALL
    DEPENDS ${proto_list}
)