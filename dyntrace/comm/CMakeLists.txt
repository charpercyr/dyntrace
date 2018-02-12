
add_library(comm STATIC
    ../comm/local.hpp
    ../comm/message.hpp
    ../comm/process.hpp
    ../comm/server.hpp
)
set_target_properties(comm PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(comm PUBLIC boost_system proto)