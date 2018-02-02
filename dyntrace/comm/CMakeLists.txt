
add_library(
    comm STATIC
    handler.hpp
    local.hpp
    server.hpp
)
set_target_properties(comm PROPERTIES LINKER_LANGUAGE CXX)
target_link_libraries(comm PUBLIC boost_system)