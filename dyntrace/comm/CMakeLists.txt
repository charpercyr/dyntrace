
add_library(comm STATIC
    local.hpp
    message.hpp
    process.cpp process.hpp
    server.hpp
)
target_link_libraries(comm PUBLIC boost_system)