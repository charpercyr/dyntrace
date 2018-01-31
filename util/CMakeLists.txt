
add_library(util STATIC
    barrier.hpp
        ../fasttp/arch/x86_64/buffer_writer.hpp
    error.hpp
    flag.hpp
    integer_range.hpp
    locked.hpp
    path.hpp path.cpp
    safe_queue.hpp
    util.cpp util.hpp)