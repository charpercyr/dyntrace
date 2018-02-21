
add_library(util STATIC
    path.cpp
    util.cpp)
set_target_properties(util PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)