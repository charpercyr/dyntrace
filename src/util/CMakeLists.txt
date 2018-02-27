
add_library(util STATIC
    path.cpp)
set_target_properties(util PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)