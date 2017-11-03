
add_library(loader MODULE
        main.cpp)
target_link_libraries(loader process pthread)