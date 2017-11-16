add_library(loader SHARED
    main.cpp)
target_link_libraries(loader fasttp pthread)