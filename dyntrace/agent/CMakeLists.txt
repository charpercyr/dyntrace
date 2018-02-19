add_library(agent SHARED
    main.cpp)
target_link_libraries(agent fasttp pthread boost_system stdc++fs)