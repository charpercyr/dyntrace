add_library(agent SHARED
    main.cpp)
target_link_libraries(agent PUBLIC
    boost_log
    comm
    fasttp
    pthread
    stdc++fs
)