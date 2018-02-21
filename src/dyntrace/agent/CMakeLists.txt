
dyntrace_shared_library(agent main.cpp)
target_link_libraries(agent
    boost_log
    boost_system
    config
    fasttp
    proto
)