cmake_minimum_required(VERSION 3.22)
project(socks5)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
link_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib)

# nlohmann_json
set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(third_party/json)

set(SOURCE_FILE
        SocksServer.cpp
        EncodeServer.cpp
        base/MD5Encode.cpp
        base/SocksResponse.cpp
        base/ValidateUtils.cpp
        base/SocksUtils.cpp
)
set(LINK_LIST
        muduo_cdns
        cares muduo_net 
        muduo_base 
        pthread
        nlohmann_json::nlohmann_json
)

add_executable(socks5 
        main.cpp
        ${SOURCE_FILE}
)
target_link_libraries(socks5 
        ${LINK_LIST}
)
