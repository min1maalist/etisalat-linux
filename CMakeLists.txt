cmake_minimum_required(VERSION 3.22)

project(dwi259s_kvm LANGUAGES CXX)

add_executable(dwi259s_kvm
    main.cpp
)

set_target_properties(dwi259s_kvm PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON)

target_link_libraries(dwi259s_kvm PRIVATE log)