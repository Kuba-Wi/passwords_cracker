cmake_minimum_required(VERSION 3.10)

project(password_cracker)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(FILES
    main.c
    passwords_dict_holder.c
    passwords_cracker.c
)

set(COMPILE_FLAGS -Wall -pedantic -Wextra)

add_executable(${PROJECT_NAME} ${FILES})
target_link_libraries(${PROJECT_NAME} pthread crypto)
target_compile_options(${PROJECT_NAME} PRIVATE ${COMPILE_FLAGS})
