cmake_minimum_required(VERSION 3.21)

# Get current path
set(path ${CMAKE_CURRENT_SOURCE_DIR})
# Put directory name to COMPONENT_NAME variable
cmake_path(GET path FILENAME COMPONENT_NAME)
# Set component name
project(${COMPONENT_NAME})

# Source files
FILE(
    GLOB_RECURSE
    SOURCE_LIB 
    "*.cpp"
    "*.c"
    )


# Add includes
include_directories(
    "Inc"
)

# Creating static library
add_library(${COMPONENT_NAME} STATIC ${SOURCE_LIB})


Depends_On("mbedTLS")

# Пример подключения библиотек
# Для Windows
if (WIN32)
    # Подключение библиотек
    target_link_libraries(${PROJECT_NAME} ws2_32)
    target_link_libraries(${PROJECT_NAME} wsock32)
    target_link_libraries(${PROJECT_NAME} pthread)
endif ()

# Для Linux
if (UNIX)
    target_link_libraries(${PROJECT_NAME} pthread)
endif ()
