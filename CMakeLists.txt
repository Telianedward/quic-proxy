cmake_minimum_required(VERSION 3.26)

# Устанавливаем политику для VERSION
if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()

# Устанавливаем версию проекта
if(NOT DEFINED APP_VERSION)
    set(APP_VERSION "0.1.0" CACHE STRING "Версия проекта")
endif()

# Проект
project(quic-proxy VERSION ${APP_VERSION} LANGUAGES CXX)

message(STATUS "🏗️ Собираем quic-proxy v${APP_VERSION}")
message(STATUS "🔍 Текущая директория: ${CMAKE_CURRENT_SOURCE_DIR}")

# Настройка стандарта C++
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Включаем оптимизацию
set(CMAKE_BUILD_TYPE Release)

# Добавляем флаги компиляции
add_compile_options(-O2 -Wall -Wextra -Wpedantic)

# Поиск библиотеки fmt
find_package(fmt CONFIG REQUIRED)

# === Источники ===
add_executable(quic_proxy
    main.cpp
    src/http2/tcp_proxy.cpp
    src/http3/quic_udp_proxy.cpp
    src/http3/client_key.cpp
    src/http3/quic_udp_deduplicator.cpp
)

# Поиск и использование OpenSSL
find_package(OpenSSL REQUIRED)

# Линковка: pthread и fmt
target_link_libraries(quic_proxy PRIVATE
    pthread
    fmt::fmt
    OpenSSL::SSL
    OpenSSL::Crypto
)