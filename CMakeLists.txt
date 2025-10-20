cmake_minimum_required(VERSION 3.26)

# Устанавливаем политику для VERSION
if(POLICY CMP0048)
    cmake_policy(SET CMP0048 NEW)
endif()

# Устанавливаем версию проекта
if(NOT DEFINED APP_VERSION)
    set(APP_VERSION "dev" CACHE STRING "Версия проекта")
endif()

# Проект
project(quic-proxy VERSION ${APP_VERSION} LANGUAGES CXX)

message(STATUS "🏗️ Собираем quic-proxy v${APP_VERSION}")
message(STATUS "🔍 Текущая директория: ${CMAKE_CURRENT_SOURCE_DIR}")

# Настройка стандарта C++
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Включаем оптимизацию и отладку
set(CMAKE_BUILD_TYPE Release) # Или Debug, если нужно

# Добавляем флаги компиляции
add_compile_options(-O2 -Wall -Wextra -Wpedantic)

# Источники
add_executable(quic_proxy quic_udp_proxy.cpp)

# Линковка: pthread
target_link_libraries(quic_proxy PRIVATE pthread)

# Установка исполняемого файла в /opt/quic-proxy/
install(TARGETS quic_proxy
        RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}
        PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_EXECUTE GROUP_READ WORLD_EXECUTE WORLD_READ)

# Установка systemd-сервиса
install(FILES quic-proxy.service
        DESTINATION /etc/systemd/system
        PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

# Цель для перезагрузки systemd
add_custom_target(reload-systemd
    COMMAND systemctl daemon-reload
    COMMENT "🔄 Перезагружаем systemd..."
)

# Цель для включения и запуска сервиса
add_custom_target(enable-and-start-service
    COMMAND systemctl enable quic-proxy.service
    COMMAND systemctl start quic-proxy.service
    COMMENT "🚀 Включаем и запускаем сервис quic-proxy..."
)

# Цель для просмотра логов
add_custom_target(journalctl
    COMMAND journalctl -u quic-proxy.service -f
    COMMENT "📝 Показываем логи службы quic-proxy (Ctrl+C для выхода)..."
)

# Цель для полной установки и запуска
add_custom_target(install-and-run ALL
    DEPENDS quic_proxy
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_INSTALL_PREFIX}
    COMMAND ${CMAKE_COMMAND} --build . --target install
    COMMAND ${CMAKE_COMMAND} --build . --target reload-systemd
    COMMAND ${CMAKE_COMMAND} --build . --target enable-and-start-service
    COMMAND ${CMAKE_COMMAND} --build . --target journalctl
    COMMENT "✅ Полная установка и запуск quic-proxy завершены."
)