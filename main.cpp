// main.cpp
/**
 * @file main.cpp
 * @brief Точка входа в приложение — запуск HTTP/3 и HTTP/2 прокси-серверов.
 *
 * Создаёт экземпляры серверов и запускает их в отдельных потоках.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-22
 * @version 1.0
 * @license MIT
 */

#include "include/http3/http3_proxy.hpp"
#include "include/http2/http2_proxy.hpp"
#include "server/logger.h"
#include <thread>
#include <iostream>
#include <string>
#include <stdexcept>
#include <csignal>

volatile sig_atomic_t running = true;

void signal_handler(int sig) {
    LOG_INFO("[INFO] Получен сигнал {}. Остановка...", sig);
    running = false;
}

int main() {
    try {
        // 👇 Инициализируем логгер ДО создания серверов
        // Логгер уже инициализирован в logger.h

        // 👇 Инициализируем quiche-логирование ТОЛЬКО ПОСЛЕ инициализации логгера
        static bool logging_set = false;
        if (!logging_set) {
            if (quiche_enable_debug_logging([](const char *line, void *)
                                            { LOG_RAW("[QUICHE] {}", line ? line : "null"); }, nullptr) < 0) {
                LOG_WARN("⚠️ Не удалось включить debug logging от quiche (уже инициализирован?)");
            }
            logging_set = true;
        }

        // Настройки
        const int http3_port = 443;
        const int http2_port = 443; // TCP-прокси слушает тот же порт
        const std::string backend_ip = "10.8.0.11"; // IP сервера в России через WireGuard
        const int backend_port = 41602; // Порт H3-прокси в РФ

        // 🚀 Создание и запуск серверов
        Http3Proxy http3_proxy(http3_port, backend_ip, backend_port);
        Http2Proxy http2_proxy(http2_port, backend_ip, 41603);

        // Запуск HTTP/3 прокси
        std::thread http3_thread([&http3_proxy]() {
            LOG_INFO("🚀 HTTP/3 прокси запущен на порту {}", http3_port);
            if (!http3_proxy.run()) {
                LOG_ERROR("❌ HTTP/3 прокси завершился с ошибкой");
                std::exit(EXIT_FAILURE);
            }
        });

        // Запуск HTTP/2 прокси
        std::thread http2_thread([&http2_proxy]() {
            LOG_INFO("🚀 HTTP/2 прокси запущен на порту {}", http2_port);
            if (!http2_proxy.run()) {
                LOG_ERROR("❌ HTTP/2 прокси завершился с ошибкой");
                std::exit(EXIT_FAILURE);
            }
        });

        // Регистрация обработчика сигналов
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Ожидание завершения всех потоков
        http3_thread.join();
        http2_thread.join();

        LOG_INFO("✅ Все серверы успешно запущены и работают.");
    }
    catch (const std::invalid_argument &e) {
        LOG_ERROR("Неверный формат порта: {}", e.what());
        return EXIT_FAILURE;
    }
    catch (const std::out_of_range &e) {
        LOG_ERROR("Порт выходит за пределы диапазона:  {}", e.what());
        return EXIT_FAILURE;
    }
    catch (const std::exception &e) {
        LOG_ERROR("Неизвестная ошибка: {}", e.what());
        return EXIT_FAILURE;
    }

    LOG_INFO("🛑 Все серверы остановлены.");
    return EXIT_SUCCESS;
}