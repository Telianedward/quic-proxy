// main.cpp
/**
 * @file main.cpp
 * @brief Точка входа в приложение — запуск HTTP/3 и HTTP/2 серверов.
 *
 * Создаёт экземпляры серверов и запускает их в отдельных потоках.
 * Также запускает мониторинг базы данных.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-22
 * @version 1.0
 * @license MIT
 */

#include "include/http3/quic_udp_proxy.hpp"
#include "include/http2/tcp_proxy.hpp"
#include "include/logger/logger.h"
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

        // Настройки
        const int http3_port = 443;
        const int http2_port = 443; // TCP-прокси слушает тот же порт
        const std::string backend_ip = "10.8.0.11"; // IP сервера в России через WireGuard
        const int backend_port = 8586; // Порт H3-сервера в РФ

        // 🚀 Создание и запуск серверов
        QuicUdpProxy quic_proxy(http3_port, backend_ip, backend_port);
        TcpProxy tcp_proxy(http2_port, backend_ip, backend_port);

        // Запуск QUIC-UDP прокси
        std::thread quic_thread([http3_port, &quic_proxy]() { // Захватываем http3_port и quic_proxy
            LOG_INFO("🚀 QUIC-UDP прокси запущен на порту {}", http3_port);
            if (!quic_proxy.run()) {
                LOG_ERROR("❌ QUIC-UDP прокси завершился с ошибкой");
                std::exit(EXIT_FAILURE);
            }
        });

        // Запуск TCP-прокси
        std::thread tcp_thread([http2_port, &tcp_proxy]() { // Захватываем http2_port и tcp_proxy
            LOG_INFO("🚀 TCP-прокси запущен на порту {}", http2_port);
            if (!tcp_proxy.run()) {
                LOG_ERROR("❌ TCP-прокси завершился с ошибкой");
                std::exit(EXIT_FAILURE);
            }
        });

        // Регистрация обработчика сигналов
        std::signal(SIGINT, signal_handler);
        std::signal(SIGTERM, signal_handler);

        // Ожидание завершения всех потоков
        quic_thread.join();
        tcp_thread.join();

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