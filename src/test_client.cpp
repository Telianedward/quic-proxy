// src/test_client.cpp
/**
 * @file test_client.cpp
 * @brief Тестовый клиент для отправки UDP-сообщения на сервер в России.
 *
 * Используется для проверки работоспособности сети и WireGuard-туннеля.
 * Отправляет простое текстовое сообщение на указанный IP и порт.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-24
 * @version 1.0
 * @license MIT
 */
#include "logger/logger.h"
#include <iostream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>

int main()
{
    try
    {
        // --- Настройки ---
        const std::string backend_ip = "10.8.0.11"; // IP сервера в России через WireGuard
        const int backend_port = 8585;              // Порт, на который отправляем (можно любой открытый)
        const std::string message = "Тестовое сообщение от сервера в Нидерландах! 🇳🇱 → 🇷🇺";

        LOG_INFO("🚀 Запуск тестового клиента...");
        LOG_INFO("Отправляю сообщение на {}:{}", backend_ip, backend_port);

        // --- Создание сокета ---
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
        {
            LOG_ERROR("❌ Не удалось создать сокет: {}", strerror(errno));
            return EXIT_FAILURE;
        }
        LOG_SUCCESS("✅ Сокет успешно создан: fd={}", sock);

        // --- Подготовка адреса сервера ---
        struct sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(backend_port);
        if (inet_pton(AF_INET, backend_ip.c_str(), &server_addr.sin_addr) <= 0)
        {
            LOG_ERROR("❌ Не удалось преобразовать IP-адрес: {}", backend_ip);
            close(sock);
            return EXIT_FAILURE;
        }

        // --- Отправка сообщения ---
        ssize_t sent_bytes = sendto(sock, message.c_str(), message.size(), 0,
                                    (struct sockaddr *)&server_addr, sizeof(server_addr));
        if (sent_bytes < 0)
        {
            LOG_ERROR("❌ Ошибка отправки сообщения: {}", strerror(errno));
            close(sock);
            return EXIT_FAILURE;
        }

        LOG_SUCCESS("✅ Сообщение успешно отправлено: \"{}\" ({} байт)", message, sent_bytes);

        // --- Закрытие сокета ---
        close(sock);
        LOG_INFO("🛑 Тестовый клиент завершил работу.");
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("❌ Неизвестная ошибка: {}", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}