// src/test_client_netherlands.cpp
/**
 * @file test_client_netherlands.cpp
 * @brief Тестовый клиент для отправки сообщения "Привет, Россия!" на сервер в России.
 *
 * Отправляет простой текстовый запрос на указанный IP и порт.
 * Ожидает ответ от сервера и выводит его в лог.
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
        const int backend_port = 8587;              // Порт, на который отправляем (должен совпадать с тем, куда отправляет клиент)
        const std::string message = "Привет, Россия!";

        LOG_INFO("🚀 [НИДЕРЛАНДЫ] Запуск тестового клиента...");
        LOG_INFO("Отправляю сообщение на {}:{}", backend_ip, backend_port);

        // --- Создание сокета ---
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0)
        {
            LOG_ERROR("❌ [НИДЕРЛАНДЫ] Не удалось создать сокет: {}", strerror(errno));
            return EXIT_FAILURE;
        }
        LOG_SUCCESS("✅ [НИДЕРЛАНДЫ] Сокет успешно создан: fd={}", sock);

        // --- Подключение к серверу ---
        struct sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(backend_port);
        if (inet_pton(AF_INET, backend_ip.c_str(), &server_addr.sin_addr) <= 0)
        {
            LOG_ERROR("❌ [НИДЕРЛАНДЫ] Не удалось преобразовать IP-адрес: {}", backend_ip);
            close(sock);
            return EXIT_FAILURE;
        }

        if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            LOG_ERROR("❌ [НИДЕРЛАНДЫ] Не удалось подключиться к серверу: {}", strerror(errno));
            close(sock);
            return EXIT_FAILURE;
        }

        LOG_SUCCESS("✅ [НИДЕРЛАНДЫ] Подключился к серверу {}:{}", backend_ip, backend_port);

        // --- Отправка сообщения ---
        ssize_t sent_bytes = send(sock, message.c_str(), message.size(), 0);
        if (sent_bytes < 0)
        {
            LOG_ERROR("❌ [НИДЕРЛАНДЫ] Ошибка отправки сообщения: {}", strerror(errno));
            close(sock);
            return EXIT_FAILURE;
        }

        LOG_SUCCESS("✅ [НИДЕРЛАНДЫ] Сообщение успешно отправлено: \"{}\" ({} байт)", message, sent_bytes);

        // --- Получение ответа ---
        char buffer[1024];
        ssize_t received_bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (received_bytes > 0)
        {
            buffer[received_bytes] = '\0'; // Завершаем строку
            LOG_SUCCESS("✅ [НИДЕРЛАНДЫ] Получено сообщение от сервера: \"{}\"", buffer);
        }
        else if (received_bytes == 0)
        {
            // Соединение закрыто сервером
            LOG_INFO("ℹ️ [НИДЕРЛАНДЫ] Сервер закрыл соединение");
        }
        else
        {
            LOG_ERROR("❌ [НИДЕРЛАНДЫ] Ошибка получения сообщения: {}", strerror(errno));
        }

        // --- Закрытие сокета ---
        close(sock);
        LOG_INFO("🛑 [НИДЕРЛАНДЫ] Тестовый клиент завершил работу.");
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("❌ [НИДЕРЛАНДЫ] Неизвестная ошибка: {}", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}