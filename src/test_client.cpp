// src/server/test_server.cpp
/**
 * @file test_server.cpp
 * @brief Тестовый HTTP/2 сервер для приёма запросов от прокси в Нидерландах.
 *
 * Слушает указанный порт (8587) и выводит любое полученное сообщение в лог.
 * Добавляет в ответ слова "Тестовое сообщение от сервера в России!" и возвращает его обратно.
 * Используется для проверки работоспособности сети и WireGuard-туннеля.
 * Не требует SSL/TLS, работает на чистом TCP.
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
#include <fcntl.h> // Для fcntl

int main()
{
    try
    {
        // --- Настройки ---
        const int listen_port = 8587; // Порт, на котором слушаем (должен совпадать с тем, куда отправляет клиент)
        const std::string listen_ip = "10.8.0.11"; // IP-адрес интерфейса WireGuard

        LOG_INFO("🚀 Запуск тестового HTTP/2 сервера...");
        LOG_INFO("Слушаю порт {} на адресе {}", listen_port, listen_ip);

        // --- Создание сокета ---
        int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock < 0)
        {
            LOG_ERROR("❌ Не удалось создать сокет: {}", strerror(errno));
            return EXIT_FAILURE;
        }
        LOG_SUCCESS("✅ Сокет успешно создан: fd={}", sock);

        // --- Установка неблокирующего режима (опционально, но рекомендуется) ---
        int flags = fcntl(sock, F_GETFL, 0);
        if (flags == -1)
        {
            LOG_WARN("⚠️ Не удалось получить флаги сокета");
        }
        else
        {
            if (fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1)
            {
                LOG_WARN("⚠️ Не удалось установить неблокирующий режим");
            }
        }

        // --- Привязка к адресу ---
        struct sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(listen_port);
        if (inet_pton(AF_INET, listen_ip.c_str(), &server_addr.sin_addr) <= 0)
        {
            LOG_ERROR("❌ Не удалось преобразовать IP-адрес: {}", listen_ip);
            close(sock);
            return EXIT_FAILURE;
        }

        if (bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            LOG_ERROR("❌ Не удалось привязать сокет к адресу: {}", strerror(errno));
            close(sock);
            return EXIT_FAILURE;
        }
        LOG_SUCCESS("✅ Сокет успешно привязан к адресу {}:{}", listen_ip, listen_port);

        // --- Начало прослушивания ---
        if (listen(sock, SOMAXCONN) < 0)
        {
            LOG_ERROR("❌ Не удалось начать прослушивание: {}", strerror(errno));
            close(sock);
            return EXIT_FAILURE;
        }
        LOG_SUCCESS("✅ Сервер начал прослушивание на порту {}", listen_port);

        // --- Цикл ожидания соединений ---
        char buffer[1024];
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);

        LOG_INFO("⏳ Ожидаю входящие соединения...");

        while (true)
        {
            int client_fd = accept(sock, (struct sockaddr *)&client_addr, &client_len);
            if (client_fd >= 0)
            {
                std::string client_ip = inet_ntoa(client_addr.sin_addr);
                uint16_t client_port = ntohs(client_addr.sin_port);

                LOG_SUCCESS("✅ Подключился клиент: {}:{} (fd={})", client_ip, client_port, client_fd);

                // --- Чтение данных от клиента ---
                ssize_t received_bytes = recv(client_fd, buffer, sizeof(buffer) - 1, 0);
                if (received_bytes > 0)
                {
                    buffer[received_bytes] = '\0'; // Завершаем строку
                    LOG_SUCCESS("✅ Получено сообщение от {}:{} ({} байт): \"{}\"",
                                client_ip, client_port, received_bytes, buffer);

                    // --- Добавление слов в ответ ---
                    std::string response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ";
                    std::string added_message = "Тестовое сообщение от сервера в России!";
                    response += std::to_string(added_message.size()) + "\r\n\r\n" + added_message;

                    // --- Отправка ответа ---
                    ssize_t sent_bytes = send(client_fd, response.c_str(), response.size(), 0);
                    if (sent_bytes < 0)
                    {
                        LOG_ERROR("❌ Ошибка отправки ответа: {}", strerror(errno));
                    }
                    else
                    {
                        LOG_SUCCESS("✅ Отправлен ответ клиенту {}:{} ({} байт): \"{}\"",
                                    client_ip, client_port, sent_bytes, response);
                    }
                }
                else if (received_bytes == 0)
                {
                    // Соединение закрыто клиентом
                    LOG_INFO("ℹ️ Клиент {}:{} закрыл соединение", client_ip, client_port);
                }
                else
                {
                    LOG_ERROR("❌ Ошибка получения данных от клиента: {}", strerror(errno));
                }

                // --- Закрытие соединения ---
                close(client_fd);
                LOG_INFO("🛑 Соединение с клиентом {}:{} закрыто.", client_ip, client_port);
            }
            else
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    LOG_ERROR("❌ Ошибка accept: {}", strerror(errno));
                }
                // Для неблокирующего сокета продолжаем цикл
            }

            // Короткая задержка, чтобы не нагружать CPU
            usleep(10000); // 10 мс
        }

        // --- Закрытие сокета (никогда не достигается в этом цикле) ---
        close(sock);
        LOG_INFO("🛑 Тестовый сервер завершил работу.");
    }
    catch (const std::exception &e)
    {
        LOG_ERROR("❌ Неизвестная ошибка: {}", e.what());
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}