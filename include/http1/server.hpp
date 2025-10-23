/**
 * @file server.hpp
 * @brief Заголовочный файл для HTTP/1.1 сервера.
 *
 * Реализует простой HTTP/1.1 сервер, который обрабатывает GET и HEAD запросы.
 * Используется для тестирования базовой сетевой связности и отладки прокси.
 * Не требует TLS — работает на чистом TCP.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-24
 * @version 1.0
 * @license MIT
 */
#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <csignal>
#include <cerrno>
#include <sys/select.h>
#include <thread>
#include "../logger/logger.h"

/**
 * @brief Класс HTTP/1.1 сервера.
 *
 * Слушает входящие TCP-соединения на указанном порту и обрабатывает HTTP/1.1 запросы.
 * Поддерживает: GET, HEAD, favicon.ico, main.css, main.js.
 */
class Http1Server {
public:
    /**
     * @brief Конструктор.
     * @param port Порт, на котором будет слушать сервер (по умолчанию 8587).
     */
    explicit Http1Server(int port = 8587);

    /**
     * @brief Запускает HTTP/1.1 сервер.
     * @return true при успешном завершении, false при ошибке.
     */
    bool run();

    /**
     * @brief Останавливает HTTP/1.1 сервер.
     */
    void stop();

private:
    int listen_fd_;          ///< Сокет для прослушивания входящих соединений
    int port_;               ///< Порт, на котором слушает сервер
    volatile sig_atomic_t running_{true}; ///< Флаг работы сервера
    std::unordered_map<int, int> connections_; ///< Карта активных соединений: client_fd -> backend_fd
    std::unordered_map<int, time_t> timeouts_; ///< Карта таймаутов: client_fd -> время последней активности

    /**
     * @brief Устанавливает неблокирующий режим сокета.
     * @param fd Дескриптор сокета.
     * @return true при успехе, false при ошибке.
     */
    [[nodiscard]] bool set_nonblocking(int fd) noexcept;

    /**
     * @brief Обрабатывает новое входящее соединение.
     */
    void handle_new_connection() noexcept;

    /**
     * @brief Обрабатывает данные от клиента или сервера.
     */
    void handle_io_events() noexcept;

    /**
     * @brief Передает данные между клиентом и сервером.
     * @param from_fd Дескриптор сокета источника.
     * @param to_fd Дескриптор сокета назначения.
     * @return true, если соединение активно, false — если нужно закрыть.
     */
    [[nodiscard]] bool forward_data(int from_fd, int to_fd) noexcept;

    /**
     * @brief Генерирует HTML-ответ для корневого пути.
     * @return Строка с HTML-контентом.
     */
    [[nodiscard]] std::string generate_index_html() const;

    /**
     * @brief Генерирует ответ для favicon.ico.
     * @return Строка с бинарными данными favicon.
     */
    [[nodiscard]] std::string generate_favicon() const;

    /**
     * @brief Генерирует ответ для main.css.
     * @return Строка с CSS-контентом.
     */
    [[nodiscard]] std::string generate_main_css() const;

    /**
     * @brief Генерирует ответ для main.js.
     * @return Строка с JS-контентом.
     */
    [[nodiscard]] std::string generate_main_js() const;
};