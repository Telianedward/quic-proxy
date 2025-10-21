// include/http2/tcp_proxy.hpp
/**
 * @file tcp_proxy.hpp
 * @brief Заголовочный файл для TCP-прокси, обрабатывающего HTTP/2 и HTTP/1.1.
 *
 * Обеспечивает прозрачное перенаправление TCP-соединений от клиента к серверу в России.
 * Использует асинхронный I/O (select) для масштабируемости.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-22
 * @version 1.0
 * @license MIT
 */
#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
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
 * @brief Класс TCP-прокси для HTTP/2 и HTTP/1.1.
 *
 * Слушает входящие TCP-соединения на порту 443 и перенаправляет их на сервер в России (через WireGuard).
 */
class TcpProxy {
public:
    /**
     * @brief Конструктор.
     * @param listen_port Порт, на котором слушает прокси (обычно 443).
     * @param backend_ip IP-адрес сервера в России.
     * @param backend_port Порт сервера в России.
     */
    TcpProxy(int listen_port, const std::string& backend_ip, int backend_port);

    /**
     * @brief Запускает TCP-прокси.
     * @return true при успешном завершении, false при ошибке.
     */
    bool run();

    /**
     * @brief Останавливает TCP-прокси.
     */
    void stop();

private:
    int listen_fd_;          ///< Сокет для прослушивания входящих соединений
    int backend_port_;       ///< Порт сервера в России
    std::string backend_ip_; ///< IP сервера в России
    int listen_port_;        ///< Порт, на котором слушает прокси
    volatile sig_atomic_t running_{true}; ///< Флаг работы прокси

    // Карта активных соединений: client_fd -> backend_fd
    std::unordered_map<int, int> connections_;

    /**
     * @brief Устанавливает неблокирующий режим сокета.
     * @param fd Дескриптор сокета.
     * @return true при успехе, false при ошибке.
     */
    [[nodiscard]] bool set_nonblocking(int fd) noexcept;

    /**
     * @brief Создает и подключается к сокету сервера в России.
     * @return Дескриптор сокета или -1 при ошибке.
     */
    [[nodiscard]] int connect_to_backend() noexcept;

    /**
     * @brief Передает данные между клиентом и сервером.
     * @param client_fd Дескриптор сокета клиента.
     * @param backend_fd Дескриптор сокета сервера.
     * @return true, если соединение активно, false — если нужно закрыть.
     */
    [[nodiscard]] bool forward_data(int client_fd, int backend_fd) noexcept;

    /**
     * @brief Обрабатывает новое входящее соединение.
     */
    void handle_new_connection() noexcept;

    /**
     * @brief Обрабатывает данные от клиента или сервера.
     */
    void handle_io_events() noexcept;
};