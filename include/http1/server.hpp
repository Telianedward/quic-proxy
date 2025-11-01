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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <memory>
#include <queue>
   // 🟠 ЗАТЕМ — КАРТЫ СОЕДИНЕНИЙ
    /**
     * @brief Структура для хранения информации о соединении.
     * @details Содержит:
     *          - backend_fd: дескриптор сокета бэкенда.
     *          - ssl: указатель на SSL-объект (nullptr, если нет TLS).
     *          - handshake_done: true, если TLS handshake завершён.
     */
    struct ConnectionInfo
    {
        int backend_fd;
        SSL *ssl;
        bool handshake_done;
        bool logged_handshake_want; // 👈 Новый флаг
    }
/**
 * @brief Класс HTTP/1.1 сервера.
 *
 * Слушает входящие TCP-соединения на указанном порту и обрабатывает HTTP/1.1 запросы.
 * Поддерживает: GET, HEAD, favicon.ico, main.css, main.js.
 */
class Http1Server
{
public:
    /**
     * @brief Конструктор.
     * @param port Порт, на котором будет слушать сервер (по умолчанию 8587).
     * @param backend_ip IP-адрес сервера в России.
     * @param backend_port Порт сервера в России.
     */
    explicit Http1Server(int port = 8587, const std::string &backend_ip = "10.8.0.11", int backend_port = 8587);

    /**
     * @brief Деструктор класса Http1Server.
     *
     * Освобождает ресурсы: SSL-контекст, SSL-соединения.
     */
    ~Http1Server();

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
    // 👇 Добавляем структуру для отслеживания незавершённых отправок
struct PendingSend
{
    int fd;          ///< Сокет назначения
    std::unique_ptr<char[]> data; ///< Буфер с данными
    size_t len;      ///< Общая длина данных
    size_t sent;     ///< Сколько уже отправлено
};
// 🟢 Карта незавершённых отправок.
std::unordered_map<int, std::queue<PendingSend>> pending_sends_; ///< Ключ — client_fd

// В файле server.hpp, в классе Http1Server, после pending_sends_
std::unordered_map<int, bool> chunked_complete_; // Ключ — client_fd, значение — true, если чанки завершены
    /**
     * @brief Карта незавершённых отправок.
     *
     * Используется для буферизации данных при EAGAIN/EWOULDBLOCK.
     * Ключ — client_fd, значение — структура PendingSend.
     */
    // 🟢 СНАЧАЛА ИДУТ ПОЛЯ, КОТОРЫЕ ИНИЦИАЛИЗИРУЮТСЯ В КОНСТРУКТОРЕ
    int listen_fd_;                       ///< Сокет для прослушивания входящих соединений
    int port_;                            ///< Порт, на котором слушает сервер
    std::string backend_ip_;              ///< IP сервера в России
    int backend_port_;                    ///< Порт сервера в России
    volatile sig_atomic_t running_{true}; ///< Флаг работы сервера

    // 🟡 ЗАТЕМ — SSL-ПОЛЯ
    SSL_CTX *ssl_ctx_;                               ///< SSL-контекст для TLS
    std::unordered_map<int, SSL *> ssl_connections_; ///< Карта: client_fd → SSL*



    // 🟢 Карта активных соединений: client_fd → ConnectionInfo
    std::unordered_map<int, ConnectionInfo> connections_; ///< Карта активных соединений
    /**
     * @brief Создает и подключается к сокету сервера в России.
     * @return Дескриптор сокета или -1 при ошибке.
     */
    [[nodiscard]] int connect_to_backend() noexcept;

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
 * @brief Передаёт данные между двумя сокетами (клиент ↔ бэкенд) в неблокирующем режиме, с поддержкой TLS.
 *
 * Основная задача — прочитать данные с одного сокета (`from_fd`) и отправить их на другой (`to_fd`),
 * при этом корректно обрабатывая:
 * - частичную отправку (EAGAIN/EWOULDBLOCK),
 * - ошибки чтения/записи,
 * - закрытие соединения,
 * - TLS-шифрование (если соединение защищено).
 *
 * Используется для проксирования HTTP/1.1 трафика через WireGuard-туннель.
 * TLS-соединение расшифровывается на сервере в Нидерландах, данные передаются на бэкенд в России в виде обычного HTTP.
 *
 * @param from_fd Дескриптор сокета источника (клиент или бэкенд).
 * @param to_fd Дескриптор сокета назначения (бэкенд или клиент).
 * @param ssl Указатель на SSL-объект (nullptr, если нет TLS).
 * @return true если соединение активно и можно продолжать, false если нужно закрыть соединение.
 * @throws Никаких исключений — используется noexcept.
 * @warning Не вызывать при отсутствии данных — может привести к busy-waiting.
 * @note Если `from_fd` связан с SSL-объектом — используется SSL_read(). Иначе — recv().
 */
[[nodiscard]] bool forward_data(int from_fd, int to_fd, SSL *ssl) noexcept;
   /**
     * @brief Получает SSL-объект по дескриптору сокета.
     * @param fd Дескриптор сокета.
     * @return Указатель на SSL-объект или nullptr, если не найден.
     */
    [[nodiscard]] SSL* get_ssl_for_fd(int fd) noexcept;
        // 🟢 Карта таймаутов: client_fd → время последней активности.
    std::unordered_map<int, time_t> timeouts_; ///< Карта таймаутов: client_fd → время последней активности

};