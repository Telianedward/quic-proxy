// /**
//  * @file server.hpp
//  * @brief Заголовочный файл для HTTP/2 сервера.
//  *
//  * Реализует простой HTTP/2 сервер, который обрабатывает GET и HEAD запросы.
//  * Используется для тестирования базовой сетевой связности и отладки прокси.
//  * Работает поверх TLS (HTTPS).
//  *
//  * @author Telian Edward <telianedward@icloud.com>
//  * @assisted-by AI-Assistant
//  * @date 2025-10-27
//  * @version 1.0
//  * @license MIT
//  */
// #pragma once

// #include <iostream>
// #include <string>
// #include <vector>
// #include <unordered_map>
// #include <atomic>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <unistd.h>
// #include <fcntl.h>
// #include <arpa/inet.h>
// #include <csignal>
// #include <cerrno>
// #include <sys/select.h>
// #include <thread>
// #include "../logger/logger.h"
// #include <openssl/ssl.h>
// #include <openssl/err.h>

// // Для работы с nghttp2
// #include <nghttp2/nghttp2.h>

// /**
//  * @brief Класс HTTP/2 сервера.
//  *
//  * Слушает входящие TCP-соединения на указанном порту и обрабатывает HTTP/2 запросы.
//  * Поддерживает: GET, HEAD, favicon.ico, main.css, main.js.
//  */
// class Http2Server
// {
// public:
//     /**
//      * @brief Конструктор.
//      * @param port Порт, на котором будет слушать сервер (по умолчанию 8586).
//      * @param backend_ip IP-адрес сервера в России.
//      * @param backend_port Порт сервера в России.
//      */
//     explicit Http2Server(int port = 8586, const std::string &backend_ip = "10.8.0.11", int backend_port = 8587);

//     /**
//      * @brief Деструктор класса Http2Server.
//      *
//      * Освобождает ресурсы: SSL-контекст, SSL-соединения.
//      */
//     ~Http2Server();

//     /**
//      * @brief Запускает HTTP/2 сервер.
//      * @return true при успешном завершении, false при ошибке.
//      */
//     bool run();

//     /**
//      * @brief Останавливает HTTP/2 сервер.
//      */
//     void stop();

// private:
//     // 👇 Добавляем структуру для отслеживания незавершённых отправок
//     struct PendingSend
//     {
//         int fd;          ///< Сокет назначения
//         const char *ptr; ///< Указатель на начало данных
//         size_t len;      ///< Общая длина данных
//         size_t sent;     ///< Сколько уже отправлено
//     };

//     /**
//      * @brief Карта незавершённых отправок.
//      *
//      * Используется для буферизации данных при EAGAIN/EWOULDBLOCK.
//      * Ключ — client_fd, значение — структура PendingSend.
//      */
//     std::unordered_map<int, PendingSend> pending_sends_;

//     /**
//      * @brief Структура для хранения информации о соединении.
//      * @details Содержит:
//      *          - backend_fd: дескриптор сокета бэкенда.
//      *          - ssl: указатель на SSL-объект (nullptr, если нет TLS).
//      *          - handshake_done: true, если TLS handshake завершён.
//      *          - session: указатель на nghttp2_session.
//      */
//     struct ConnectionInfo
//     {
//         int backend_fd;      ///< Дескриптор сокета бэкенда
//         SSL *ssl;            ///< Указатель на SSL-объект (nullptr, если нет TLS)
//         bool handshake_done; ///< true, если TLS handshake завершён
//         nghttp2_session *session; ///< Указатель на nghttp2_session
//     };

//     // 🟢 Карта активных соединений: client_fd → ConnectionInfo
//     std::unordered_map<int, ConnectionInfo> connections_; ///< Карта активных соединений

//     int listen_fd_;                       ///< Сокет для прослушивания входящих соединений
//     int port_;                            ///< Порт, на котором слушает сервер
//     std::string backend_ip_;              ///< IP сервера в России
//     int backend_port_;                    ///< Порт сервера в России
//     volatile sig_atomic_t running_{true}; ///< Флаг работы сервера

//     // 🟡 ЗАТЕМ — SSL-ПОЛЯ
//     SSL_CTX *ssl_ctx_;                               ///< SSL-контекст для TLS
//     std::unordered_map<int, SSL *> ssl_connections_; ///< Карта: client_fd → SSL*

//     // 🟠 ЗАТЕМ — КАРТЫ СОЕДИНЕНИЙ
//     std::unordered_map<int, time_t> timeouts_; ///< Карта таймаутов: client_fd → время последней активности

//     /**
//      * @brief Создает и подключается к сокету сервера в России.
//      * @return Дескриптор сокета или -1 при ошибке.
//      */
//     [[nodiscard]] int connect_to_backend() noexcept;

//     /**
//      * @brief Устанавливает неблокирующий режим сокета.
//      * @param fd Дескриптор сокета.
//      * @return true при успехе, false при ошибке.
//      */
//     [[nodiscard]] bool set_nonblocking(int fd) noexcept;

//     /**
//      * @brief Обрабатывает новое входящее соединение.
//      */
//     void handle_new_connection() noexcept;

//     /**
//      * @brief Обрабатывает данные от клиента или сервера.
//      */
//     void handle_io_events() noexcept;

//     /**
//      * @brief Передаёт данные между двумя сокетами (клиент ↔ бэкенд) в неблокирующем режиме, с поддержкой TLS и HTTP/2.
//      *
//      * Основная задача — прочитать данные с одного сокета (`from_fd`) и отправить их на другой (`to_fd`),
//      * при этом корректно обрабатывая:
//      * - частичную отправку (EAGAIN/EWOULDBLOCK),
//      * - ошибки чтения/записи,
//      * - закрытие соединения,
//      * - TLS-шифрование (если соединение защищено),
//      * - HTTP/2 фреймы (если используется HTTP/2).
//      *
//      * Используется для проксирования HTTP/2 трафика через WireGuard-туннель.
//      * TLS-соединение расшифровывается на сервере в Нидерландах, данные передаются на бэкенд в России в виде обычного HTTP.
//      *
//      * @param from_fd Дескриптор сокета источника (клиент или бэкенд).
//      * @param to_fd Дескриптор сокета назначения (бэкенд или клиент).
//      * @param ssl Указатель на SSL-объект (nullptr, если нет TLS).
//      * @param session Указатель на nghttp2_session (nullptr, если нет HTTP/2).
//      * @return true если соединение активно и можно продолжать, false если нужно закрыть соединение.
//      * @throws Никаких исключений — используется noexcept.
//      * @warning Не вызывать при отсутствии данных — может привести к busy-waiting.
//      * @note Если `from_fd` связан с SSL-объектом — используется SSL_read(). Иначе — recv().
//      */
//     [[nodiscard]] bool forward_data(int from_fd, int to_fd, SSL *ssl, nghttp2_session *session) noexcept;

//     /**
//      * @brief Инициализирует nghttp2_session.
//      * @param client_fd Дескриптор сокета клиента.
//      * @param ssl Указатель на SSL-объект.
//      * @return Указатель на nghttp2_session или nullptr при ошибке.
//      */
//     [[nodiscard]] nghttp2_session *init_nghttp2_session(int client_fd, SSL *ssl) noexcept;

//     /**
//      * @brief Обработчик nghttp2 для получения заголовков.
//      * @param session Указатель на nghttp2_session.
//      * @param frame Указатель на nghttp2_frame.
//      * @param name Указатель на имя заголовка.
//      * @param namelen Длина имени заголовка.
//      * @param value Указатель на значение заголовка.
//      * @param valuelen Длина значения заголовка.
//      * @param flags Флаги заголовка.
//      * @param user_data Указатель на пользовательские данные.
//      * @return 0 при успехе, -1 при ошибке.
//      */
//     static int on_header(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data);

//     /**
//      * @brief Обработчик nghttp2 для получения данных.
//      * @param session Указатель на nghttp2_session.
//      * @param frame Указатель на nghttp2_frame.
//      * @param data Указатель на данные.
//      * @param len Длина данных.
//      * @param flags Флаги данных.
//      * @param user_data Указатель на пользовательские данные.
//      * @return 0 при успехе, -1 при ошибке.
//      */
//     static int on_data_chunk_recv(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *data, size_t len, void *user_data);

//     /**
//      * @brief Обработчик nghttp2 для завершения фрейма.
//      * @param session Указатель на nghttp2_session.
//      * @param frame Указатель на nghttp2_frame.
//      * @param user_data Указатель на пользовательские данные.
//      * @return 0 при успехе, -1 при ошибке.
//      */
//     static int on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data);

//     /**
//      * @brief Обработчик nghttp2 для отправки данных.
//      * @param session Указатель на nghttp2_session.
//      * @param data Указатель на данные.
//      * @param len Длина данных.
//      * @param flags Флаги данных.
//      * @param user_data Указатель на пользовательские данные.
//      * @return 0 при успехе, -1 при ошибке.
//      */
//     static int send_callback(nghttp2_session *session, const uint8_t *data, size_t len, int flags, void *user_data);

//     /**
//      * @brief Генерирует HTML-ответ для корневого пути.
//      * @return Строка с HTML-контентом.
//      */
//     [[nodiscard]] std::string generate_index_html() const;

//     /**
//      * @brief Генерирует ответ для favicon.ico.
//      * @return Строка с бинарными данными favicon.
//      */
//     [[nodiscard]] std::string generate_favicon() const;

//     /**
//      * @brief Генерирует ответ для main.css.
//      * @return Строка с CSS-контентом.
//      */
//     [[nodiscard]] std::string generate_main_css() const;

//     /**
//      * @brief Генерирует ответ для main.js.
//      * @return Строка с JS-контентом.
//      */
//     [[nodiscard]] std::string generate_main_js() const;
// };