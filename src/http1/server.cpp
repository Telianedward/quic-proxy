/**
 * @file server.cpp
 * @brief Реализация HTTP/1.1 сервера с использованием epoll.
 *
 * Обеспечивает обработку простых HTTP/1.1 запросов (GET, HEAD) с поддержкой TLS.
 * Использует современный API OpenSSL 3.0+ и epoll для асинхронного ввода-вывода.
 * Логирует все ключевые события: подключение, получение данных, отправка ответа.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-11-02
 * @version 1.0
 * @license MIT
 */
#include "server.hpp"
#include <cstring>
#include <algorithm>
#include <sstream>
#include <poll.h>

// === Реализация методов класса Http1Server ===

Http1Server::Http1Server(int port, const std::string &backend_ip, int backend_port)
    : listen_fd_(-1), port_(port), backend_ip_(backend_ip), backend_port_(backend_port),
      ssl_ctx_(nullptr), epoll_fd_(-1) {
    // Инициализация OpenSSL 3.0+
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr) != 1) {
        LOG_ERROR("[ERROR] [server.cpp:65] Не удалось инициализировать OpenSSL");
        return;
    }
    LOG_INFO("[INFO] [server.cpp:69] ✅ OpenSSL 3.0+ успешно инициализирован");

    // Создание SSL-контекста
    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx_) {
        LOG_ERROR("[ERROR] [server.cpp:75] ❌ Не удалось создать SSL-контекст");
        return;
    }

    // 🟢 ИСПОЛЬЗУЕМ ПОДГОТОВЛЕННЫЕ ФАЙЛЫ ИЗ /opt/quic-proxy/
    const char *cert_path = "/opt/quic-proxy/fullchain.pem";
    const char *key_path = "/opt/quic-proxy/privkey.pk8";

    // 🟡 ПРОВЕРКА СУЩЕСТВОВАНИЯ ФАЙЛОВ
    if (access(cert_path, R_OK) != 0) {
        LOG_ERROR("[ERROR] [server.cpp:85] ❌ Сертификат не найден или недоступен: {}", cert_path);
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    if (access(key_path, R_OK) != 0) {
        LOG_ERROR("[ERROR] [server.cpp:90] ❌ Приватный ключ не найден или недоступен: {}", key_path);
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }

    // Загрузка сертификата и ключа
    if (SSL_CTX_use_certificate_file(ssl_ctx_, cert_path, SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("[ERROR] [server.cpp:97] ❌ Не удалось загрузить сертификат: {}", ERR_error_string(ERR_get_error(), nullptr));
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, key_path, SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("[ERROR] [server.cpp:102] ❌ Не удалось загрузить приватный ключ: {}", ERR_error_string(ERR_get_error(), nullptr));
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    // Проверка соответствия ключа и сертификата
    if (!SSL_CTX_check_private_key(ssl_ctx_)) {
        LOG_ERROR("[ERROR] [server.cpp:108] ❌ Ключ и сертификат не совпадают");
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    LOG_INFO("[INFO] [server.cpp:113] ✅ SSL-контекст успешно создан и настроен");
}

Http1Server::~Http1Server() {
    // Закрываем epoll
    if (epoll_fd_ != -1) {
        ::close(epoll_fd_);
        epoll_fd_ = -1;
    }

    // Очистка всех SSL-соединений
    for (auto &[fd, ssl] : ssl_connections_) {
        SSL_free(ssl);
    }
    ssl_connections_.clear();

    if (ssl_ctx_) {
        SSL_CTX_set_max_send_fragment(ssl_ctx_, 16384); // 16KB фрагменты
        SSL_CTX_set_read_ahead(ssl_ctx_, 1);            // Включить read-ahead
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }

    // Закрываем все соединения
    for (const auto &conn : connections_) {
        int client_fd = conn.first;
        const ConnectionInfo &info = conn.second;
        ::close(client_fd);
        ::close(info.backend_fd);
    }
    connections_.clear();
    if (listen_fd_ != -1) {
        ::close(listen_fd_);
    }
    LOG_INFO("[INFO] [server.cpp:146] HTTP/1.1 сервер остановлен.");
}

bool Http1Server::run() {
    // Создаем сокет для прослушивания
    listen_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd_ < 0) {
        LOG_ERROR("[ERROR] [server.cpp:156] Не удалось создать сокет для прослушивания: {}", strerror(errno));
        return false;
    }

    // Устанавливаем опции
    int opt = 1;
    if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("[ERROR] [server.cpp:163] setsockopt SO_REUSEADDR failed: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }
    if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("[ERROR] [server.cpp:168] setsockopt SO_REUSEPORT failed: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }

    // Устанавливаем неблокирующий режим
    if (!set_nonblocking(listen_fd_)) {
        LOG_ERROR("[ERROR] [server.cpp:175] Не удалось установить неблокирующий режим для сокета прослушивания");
        ::close(listen_fd_);
        return false;
    }

    // Привязываемся к адресу и порту
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);
    if (bind(listen_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("[ERROR] [server.cpp:185] Не удалось привязать сокет к порту {}: {}", port_, strerror(errno));
        ::close(listen_fd_);
        return false;
    }

    // Начинаем прослушивать
    if (listen(listen_fd_, SOMAXCONN) < 0) {
        LOG_ERROR("[ERROR] [server.cpp:191] Не удалось начать прослушивание: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }

    // Создаем epoll
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ == -1) {
        LOG_ERROR("[ERROR] [server.cpp:198] Не удалось создать epoll: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }

    // Регистрируем listen_fd в epoll
    if (!add_epoll_event(listen_fd_, EPOLLIN)) {
        LOG_ERROR("[ERROR] [server.cpp:204] Не удалось добавить listen_fd в epoll");
        ::close(listen_fd_);
        ::close(epoll_fd_);
        return false;
    }

    LOG_INFO("[INFO] [server.cpp:209] HTTP/1.1 сервер запущен на порту {} с использованием epoll", port_);

    // Главный цикл
    while (running_.load()) {
        struct epoll_event events[64];
        int nfds = epoll_wait(epoll_fd_, events, 64, 1000); // Таймаут 1 секунда

        if (nfds == -1) {
            if (errno == EINTR) {
                continue; // Прерван сигналом
            }
            LOG_ERROR("[ERROR] [server.cpp:220] Ошибка epoll_wait: {}", strerror(errno));
            continue;
        }

        for (int i = 0; i < nfds; ++i) {
            int fd = events[i].data.fd;
            uint32_t events_mask = events[i].events;

            if (fd == listen_fd_) {
                // Новое соединение
                handle_new_connection();
            } else {
                // Обработка данных от клиента или бэкенда
                handle_io_events(fd, events_mask);
            }
        }

        // Проверка таймаутов
        time_t now = time(nullptr);
        for (auto it = timeouts_.begin(); it != timeouts_.end();) {
            if (now - it->second > 60) { // Таймаут 60 секунд
                int client_fd = it->first;
                ::close(client_fd);
                connections_.erase(client_fd);
                timeouts_.erase(it++);
                LOG_INFO("[INFO] [server.cpp:244] TCP-соединение закрыто по таймауту: клиент {}", client_fd);
            } else {
                ++it;
            }
        }
    }

    return true;
}

void Http1Server::stop() {
    running_.store(false);
}

bool Http1Server::set_nonblocking(int fd) noexcept {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

int Http1Server::connect_to_backend() noexcept {
    int backend_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (backend_fd < 0) {
        LOG_ERROR("[ERROR] [server.cpp:267] Не удалось создать сокет для подключения к серверу в России: {}", strerror(errno));
        return -1;
    }

    // Устанавливаем неблокирующий режим
    if (!set_nonblocking(backend_fd)) {
        LOG_ERROR("[ERROR] [server.cpp:273] Не удалось установить неблокирующий режим для сокета сервера");
        ::close(backend_fd);
        return -1;
    }

    // Устанавливаем адрес сервера
    struct sockaddr_in backend_addr{};
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(backend_port_);
    if (inet_pton(AF_INET, backend_ip_.c_str(), &backend_addr.sin_addr) <= 0) {
        LOG_ERROR("[ERROR] [server.cpp:282] Не удалось преобразовать IP-адрес сервера: {}", backend_ip_);
        ::close(backend_fd);
        return -1;
    }

    // Подключаемся к серверу
    if (connect(backend_fd, (struct sockaddr *)&backend_addr, sizeof(backend_addr)) < 0) {
        if (errno != EINPROGRESS) {
            LOG_ERROR("[ERROR] [server.cpp:290] Не удалось подключиться к серверу в России: {}", strerror(errno));
            ::close(backend_fd);
            return -1;
        }
        LOG_DEBUG("[DEBUG] [server.cpp:294] ⏳ Подключение к бэкенду {}:{} в процессе...", backend_ip_, backend_port_);

        // Ждём завершения подключения
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(backend_fd, &write_fds);
        timeval timeout{.tv_sec = 5, .tv_usec = 0}; // Таймаут 5 секунд
        int activity = select(backend_fd + 1, nullptr, &write_fds, nullptr, &timeout);
        if (activity <= 0) {
            LOG_ERROR("[ERROR] [server.cpp:302] ❌ Таймаут подключения к бэкенду {}:{} (errno={})", backend_ip_, backend_port_, errno);
            ::close(backend_fd);
            return -1;
        }

        // Проверяем, успешно ли подключились
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(backend_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            LOG_ERROR("[ERROR] [server.cpp:310] ❌ Не удалось получить статус подключения: {}", strerror(errno));
            ::close(backend_fd);
            return -1;
        }
        if (error != 0) {
            LOG_ERROR("[ERROR] [server.cpp:315] ❌ Ошибка подключения к бэкенду {}:{}: {}", backend_ip_, backend_port_, strerror(error));
            ::close(backend_fd);
            return -1;
        }
        LOG_INFO("[INFO] [server.cpp:319] ✅ Подключение к бэкенду {}:{} успешно установлено", backend_ip_, backend_port_);
    } else {
        LOG_INFO("[INFO] [server.cpp:322] ✅ Подключение к бэкенду {}:{} успешно установлено (мгновенно)", backend_ip_, backend_port_);
    }
    return backend_fd;
}

void Http1Server::handle_new_connection() noexcept {
    // 🟡 СТРУКТУРА ДЛЯ ХРАНЕНИЯ АДРЕСА КЛИЕНТА
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    // 🟢 ПРИЕМ НОВОГО СОЕДИНЕНИЯ
    int client_fd = accept(listen_fd_, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("[ERROR] [server.cpp:337] ❌ Ошибка accept: {}", strerror(errno));
        }
        return;
    }

    // 🟣 УСТАНОВКА НЕБЛОКИРУЮЩЕГО РЕЖИМА
    if (!set_nonblocking(client_fd)) {
        LOG_ERROR("[ERROR] [server.cpp:343] ❌ Не удалось установить неблокирующий режим для клиента");
        ::close(client_fd);
        return;
    }

    // 🟤 ЛОГИРОВАНИЕ ИНФОРМАЦИИ О КЛИЕНТЕ
    std::string client_ip_str = inet_ntoa(client_addr.sin_addr);
    uint16_t client_port_num = ntohs(client_addr.sin_port);
    LOG_INFO("[INFO] [server.cpp:350] 🟢 Новое соединение от клиента: {}:{} (fd={})", client_ip_str, client_port_num, client_fd);

    // 🟢 ОБЪЯВЛЯЕМ backend_fd ВНАЧАЛЕ МЕТОДА
    int backend_fd = -1;
    // Подключаемся к серверу в России
    backend_fd = connect_to_backend();
    if (backend_fd == -1) {
        LOG_ERROR("[ERROR] [server.cpp:357] ❌ Не удалось подключиться к серверу в России. Закрываем соединение с клиентом.");
        ::close(client_fd);
        return;
    }

    // 🟢 СОЗДАНИЕ SSL-ОБЪЕКТА ДЛЯ TLS-ШИФРОВАНИЯ
    SSL *ssl = SSL_new(ssl_ctx_);
    if (!ssl) {
        LOG_ERROR("[ERROR] [server.cpp:364] ❌ Не удалось создать SSL-объект для клиента");
        ::close(client_fd);
        return;
    }

    // 🟠 ПРИВЯЗКА SSL К СОКЕТУ
    SSL_set_fd(ssl, client_fd);

    // 🟣 УСТАНОВКА НЕБЛОКИРУЮЩЕГО РЕЖИМА ДЛЯ SSL
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    // 🟢 ДОБАВЛЯЕМ СОЕДИНЕНИЕ В connections_ ДАЖЕ ЕСЛИ HANDSHAKE НЕ ЗАВЕРШЁН
    ConnectionInfo info;
    info.backend_fd = backend_fd;
    info.ssl = ssl;
    info.handshake_done = false; // 👈 Пока не завершён
    connections_[client_fd] = info;

    // 🟢 ИНИЦИАЛИЗИРУЕМ chunked_complete_ ДЛЯ НОВОГО СОЕДИНЕНИЯ
    chunked_complete_[client_fd] = false;

    // 🟢 УСТАНАВЛИВАЕМ ТАЙМАУТ
    timeouts_[client_fd] = time(nullptr);

    // 🟢 РЕГИСТРИРУЕМ client_fd В epoll
    if (!add_epoll_event(client_fd, EPOLLIN)) {
        LOG_ERROR("[ERROR] [server.cpp:387] ❌ Не удалось добавить client_fd в epoll");
        SSL_free(ssl);
        connections_.erase(client_fd);
        timeouts_.erase(client_fd);
        ::close(client_fd);
        return;
    }

    // 🟢 ЗАПУСКАЕМ TLS HANDSHAKE
    int ssl_accept_result = SSL_accept(ssl);
    if (ssl_accept_result <= 0) {
        int ssl_error = SSL_get_error(ssl, ssl_accept_result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
            LOG_DEBUG("[DEBUG] [server.cpp:397] ⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE). Соединение оставлено в connections_ для дальнейшей обработки.");
            return; // Ждём следующего цикла epoll
        } else {
            LOG_ERROR("[ERROR] [server.cpp:401] ❌ TLS handshake не удался: {}", ERR_error_string(ERR_get_error(), nullptr));
            SSL_free(ssl);
            connections_.erase(client_fd);
            timeouts_.erase(client_fd);
            ::close(client_fd);
            return;
        }
    }

    // 🟢 HANDSHAKE УСПЕШНО ЗАВЕРШЁН
    LOG_INFO("[INFO] [server.cpp:409] ✅ TLS handshake успешно завершён для клиента: {}:{} (fd={})", client_ip_str, client_port_num, client_fd);
    // Обновляем информацию — помечаем handshake как завершённый
    info.handshake_done = true;
    connections_[client_fd] = info;
    LOG_INFO("[INFO] [server.cpp:414] ✅ TLS-соединение успешно установлено для клиента: {}:{} (fd={})", client_ip_str, client_port_num, client_fd);
}

void Http1Server::handle_io_events(int fd, uint32_t events_mask) noexcept {
    auto it = connections_.find(fd);
    if (it == connections_.end()) {
        LOG_WARN("[WARN] [server.cpp:423] ⚠️ Неизвестный fd={} в connections_", fd);
        return;
    }

    int client_fd = it->first;
    ConnectionInfo &info = it->second;

    // 🟡 ПРОВЕРКА: ЭТО SSL-СОЕДИНЕНИЕ?
    bool is_ssl = info.ssl != nullptr;

    // 🟠 ЕСЛИ HANDSHAKE НЕ ЗАВЕРШЁН — ПОПЫТКА ЗАВЕРШИТЬ ЕГО
    if (is_ssl && !info.handshake_done) {
        int ssl_accept_result = SSL_accept(info.ssl);
        if (ssl_accept_result <= 0) {
            int ssl_error = SSL_get_error(info.ssl, ssl_accept_result);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                // 🟡 ЛОГИРОВАНИЕ ТЕКУЩЕГО СОСТОЯНИЯ SSL
                LOG_DEBUG("[DEBUG] [server.cpp:439] 🔒 SSL state: {}", SSL_state_string_long(info.ssl));
                // 🟢 ПОПЫТКА ПРОЧИТАТЬ ClientHello (если есть данные)
                char client_hello[8192];
                int bytes_read = SSL_read(info.ssl, client_hello, sizeof(client_hello));
                if (bytes_read > 0) {
                    // 🟣 ЛОГИРОВАНИЕ ClientHello
                    LOG_INFO("[INFO] [server.cpp:445] 📋 ClientHello от клиента {}:\n{}", client_fd, std::string(client_hello, bytes_read).substr(0, 512));
                } else if (bytes_read == 0) {
                    LOG_WARN("[WARN] [server.cpp:449] ⚠️ Клиент {} закрыл соединение во время handshake", client_fd);
                    SSL_free(info.ssl);
                    connections_.erase(client_fd);
                    ::close(client_fd);
                    remove_epoll_event(client_fd);
                    return;
                } else {
                    int ssl_error_after_read = SSL_get_error(info.ssl, bytes_read);
                    if (ssl_error_after_read != SSL_ERROR_WANT_READ && ssl_error_after_read != SSL_ERROR_WANT_WRITE) {
                        LOG_ERROR("[ERROR] [server.cpp:456] ❌ Ошибка чтения ClientHello: {}", ERR_error_string(ERR_get_error(), nullptr));
                        SSL_free(info.ssl);
                        connections_.erase(client_fd);
                        ::close(client_fd);
                        remove_epoll_event(client_fd);
                        return;
                    }
                }
                LOG_DEBUG("[DEBUG] [server.cpp:462] ⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE)");
                return; // Ждём следующего цикла
            } else {
                LOG_ERROR("[ERROR] [server.cpp:467] ❌ TLS handshake не удался: {}", ERR_error_string(ERR_get_error(), nullptr));
                SSL_free(info.ssl);
                connections_.erase(client_fd);
                ::close(client_fd);
                remove_epoll_event(client_fd);
                return;
            }
        }
        // 🟢 HANDSHAKE УСПЕШНО ЗАВЕРШЁН
        LOG_INFO("[INFO] [server.cpp:475] ✅ TLS handshake успешно завершён для клиента: {} (fd={})", client_fd, client_fd);
        // Обновляем информацию — помечаем handshake как завершённый
        info.handshake_done = true;
    }

    // 🟢 ПЕРЕДАЧА ДАННЫХ ОТ КЛИЕНТА К СЕРВЕРУ
    if (events_mask & EPOLLIN) {
        LOG_INFO("[INFO] [server.cpp:484] 📥 Получены данные от клиента {} (fd={})", client_fd, client_fd);
        LOG_DEBUG("[DEBUG] [server.cpp:485] 🔄 Начало обработки данных через forward_data: from_fd={}, to_fd={}", client_fd, info.backend_fd);

        // 🟢 СНАЧАЛА ПРОВЕРЯЕМ НЕЗАВЕРШЁННЫЕ ОТПРАВКИ ДЛЯ БЭКЕНДА
        if (!pending_sends_.empty() && pending_sends_.find(info.backend_fd) != pending_sends_.end() && !pending_sends_[info.backend_fd].empty()) {
            auto &pending_queue = pending_sends_[info.backend_fd];
            while (!pending_queue.empty()) {
                auto &pending = pending_queue.front();
                if (pending.fd != info.backend_fd) {
                    pending_queue.pop();
                    continue;
                }
                ssize_t bytes_sent = send(pending.fd, pending.data.get() + pending.sent, pending.len - pending.sent, MSG_NOSIGNAL);
                if (bytes_sent <= 0) {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        LOG_WARN("[WARN] [server.cpp:500] ⏸️ Буфер отправки на бэкенд заполнен");
                        break; // Оставляем в очереди
                    } else {
                        LOG_ERROR("[ERROR] [server.cpp:504] ❌ send() ошибка при отправке на бэкенд: {}", strerror(errno));
                        pending_queue.pop();
                        break;
                    }
                }
                pending.sent += bytes_sent;
                LOG_DEBUG("[DEBUG] [server.cpp:510] 📈 Отправлено {} байт на бэкенд, всего {}/{}", bytes_sent, pending.sent, pending.len);
                if (pending.sent >= pending.len) {
                    pending_queue.pop(); // Успешно отправили всю порцию
                } else {
                    break; // Остались неотправленные данные
                }
            }
        }

        // 🟢 ТЕПЕРЬ ЧИТАЕМ НОВЫЕ ДАННЫЕ ОТ КЛИЕНТА
        bool keep_alive = forward_data(client_fd, info.backend_fd, info.ssl); // 👈 Передаём ssl
        if (!keep_alive) {
            // 🟢 Если клиент уже закрыл соединение — не вызываем SSL_shutdown()
            if (SSL_is_init_finished(info.ssl)) {
                LOG_DEBUG("[DEBUG] [server.cpp:526] 🔄 Начало SSL_shutdown() для клиента {}", client_fd);
                int shutdown_result = SSL_shutdown(info.ssl);
                if (shutdown_result == 1) {
                    // Успешное завершение
                    LOG_INFO("[INFO] [server.cpp:530] ✅ SSL_shutdown() успешно завершён (первый этап) для клиента {}", client_fd);
                } else if (shutdown_result == 0) {
                    // Требуется второй вызов
                    LOG_DEBUG("[DEBUG] [server.cpp:534] ⏸️ Требуется второй вызов SSL_shutdown() для клиента {}", client_fd);
                    int second_shutdown = SSL_shutdown(info.ssl);
                    if (second_shutdown == 1) {
                        LOG_INFO("[INFO] [server.cpp:538] ✅ SSL_shutdown() успешно завершён (второй этап) для клиента {}", client_fd);
                    } else {
                        LOG_WARN("[WARN] [server.cpp:541] ⚠️ Второй SSL_shutdown() не удался для клиента {}: {}", client_fd, ERR_error_string(ERR_get_error(), nullptr));
                    }
                } else {
                    // Ошибка
                    int shutdown_error = SSL_get_error(info.ssl, shutdown_result);
                    LOG_ERROR("[ERROR] [server.cpp:547] ❌ SSL_shutdown() ошибка: {} (код={})", ERR_error_string(shutdown_error, nullptr), shutdown_error);
                }
            } else {
                LOG_DEBUG("[DEBUG] [server.cpp:552] ⏸️ SSL не готов к shutdown - пропускаем");
            }
            // 🟢 Закрываем сокеты
            ::close(client_fd);
            ::close(info.backend_fd);
            // 🟢 Удаляем из карт
            connections_.erase(client_fd);
            timeouts_.erase(client_fd);
            // 🟢 Освобождаем SSL-объект
            if (is_ssl && info.ssl) {
                SSL_free(info.ssl);
            }
            remove_epoll_event(client_fd);
            LOG_INFO("[INFO] [server.cpp:564] TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, info.backend_fd);
        } else {
            timeouts_[client_fd] = time(nullptr);
        }
    }

    // 🟢 ПЕРЕДАЧА ДАННЫХ ОТ БЭКЕНДА К КЛИЕНТУ
    if (events_mask & EPOLLIN) {
        LOG_INFO("[INFO] [server.cpp:573] 📤 Получены данные от сервера {}", info.backend_fd);
        // 🔴 ПРОВЕРКА: ЗАВЕРШЁН ЛИ HANDSHAKE?
        if (info.ssl != nullptr && !info.handshake_done) {
            LOG_WARN("[WARN] [server.cpp:577] ❗ Нельзя отправлять данные клиенту, пока handshake не завершён. Пропускаем.");
            return; // Пропускаем эту итерацию, ждём завершения handshake
        }
        // 🟢 Передаём данные
        bool keep_alive = forward_data(info.backend_fd, client_fd, nullptr); // 👈 Передаём nullptr, так как данные от бэкенда не шифруются
        if (!keep_alive) {
            // 🟢 Если клиент уже закрыл соединение — не вызываем SSL_shutdown()
            if (is_ssl && info.ssl) {
                // 🟢 Проверяем, был ли уже вызван SSL_shutdown()
                int shutdown_state = SSL_get_shutdown(info.ssl);
                if (shutdown_state & SSL_RECEIVED_SHUTDOWN) {
                    LOG_DEBUG("[DEBUG] [server.cpp:590] 🟡 Клиент уже закрыл соединение. SSL_shutdown() не требуется.");
                } else {
                    LOG_DEBUG("[DEBUG] [server.cpp:593] 🔄 Вызов SSL_shutdown() для клиента {}", client_fd);
                    int shutdown_result = SSL_shutdown(info.ssl);
                    if (shutdown_result < 0) {
                        LOG_WARN("[WARN] [server.cpp:597] ⚠️ SSL_shutdown() вернул ошибку: {}", ERR_error_string(ERR_get_error(), nullptr));
                    } else {
                        LOG_INFO("[INFO] [server.cpp:600] ✅ SSL_shutdown() успешно завершён для клиента {}", client_fd);
                    }
                }
            }
            // 🟢 Закрываем сокеты
            ::close(client_fd);
            ::close(info.backend_fd);
            // 🟢 Удаляем из карт
            connections_.erase(client_fd);
            timeouts_.erase(client_fd);
            // 🟢 Освобождаем SSL-объект
            if (is_ssl && info.ssl) {
                SSL_free(info.ssl);
            }
            remove_epoll_event(client_fd);
            LOG_INFO("[INFO] [server.cpp:612] TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, info.backend_fd);
        } else {
            // 🟢 ПРОВЕРЯЕМ, ЗАВЕРШЕН ЛИ ЧАНК
            if (chunked_complete_.find(client_fd) != chunked_complete_.end()) {
                if (chunked_complete_[client_fd]) {
                    // 🟢 Чанки завершены — можно закрыть соединение
                    LOG_INFO("[INFO] [server.cpp:620] ✅ Все чанки отправлены. Закрываем соединение для клиента {}", client_fd);
                    ::close(client_fd);
                    ::close(info.backend_fd);
                    connections_.erase(client_fd);
                    timeouts_.erase(client_fd);
                    if (is_ssl && info.ssl) {
                        SSL_free(info.ssl);
                    }
                    remove_epoll_event(client_fd);
                    LOG_INFO("[INFO] [server.cpp:627] TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, info.backend_fd);
                } else {
                    // 🟡 Чанки ещё не завершены — обновляем таймаут
                    timeouts_[client_fd] = time(nullptr);
                }
            } else {
                // 🟡 Неизвестное состояние — обновляем таймаут
                timeouts_[client_fd] = time(nullptr);
            }
        }
    }
}

SSL *Http1Server::get_ssl_for_fd(int fd) noexcept {
    for (const auto &conn : connections_) {
        if (conn.first == fd) {
            // Проверяем, что SSL-объект существует
            if (conn.second.ssl != nullptr) {
                return conn.second.ssl;
            } else {
                LOG_WARN("[WARN] [server.cpp:648] ⚠️ Найден fd={}, но SSL-объект равен nullptr", fd);
                return nullptr;
            }
        }
    }
    return nullptr;
}

bool Http1Server::forward_data(int from_fd, int to_fd, SSL *ssl) noexcept {
    LOG_DEBUG("[DEBUG] [server.cpp:657] 🔄 Начало forward_data(from_fd={}, to_fd={}, ssl={})", from_fd, to_fd, ssl ? "true" : "false");

    // 🟡 ЧТЕНИЕ ДАННЫХ
    char buffer[8192];
    bool use_ssl = (ssl != nullptr);
    ssize_t bytes_read = 0;

    if (use_ssl) {
        LOG_INFO("[INFO] [server.cpp:665] [READ] 🔐 Попытка чтения через SSL из fd={}", from_fd);
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read < 0) {
            int ssl_error = SSL_get_error(ssl, bytes_read);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                LOG_WARN("[WARN] [server.cpp:671] [READ] ⏳ SSL_ERROR_WANT_READ/WRITE — повторная попытка позже");
                return true;
            } else if (ssl_error == SSL_ERROR_ZERO_RETURN) {
                LOG_INFO("[INFO] [server.cpp:675] [READ] ✅ Клиент корректно закрыл соединение (SSL_ERROR_ZERO_RETURN)");
                return false;
            } else {
                LOG_ERROR("[ERROR] [server.cpp:679] [READ] ❌ Фатальная ошибка SSL: {}", ERR_error_string(ERR_get_error(), nullptr));
                return false;
            }
        } else if (bytes_read == 0) {
            LOG_WARN("[WARN] [server.cpp:684] [READ] ⚠️ SSL_read вернул 0 — возможно, соединение закрыто.");
            return false;
        } else {
            LOG_INFO("[INFO] [server.cpp:688] [READ] ✅ Прочитано {} байт через SSL", bytes_read);
        }
    } else {
        LOG_INFO("[INFO] [server.cpp:692] [READ] 📥 Попытка чтения через recv из fd={}", from_fd);
        bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
        if (bytes_read < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_WARN("[WARN] [server.cpp:697] [READ] ⏳ recv() вернул EAGAIN/EWOULDBLOCK — буфер пуст");
                return true;
            } else {
                LOG_ERROR("[ERROR] [server.cpp:701] [READ] ❌ recv ошибка: {} (errno={})", strerror(errno), errno);
                return false;
            }
        } else if (bytes_read == 0) {
            LOG_WARN("[WARN] [server.cpp:706] [READ] ⚠️ recv вернул 0 — соединение закрыто.");
            return false;
        } else {
            LOG_INFO("[INFO] [server.cpp:710] [READ] ✅ Прочитано {} байт через recv", bytes_read);
        }
    }

    if (bytes_read <= 0) {
        LOG_DEBUG("[DEBUG] [server.cpp:715] [READ] 🛑 Обработка ошибки чтения или закрытия соединения");
        if (use_ssl) {
            int ssl_error = SSL_get_error(ssl, bytes_read);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                LOG_WARN("[WARN] [server.cpp:720] [READ] ⏳ SSL_ERROR_WANT_READ/WRITE — повторная попытка позже");
                return true;
            } else {
                LOG_ERROR("[ERROR] [server.cpp:724] [READ] ❌ Фатальная ошибка SSL: {}", ERR_error_string(ERR_get_error(), nullptr));
                return false;
            }
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_WARN("[WARN] [server.cpp:729] [READ] ⏳ recv() вернул EAGAIN/EWOULDBLOCK — буфер пуст");
                return true;
            } else {
                LOG_ERROR("[ERROR] [server.cpp:733] [READ] ❌ Фатальная ошибка recv(): {}", strerror(errno));
                return false;
            }
        }
    }

    LOG_INFO("[INFO] [server.cpp:738] ✅ Получено {} байт данных от {} (fd={})", bytes_read, use_ssl ? "клиента" : "сервера", from_fd);

    // 🟢 ПРОСТАЯ ПЕРЕДАЧА ДАННЫХ БЕЗ CHUNKED PROCESSING
    SSL *target_ssl = get_ssl_for_fd(to_fd);
    LOG_DEBUG("[DEBUG] [server.cpp:743] [WRITE] 🎯 Целевой fd={} имеет SSL? {}", to_fd, target_ssl ? "да" : "нет");

    // 🟢 ПРОВЕРКА: ЕСТЬ ЛИ НЕЗАВЕРШЁННЫЕ ОТПРАВКИ?
    if (!pending_sends_.empty() && pending_sends_.find(to_fd) != pending_sends_.end() && !pending_sends_[to_fd].empty()) {
        LOG_INFO("[INFO] [server.cpp:748] [PENDING] 🕒 Есть незавершённые отправки для fd={}", to_fd);
        auto &pending_queue = pending_sends_[to_fd];
        while (!pending_queue.empty()) {
            auto &pending = pending_queue.front();
            if (pending.fd != to_fd) {
                LOG_WARN("[WARN] [server.cpp:753] [PENDING] 🗑️ Некорректный fd в очереди — пропускаем элемент");
                pending_queue.pop();
                continue;
            }
            // 🟠 ПОПЫТКА ОТПРАВИТЬ ОСТАВШИЕСЯ ДАННЫЕ
            LOG_DEBUG("[DEBUG] [server.cpp:758] [PENDING] 📤 Отправка оставшихся {} байт из {} (уже отправлено {})", pending.len - pending.sent, pending.len, pending.sent);
            ssize_t bytes_sent = 0;
            if (target_ssl != nullptr) {
                LOG_INFO("[INFO] [server.cpp:762] [PENDING] 🔐 SSL_write для fd={}", to_fd);
                bytes_sent = SSL_write(target_ssl, pending.data.get() + pending.sent, pending.len - pending.sent);
            } else {
                LOG_INFO("[INFO] [server.cpp:766] [PENDING] 📤 send() для fd={}", to_fd);
                bytes_sent = send(to_fd, pending.data.get() + pending.sent, pending.len - pending.sent, MSG_NOSIGNAL);
            }
            if (bytes_sent <= 0) {
                if (target_ssl != nullptr) {
                    int ssl_error = SSL_get_error(target_ssl, bytes_sent);
                    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                        LOG_WARN("[WARN] [server.cpp:773] [PENDING] ⏳ SSL_write требует повторной попытки — оставляем в очереди");
                        return true; // Оставляем в очереди
                    } else {
                        LOG_ERROR("[ERROR] [server.cpp:777] [PENDING] ❌ SSL_write фатальная ошибка: {}", ERR_error_string(ERR_get_error(), nullptr));
                        pending_queue.pop(); // Удаляем из очереди при фатальной ошибке
                        return false;
                    }
                } else {
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        LOG_WARN("[WARN] [server.cpp:783] [PENDING] ⏳ send() вернул EAGAIN/EWOULDBLOCK — буфер заполнен");
                        return true;
                    } else {
                        LOG_ERROR("[ERROR] [server.cpp:787] [PENDING] ❌ send() фатальная ошибка: {}", strerror(errno));
                        pending_queue.pop();
                        return false;
                    }
                }
            }
            pending.sent += static_cast<size_t>(bytes_sent);
            LOG_DEBUG("[DEBUG] [server.cpp:793] [PENDING] 📈 Отправлено {} байт, всего {}/{}", bytes_sent, pending.sent, pending.len);
            if (pending.sent >= pending.len) {
                LOG_SUCCESS("[SUCCESS] [server.cpp:796] ✅ Полностью отправлена порция данных ({} байт)", pending.len);
                pending_queue.pop(); // Успешно отправили всю порцию
            } else {
                LOG_INFO("[INFO] [server.cpp:800] [PENDING] 📥 Остались неотправленные данные: {} байт", pending.len - pending.sent);
                return true; // Остались неотправленные данные
            }
        }
    }

    // 🟢 ЗАПИСЬ НОВЫХ ДАННЫХ
    LOG_INFO("[INFO] [server.cpp:806] [NEW] 🆕 Создаём новый элемент для отправки {} байт на fd={}", bytes_read, to_fd);
    PendingSend new_send;
    new_send.fd = to_fd;
    new_send.len = static_cast<size_t>(bytes_read);
    new_send.sent = 0;
    new_send.data = std::make_unique<char[]>(new_send.len);
    std::memcpy(new_send.data.get(), buffer, new_send.len);

    // Пытаемся отправить сразу
    LOG_INFO("[INFO] [server.cpp:815] [NEW] 📤 Попытка немедленной отправки {} байт на fd={}", new_send.len, to_fd);
    ssize_t bytes_sent = 0;
    if (target_ssl != nullptr) {
        LOG_INFO("[INFO] [server.cpp:819] [NEW] 🔐 SSL_write для нового блока на fd={}", to_fd);
        bytes_sent = SSL_write(target_ssl, new_send.data.get(), new_send.len);
    } else {
        LOG_INFO("[INFO] [server.cpp:823] [NEW] 📤 send() для нового блока на fd={}", to_fd);
        bytes_sent = send(to_fd, new_send.data.get(), new_send.len, MSG_NOSIGNAL);
    }

    if (bytes_sent <= 0) {
        if (target_ssl != nullptr) {
            int ssl_error = SSL_get_error(target_ssl, bytes_sent);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                LOG_WARN("[WARN] [server.cpp:830] [NEW] ⏳ SSL_write требует повторной попытки — добавляем в очередь");
                pending_sends_[to_fd].push(std::move(new_send));
                return true;
            } else {
                LOG_ERROR("[ERROR] [server.cpp:834] [NEW] ❌ SSL_write фатальная ошибка: {}", ERR_error_string(ERR_get_error(), nullptr));
                return false;
            }
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_WARN("[WARN] [server.cpp:839] [NEW] ⏳ send() вернул EAGAIN/EWOULDBLOCK — буфер заполнен");
                pending_sends_[to_fd].push(std::move(new_send));
                return true;
            } else {
                LOG_ERROR("[ERROR] [server.cpp:843] [NEW] ❌ send() фатальная ошибка: {}", strerror(errno));
                return false;
            }
        }
    }

    // Успешно отправили всё сразу
    LOG_SUCCESS("[SUCCESS] [server.cpp:848] 🎉 Успешно передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
    LOG_DEBUG("[DEBUG] [server.cpp:849] 🔄 Конец forward_data — соединение остаётся активным");
    return true;
}

bool Http1Server::add_epoll_event(int fd, uint32_t events) noexcept {
    struct epoll_event ev;
    ev.events = events;
    ev.data.fd = fd;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) == -1) {
        LOG_ERROR("[ERROR] [server.cpp:859] ❌ Не удалось добавить fd={} в epoll: {}", fd, strerror(errno));
        return false;
    }
    return true;
}

bool Http1Server::remove_epoll_event(int fd) noexcept {
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_DEL, fd, nullptr) == -1) {
        LOG_ERROR("[ERROR] [server.cpp:866] ❌ Не удалось удалить fd={} из epoll: {}", fd, strerror(errno));
        return false;
    }
    return true;
}