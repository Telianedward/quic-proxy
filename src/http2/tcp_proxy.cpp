/**
 * @file tcp_proxy.cpp
 * @brief Реализация TCP-прокси для HTTP/2 и HTTP/1.1.
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
#include "../../include/http2/tcp_proxy.hpp"
#include "../../include/config.h"
#include <cstring>
#include <algorithm>

const AppConfig app_config{};

TcpProxy::TcpProxy(int listen_port, const std::string& backend_ip, int backend_port)
    : listen_fd_(-1),
      listen_port_(listen_port),
      backend_port_(backend_port),
      backend_ip_(backend_ip),
      running_(true),
      connections_{},
      timeouts_{},
      ssl_ctx_(nullptr) {
    // === Инициализация OpenSSL ===
    if (!OPENSSL_init_ssl(OPENSSL_INIT_LOAD_CONFIG, nullptr)) {
        LOG_ERROR("❌ Не удалось инициализировать OpenSSL");
        ERR_print_errors_fp(stderr);
        return;
    }

    // Создаем контекст для сервера
    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    if (!ssl_ctx_) {
        LOG_ERROR("❌ Не удалось создать SSL-контекст");
        ERR_print_errors_fp(stderr);
        return;
    }

    // Настройка SSL-контекста
    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_2_VERSION);

    // Загружаем сертификат и ключ
    auto fullchain_path = std::string(AppConfig::SSL_DIR) + "/" + std::string(AppConfig::FULLCHAIN_FILE);
    if (SSL_CTX_use_certificate_file(ssl_ctx_, fullchain_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("❌ Не удалось загрузить сертификат");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    auto privkey_path = std::string(AppConfig::SSL_DIR) + "/" + std::string(AppConfig::PRIVEKEY_FILE);
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, privkey_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("❌ Не удалось загрузить приватный ключ");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }

    // Проверяем соответствие ключа и сертификата
    if (!SSL_CTX_check_private_key(ssl_ctx_)) {
        LOG_ERROR("❌ Ключ и сертификат не совпадают");
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }

    LOG_INFO("✅ SSL-контекст успешно создан и настроен");
}

TcpProxy::~TcpProxy() {
    if (ssl_ctx_) {
        SSL_CTX_free(ssl_ctx_);
    }
    if (listen_fd_ != -1) {
        ::close(listen_fd_);
    }
}

bool TcpProxy::run() {
    // Создаем сокет для прослушивания
    listen_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd_ < 0) {
        LOG_ERROR("Не удалось создать сокет для прослушивания: {}", strerror(errno));
        return false;
    }

    // Устанавливаем опции
    int opt = 1;
    if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("setsockopt SO_REUSEADDR failed: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }
    if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("setsockopt SO_REUSEPORT failed: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }

    // Устанавливаем неблокирующий режим
    if (!set_nonblocking(listen_fd_)) {
        LOG_ERROR("Не удалось установить неблокирующий режим для сокета прослушивания");
        ::close(listen_fd_);
        return false;
    }

    // Привязываемся к адресу и порту
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port_);
    if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Не удалось привязать сокет к порту {}: {}", listen_port_, strerror(errno));
        ::close(listen_fd_);
        return false;
    }

    // Начинаем прослушивать
    if (listen(listen_fd_, SOMAXCONN) < 0) {
        LOG_ERROR("Не удалось начать прослушивание: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }

    LOG_INFO("TCP-прокси запущен на порту {} для {}:{}", listen_port_, backend_ip_, backend_port_);

    // Главный цикл
    while (running_) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);

        // Добавляем сокет прослушивания
        FD_SET(listen_fd_, &read_fds);

        // Добавляем все активные соединения
        for (const auto& [client_fd, backend_fd] : connections_) {
            FD_SET(client_fd, &read_fds);
            FD_SET(backend_fd, &read_fds);
        }

        // Выбираем максимальный дескриптор
        int max_fd = listen_fd_;
        for (const auto& [client_fd, backend_fd] : connections_) {
            max_fd = std::max({max_fd, client_fd, backend_fd});
        }

        timeval timeout{.tv_sec = 1, .tv_usec = 0}; // Таймаут 1 секунда
        int activity = select(max_fd + 1, &read_fds, &write_fds, nullptr, &timeout);
        if (activity < 0 && errno != EINTR) {
            LOG_ERROR("Ошибка select: {}", strerror(errno));
            continue;
        }

        if (activity > 0) {
            // Обработка новых соединений
            if (FD_ISSET(listen_fd_, &read_fds)) {
                handle_new_connection();
            }

            // Обработка данных от клиентов и сервера
            handle_io_events();
        }
    }

    // Закрываем все соединения
    for (const auto& [client_fd, backend_fd] : connections_) {
        ::close(client_fd);
        ::close(backend_fd);
    }
    connections_.clear();

    if (listen_fd_ != -1) {
        ::close(listen_fd_);
    }

    LOG_INFO("TCP-прокси остановлен.");
    return true;
}

void TcpProxy::stop() {
    running_ = false;
}

bool TcpProxy::set_nonblocking(int fd) noexcept {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

int TcpProxy::connect_to_backend() noexcept {
    int backend_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (backend_fd < 0) {
        LOG_ERROR("Не удалось создать сокет для подключения к серверу в России: {}", strerror(errno));
        return -1;
    }

    // Устанавливаем неблокирующий режим
    if (!set_nonblocking(backend_fd)) {
        LOG_ERROR("Не удалось установить неблокирующий режим для сокета сервера");
        ::close(backend_fd);
        return -1;
    }

    // Устанавливаем адрес сервера
    struct sockaddr_in backend_addr{};
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(backend_port_);
    if (inet_pton(AF_INET, backend_ip_.c_str(), &backend_addr.sin_addr) <= 0) {
        LOG_ERROR("Не удалось преобразовать IP-адрес сервера: {}", backend_ip_);
        ::close(backend_fd);
        return -1;
    }

    // Подключаемся к серверу
    if (connect(backend_fd, (struct sockaddr*)&backend_addr, sizeof(backend_addr)) < 0) {
        if (errno != EINPROGRESS) {
            LOG_ERROR("Не удалось подключиться к серверу в России: {}", strerror(errno));
            ::close(backend_fd);
            return -1;
        }
    }

    LOG_INFO("✅ Новое TLS-соединение: бэкенд {}:{}", backend_ip_, backend_port_);
    return backend_fd;
}

void TcpProxy::handle_new_connection() noexcept {
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(listen_fd_, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("Ошибка accept: {}", strerror(errno));
        }
        return;
    }

    // Устанавливаем неблокирующий режим
    if (!set_nonblocking(client_fd)) {
        LOG_ERROR("Не удалось установить неблокирующий режим для клиента");
        ::close(client_fd);
        return;
    }

    // 👇 ЛОГИРУЕМ АДРЕС КЛИЕНТА И ПОРТ
    std::string client_ip_str = inet_ntoa(client_addr.sin_addr);
    uint16_t client_port_num = ntohs(client_addr.sin_port);
    LOG_INFO("🟢 Новое соединение от клиента: {}:{} (fd={})", client_ip_str, client_port_num, client_fd);

    // Создаем SSL-объект
    SSL *ssl = SSL_new(ssl_ctx_);
    if (!ssl) {
        LOG_ERROR("Не удалось создать SSL-объект");
        ::close(client_fd);
        return;
    }

    // Устанавливаем сокет для SSL
    if (SSL_set_fd(ssl, client_fd) != 1) {
        LOG_ERROR("Не удалось установить сокет для SSL");
        SSL_free(ssl);
        ::close(client_fd);
        return;
    }

    // Устанавливаем неблокирующий режим для SSL
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    // Подключаемся к серверу в России
    int backend_fd = connect_to_backend();
    if (backend_fd == -1) {
        LOG_ERROR("Не удалось подключиться к серверу в России");
        SSL_free(ssl);
        ::close(client_fd);
        return;
    }

    // Сохраняем соединение
    connections_[client_fd] = backend_fd;
    timeouts_[client_fd] = time(nullptr); // Устанавливаем таймаут
}

void TcpProxy::handle_io_events() noexcept {
    // Создаем копию карты, чтобы избежать проблем при изменении во время итерации
    auto connections_copy = connections_;
    for (const auto& [client_fd, backend_fd] : connections_copy) {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(client_fd, &read_fds);
        FD_SET(backend_fd, &read_fds);
        int max_fd = std::max(client_fd, backend_fd);
        timeval timeout{.tv_sec = 0, .tv_usec = 10000}; // 10 мс
        int activity = select(max_fd + 1, &read_fds, &write_fds, nullptr, &timeout);
        if (activity <= 0) {
            continue;
        }

        // Передача данных от клиента к серверу
        if (FD_ISSET(client_fd, &read_fds)) {
            // 👇 ЛОГИРУЕМ ПОЛУЧЕНИЕ ДАННЫХ ОТ КЛИЕНТА
            LOG_INFO("📥 Получены данные от клиента {}", client_fd);
            if (!forward_data(client_fd, backend_fd)) {
                // Соединение закрыто
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
            } else {
                // Обновляем таймаут
                timeouts_[client_fd] = time(nullptr);
            }
        }

        // Передача данных от сервера к клиенту
        if (FD_ISSET(backend_fd, &read_fds)) {
            // 👇 ЛОГИРУЕМ ПОЛУЧЕНИЕ ДАННЫХ ОТ СЕРВЕРА
            LOG_INFO("📤 Получены данные от сервера {}", backend_fd);
            if (!forward_data(backend_fd, client_fd)) {
                // Соединение закрыто
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
            } else {
                // Обновляем таймаут
                timeouts_[client_fd] = time(nullptr);
            }
        }
    }
}

bool TcpProxy::forward_data(int from_fd, int to_fd) noexcept {
    char buffer[8192];
    ssize_t bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
    if (bytes_read > 0) {
        // 👇 ЛОГИРУЕМ ПОЛУЧЕННЫЕ ДАННЫЕ ОТ КЛИЕНТА
        LOG_INFO("📥 Получено {} байт от клиента {}", bytes_read, from_fd);
        std::string request_str(buffer, bytes_read);
        LOG_DEBUG("Запрос: {}", request_str);

        // Отправляем данные на другой сокет
        ssize_t total_sent = 0;
        while (total_sent < bytes_read) {
            ssize_t bytes_sent = send(to_fd, buffer + total_sent, bytes_read - total_sent, 0);
            if (bytes_sent < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Буфер отправки заполнен — попробуем позже
                    LOG_DEBUG("Буфер отправки заполнен, попробуем позже");
                    return true; // Соединение активно, продолжаем
                } else {
                    LOG_ERROR("Ошибка отправки данных: {}", strerror(errno));
                    return false;
                }
            }
            total_sent += bytes_sent;
        }

        // 👇 ЛОГИРУЕМ ОТПРАВЛЕННЫЕ ДАННЫЕ НА БЭКЕНД
        LOG_INFO("📤 Отправлено {} байт на бэкенд {}", total_sent, to_fd);
        LOG_DEBUG("Отправлено: {}", request_str);

        return true;
    } else if (bytes_read == 0) {
        // Клиент или сервер закрыл соединение
        return false;
    } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("Ошибка чтения данных: {}", strerror(errno));
            return false;
        }
        return true; // Нет данных, продолжаем
    }
}
