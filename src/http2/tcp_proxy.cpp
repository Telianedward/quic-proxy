// src/tcp_proxy.cpp
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
#include <cstring>
#include <algorithm>

TcpProxy::TcpProxy(int listen_port, const std::string& backend_ip, int backend_port)
    : listen_fd_(-1), backend_port_(backend_port), backend_ip_(backend_ip), listen_port_(listen_port) {}

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

    LOG_INFO("TCP-прокси запущен на порту {} для {}:{}",
             listen_port_, backend_ip_, backend_port_);

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

        // Проверка таймаутов
        time_t now = time(nullptr);
        for (auto it = timeouts_.begin(); it != timeouts_.end(); ) {
            if (now - it->second > 30) { // Таймаут 30 секунд
                int client_fd = it->first;
                int backend_fd = connections_[client_fd];
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(it++);
                LOG_INFO("TCP-соединение закрыто по таймауту: клиент {}, бэкенд {}", client_fd, backend_fd);
            } else {
                ++it;
            }
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
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        LOG_ERROR("Не удалось создать сокет для подключения к бэкенду: {}", strerror(errno));
        return -1;
    }

    if (!set_nonblocking(sock)) {
        LOG_ERROR("Не удалось установить неблокирующий режим для сокета бэкенда");
        ::close(sock);
        return -1;
    }

    struct sockaddr_in backend_addr{};
    backend_addr.sin_family = AF_INET;
    inet_pton(AF_INET, backend_ip_.c_str(), &backend_addr.sin_addr);
    backend_addr.sin_port = htons(backend_port_);

    // Подключаемся к бэкенду
    if (::connect(sock, (struct sockaddr*)&backend_addr, sizeof(backend_addr)) < 0) {
        if (errno != EINPROGRESS) { // EINPROGRESS ожидаемо для неблокирующего сокета
            LOG_ERROR("Не удалось подключиться к бэкенду {}: {}", backend_ip_, strerror(errno));
            ::close(sock);
            return -1;
        }
    }

    return sock;
}

// src/http2/tcp_proxy.cpp
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

    // Создаём SSL-объект для клиента
    SSL *ssl_client = SSL_new(ssl_ctx_);
    if (!ssl_client) {
        LOG_ERROR("Не удалось создать SSL-объект для клиента");
        ::close(client_fd);
        return;
    }
    SSL_set_fd(ssl_client, client_fd);

    // Устанавливаем TLS-соединение с клиентом
    int ret = SSL_accept(ssl_client);
    if (ret <= 0) {
        LOG_ERROR("SSL_accept вернул {}", ret);
        ERR_print_errors_fp(stderr);
        SSL_free(ssl_client);
        ::close(client_fd);
        return;
    }

    // Подключаемся к бэкенду (без TLS)
    int backend_fd = connect_to_backend();
    if (backend_fd == -1) {
        SSL_free(ssl_client);
        ::close(client_fd);
        return;
    }

    // Сохраняем соединение
    connections_[client_fd] = backend_fd;
    timeouts_[client_fd] = time(nullptr); // Устанавливаем таймаут
    LOG_INFO("Новое TLS-соединение: клиент {}:{}, бэкенд {}:{}",
             inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
             backend_ip_, backend_port_);
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

        // Передача данных от клиента к бэкенду
        if (FD_ISSET(client_fd, &read_fds)) {
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

        // Передача данных от бэкенда к клиенту
        if (FD_ISSET(backend_fd, &read_fds)) {
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
        LOG_DEBUG("Передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
        return true;
    } else if (bytes_read == 0) {
        // Клиент или бэкенд закрыл соединение
        return false;
    } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("Ошибка чтения данных: {}", strerror(errno));
            return false;
        }
        return true; // Нет данных, продолжаем
    }
}