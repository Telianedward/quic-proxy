/**
 * @file server.cpp
 * @brief Реализация HTTP/1.1 сервера.
 *
 * Обеспечивает обработку простых HTTP/1.1 запросов (GET, HEAD) без TLS.
 * Используется для тестирования сетевой связности и отладки прокси.
 * Логирует все ключевые события: подключение, получение данных, отправка ответа.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-24
 * @version 1.0
 * @license MIT
 */
#include "../../include/http1/server.hpp"
#include <cstring>
#include <algorithm>
#include <sstream>
#include <poll.h>

// === Реализация методов класса Http1Server ===

Http1Server::Http1Server(int port, const std::string& backend_ip, int backend_port)
    : listen_fd_(-1), port_(port), backend_ip_(backend_ip), backend_port_(backend_port) {}

bool Http1Server::run() {
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
    addr.sin_port = htons(port_);
    if (bind(listen_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Не удалось привязать сокет к порту {}: {}", port_, strerror(errno));
        ::close(listen_fd_);
        return false;
    }

    // Начинаем прослушивать
    if (listen(listen_fd_, SOMAXCONN) < 0) {
        LOG_ERROR("Не удалось начать прослушивание: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }

    LOG_INFO("HTTP/1.1 сервер запущен на порту {}", port_);

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
                ::close(client_fd);
                connections_.erase(client_fd);
                timeouts_.erase(it++);
                LOG_INFO("TCP-соединение закрыто по таймауту: клиент {}", client_fd);
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

    LOG_INFO("HTTP/1.1 сервер остановлен.");
    return true;
}

void Http1Server::stop() {
    running_ = false;
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
    LOG_INFO("✅ Новое HTTP/1.1 соединение: бэкенд {}:{}", backend_ip_, backend_port_);
    return backend_fd;
}

void Http1Server::handle_new_connection() noexcept {
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

    // Подключаемся к серверу в России
    int backend_fd = connect_to_backend();
    if (backend_fd == -1) {
        LOG_ERROR("❌ Не удалось подключиться к серверу в России. Закрываем соединение с клиентом.");
        ::close(client_fd);
        return; // ❗ ВАЖНО: НЕ ДОБАВЛЯТЬ В connections_!
    }

    // Сохраняем соединение
    connections_[client_fd] = backend_fd;
    timeouts_[client_fd] = time(nullptr); // Устанавливаем таймаут
}


// Замените метод handle_io_events()
void Http1Server::handle_io_events() noexcept {
    auto connections_copy = connections_;
    for (const auto& [client_fd, backend_fd] : connections_copy) {
        if (backend_fd == -1) { // 👈 Защита от некорректных дескрипторов
            LOG_WARN("Некорректный backend_fd (-1) для client_fd={}. Закрываем соединение.", client_fd);
            ::close(client_fd);
            connections_.erase(client_fd);
            timeouts_.erase(client_fd);
            continue;
        }

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
            LOG_INFO("📥 Получены данные от клиента {}", client_fd);
            if (!forward_data(client_fd, backend_fd)) {
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
            } else {
                timeouts_[client_fd] = time(nullptr);
            }
        }

        // Передача данных от сервера к клиенту
        if (FD_ISSET(backend_fd, &read_fds)) {
            LOG_INFO("📤 Получены данные от сервера {}", backend_fd);
            if (!forward_data(backend_fd, client_fd)) {
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
            } else {
                timeouts_[client_fd] = time(nullptr);
            }
        }
    }
}
bool Http1Server::forward_data(int from_fd, int to_fd) noexcept {
    // Если есть незавершённая отправка — продолжаем её
    if (pending_sends_.find(from_fd) != pending_sends_.end()) {
        auto& ps = pending_sends_[from_fd];
        ssize_t bytes_sent = send(ps.fd, ps.ptr + ps.sent, ps.len - ps.sent, 0);
        if (bytes_sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                LOG_DEBUG("Буфер отправки заполнен, продолжим позже (отправлено {}/{} байт)", ps.sent, ps.len);
                return true; // Сохраняем соединение
            } else {
                LOG_ERROR("Ошибка отправки данных: {}", strerror(errno));
                pending_sends_.erase(from_fd);
                return false;
            }
        }
        ps.sent += bytes_sent;
        LOG_DEBUG("Отправлено {} байт из {} (осталось {})", bytes_sent, ps.len, ps.len - ps.sent);

        if (ps.sent >= ps.len) {
            // Отправка завершена
            pending_sends_.erase(from_fd);
            LOG_INFO("✅ Полностью отправлено {} байт на бэкенд", ps.len);
            return true;
        }
        // Ещё не всё отправлено — продолжаем
        return true;
    }

    // Нет незавершённой отправки — читаем новые данные
    char buffer[8192];
    ssize_t bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
    if (bytes_read > 0) {
        // Создаём новую запись в pending_sends_
        pending_sends_[from_fd] = {
            .fd = to_fd,
            .ptr = buffer,
            .len = static_cast<size_t>(bytes_read),
            .sent = 0
        };

        // Пытаемся отправить сразу
        return forward_data(from_fd, to_fd); // Рекурсивный вызов — безопасен, так как не зацикливается
    } else if (bytes_read == 0) {
        // Клиент закрыл соединение
        return false;
    } else {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            LOG_ERROR("Ошибка чтения данных: {}", strerror(errno));
            return false;
        }
        return true;
    }
}
std::string Http1Server::generate_index_html() const {
    return R"(<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>ErosJ</title>
    <link rel="stylesheet" href="/css/main.css">
</head>
<body>
    <h1>Привет из России!</h1>
    <p>Это HTTP/1.1 сервер на порту 8587.</p>
    <script src="/js/main.js"></script>
</body>
</html>)";
}

std::string Http1Server::generate_favicon() const {
    // Здесь должен быть бинарный контент favicon.ico
    // Для примера используем пустую строку
    return "";
}

std::string Http1Server::generate_main_css() const {
    return "body { background: #eee; font-family: Arial, sans-serif; }";
}

std::string Http1Server::generate_main_js() const {
    return "console.log('Hello from Russia!');";
}