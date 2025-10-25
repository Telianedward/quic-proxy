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
        LOG_DEBUG("⏳ Подключение к бэкенду {}:{} в процессе...", backend_ip_, backend_port_);

        // Ждём завершения подключения
        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(backend_fd, &write_fds);

        timeval timeout{.tv_sec = 5, .tv_usec = 0}; // Таймаут 5 секунд
        int activity = select(backend_fd + 1, nullptr, &write_fds, nullptr, &timeout);
        if (activity <= 0) {
            LOG_ERROR("❌ Таймаут подключения к бэкенду {}:{} (errno={})", backend_ip_, backend_port_, errno);
            ::close(backend_fd);
            return -1;
        }

        // Проверяем, успешно ли подключились
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(backend_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
            LOG_ERROR("❌ Не удалось получить статус подключения: {}", strerror(errno));
            ::close(backend_fd);
            return -1;
        }

        if (error != 0) {
            LOG_ERROR("❌ Ошибка подключения к бэкенду {}:{}: {}", backend_ip_, backend_port_, strerror(error));
            ::close(backend_fd);
            return -1;
        }

        LOG_INFO("✅ Подключение к бэкенду {}:{} успешно установлено", backend_ip_, backend_port_);
    } else {
        LOG_INFO("✅ Подключение к бэкенду {}:{} успешно установлено (мгновенно)", backend_ip_, backend_port_);
    }

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


        // // Передача данных от клиента к серверу
        // if (FD_ISSET(client_fd, &read_fds)) {
        //     LOG_INFO("📥 Получены данные от клиента {}", client_fd);
        //     if (!forward_data(client_fd, backend_fd)) {
        //         ::close(client_fd);
        //         ::close(backend_fd);
        //         connections_.erase(client_fd);
        //         timeouts_.erase(client_fd);
        //         LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
        //     } else {
        //         timeouts_[client_fd] = time(nullptr);
        //     }
        // }

        // Передача данных от клиента к серверу
        if (FD_ISSET(client_fd, &read_fds)) {
            LOG_INFO("📥 Получены данные от клиента {}", client_fd);
            LOG_DEBUG("🔄 Вызов forward_data(client_fd={}, backend_fd={})", client_fd, backend_fd);

            bool keep_alive = forward_data(client_fd, backend_fd);

            LOG_DEBUG("⬅️ forward_data вернул: {}", keep_alive ? "true" : "false");

            if (!keep_alive) {
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
            } else {
                timeouts_[client_fd] = time(nullptr);
                LOG_DEBUG("⏱️ Таймаут обновлён для client_fd={}: {}", client_fd, timeouts_[client_fd]);
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
    LOG_DEBUG("🔄 Начало forward_data(from_fd={}, to_fd={})", from_fd, to_fd);

    char buffer[8192];
    LOG_DEBUG("📦 Буфер создан: размер {} байт", sizeof(buffer));

    ssize_t bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);

    LOG_DEBUG("📥 recv(from_fd={}, buffer_size={}) вернул bytes_read={}", from_fd, sizeof(buffer), bytes_read);

    if (bytes_read > 0) {
        LOG_INFO("✅ Получено {} байт данных от клиента (from_fd={})", bytes_read, from_fd);
    // 👇 ЛОГИРУЕМ СОДЕРЖИМОЕ (ВСЁ, ЧТО ПОЛУЧИЛИ)
    std::string received_data(buffer, static_cast<size_t>(bytes_read));

    // Заменяем непечатаемые символы на '?' для читаемости
    for (char& c : received_data) {
        if (c < 32 && c != '\n' && c != '\r' && c != '\t') c = '?';
    }

    LOG_DEBUG("📥 Получено от бэкенда ({} байт):\n{}", bytes_read, received_data);
        ssize_t total_sent = 0;
        LOG_DEBUG("📌 total_sent инициализирован: {}", total_sent);

        while (total_sent < bytes_read) {
            size_t remaining = static_cast<size_t>(bytes_read - total_sent);
            LOG_DEBUG("⏳ Осталось отправить {} байт (total_sent={}, bytes_read={})", remaining, total_sent, bytes_read);

            ssize_t bytes_sent = send(from_fd, buffer + total_sent, remaining, 0);
            LOG_DEBUG("📤 send(from_fd={}, offset={}, size={}) вернул bytes_sent={}",
                      from_fd, total_sent, remaining, bytes_sent);

                if (bytes_sent > 0) {
                    std::string sent_chunk(buffer + total_sent, static_cast<size_t>(bytes_sent));
                    // Убираем непечатаемые символы для читаемости (опционально)
                    for (char& c : sent_chunk) {
                        if (c < 32 && c != '\n' && c != '\r' && c != '\t') c = '?';
                    }
                    LOG_DEBUG("📦 Отправлено содержимое (первые {} байт):\n{}",
                            std::min<size_t>(bytes_sent, sent_chunk.size()),
                            sent_chunk.substr(0, std::min<size_t>(bytes_sent, sent_chunk.size())));
                }
                if (bytes_sent < 0)
                {
                    LOG_ERROR("❌ send() вернул ошибку: errno={} ({})", errno, strerror(errno));

                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        LOG_WARN("⏸️ Буфер отправки заполнен, попробуем позже. Отправлено {}/{} байт", total_sent, bytes_read);
                        return true;
                    } else {
                        LOG_ERROR("💥 Критическая ошибка отправки данных: {}", strerror(errno));
                        return false;
                    }
                }

            total_sent += bytes_sent;
            LOG_DEBUG("📈 total_sent обновлён: {} (отправлено {} байт)", total_sent, bytes_sent);

            if (bytes_sent == 0) {
                LOG_WARN("⚠️ send() вернул 0 — возможно, соединение закрыто на стороне получателя");
                break;
            }
        }

        LOG_SUCCESS("🎉 Успешно передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
        return true;

    } else if (bytes_read == 0) {
        LOG_INFO("🔚 Клиент (from_fd={}) закрыл соединение (recv вернул 0)", from_fd);
        return false;

    } else {
        LOG_DEBUG("⏸️ recv() вернул -1: errno={} ({})", errno, strerror(errno));

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            LOG_DEBUG("🔁 recv() вернул EAGAIN/EWOULDBLOCK — это нормально в неблокирующем режиме");
            return true;
        } else {
            LOG_ERROR("❌ Ошибка чтения данных от клиента (from_fd={}): {}", from_fd, strerror(errno));
            return false;
        }
    }
}