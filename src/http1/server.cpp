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

// Конструктор
Http1Server::Http1Server(int port, const std::string& backend_ip, int backend_port)
    : listen_fd_(-1), port_(port), backend_ip_(backend_ip), backend_port_(backend_port) {}

// 👇 Сделали parse_http_request статическим методом класса
HttpRequest Http1Server::parse_http_request(const std::string& request_str) {
    HttpRequest req;
    size_t pos = request_str.find("\r\n");
    if (pos != std::string::npos) {
        std::string first_line = request_str.substr(0, pos);
        std::istringstream iss(first_line);
        iss >> req.method >> req.url >> req.version;
    }

    // Парсим заголовки
    size_t start = pos + 2; // Пропускаем \r\n
    while (start < request_str.size()) {
        size_t end = request_str.find("\r\n", start);
        if (end == std::string::npos) break;

        std::string line = request_str.substr(start, end - start);
        if (line.empty()) { // Пустая строка — конец заголовков
            req.body = request_str.substr(end + 2); // Тело запроса начинается после \r\n\r\n
            break;
        }

        size_t colon_pos = line.find(':');
        if (colon_pos != std::string::npos) {
            std::string key = line.substr(0, colon_pos);
            std::string value = line.substr(colon_pos + 1);
            // Удаляем пробелы в начале и конце
            key.erase(0, key.find_first_not_of(" \t"));
            key.erase(key.find_last_not_of(" \t") + 1);
            value.erase(0, value.find_first_not_of(" \t"));
            value.erase(value.find_last_not_of(" \t") + 1);
            req.headers[key] = value;
        }

        start = end + 2;
    }

    return req;
}

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

// Метод connect_to_backend()
int Http1Server::connect_to_backend() noexcept { // 👈 Это должно быть здесь
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

        // Передача данных от клиента к серверу
        if (FD_ISSET(client_fd, &read_fds)) {
            LOG_INFO("📥 Получены данные от клиента {}", client_fd);
            LOG_DEBUG("🔄 Вызов forward_data(client_fd={}, backend_fd={})", client_fd, backend_fd);

            // Читаем данные от клиента
            char buffer[8192];
            ssize_t bytes_read = recv(client_fd, buffer, sizeof(buffer), 0);
            if (bytes_read > 0) {
                std::string request_str(buffer, bytes_read); // 👈 Объявление переменной
                LOG_INFO("✅  ( 2 )  Полный запрос от клиента ({} байт):", bytes_read);
            if (!request_str.empty()) {
                LOG_DEBUG("📝 Содержимое запроса:\n{}", request_str);
            } else {
                LOG_DEBUG("📝 Запрос пустой");
            }

                // 👇 Передаём request_str в forward_data
                bool keep_alive = forward_data(client_fd, backend_fd, request_str);
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
            } else if (bytes_read == 0) {
                LOG_INFO("✅  ( 3 )  Полный запрос от клиента (0 байт):");
                LOG_INFO("🔚 Клиент (client_fd={}) закрыл соединение (recv вернул 0)", client_fd);
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                LOG_INFO("TCP-соединение закрыто (блок 2):: клиент {}, backend_fd={}", client_fd, backend_fd);
            } else {
                LOG_ERROR("❌ Ошибка чтения данных от клиента (client_fd={}): {}", client_fd, strerror(errno));
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
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
    LOG_DEBUG("🔄 Начало forward_data(from_fd={}, to_fd=*) — без request_str", from_fd);

    char buffer[8192];
    std::string data;

    // Получаем данные от источника
    ssize_t bytes_read;
    do {
        bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
        if (bytes_read > 0) {
            data.append(buffer, bytes_read);
        }
    } while (bytes_read > 0);

    if (data.empty()) {
        LOG_WARN("⚠️ Получены пустые данные от fd={}", from_fd);
        return false;
    }

    LOG_DEBUG("📥 Получено {} байт от fd={}", data.size(), from_fd);

    // Отправляем данные получателю
    ssize_t total_sent = 0;
    while (total_sent < static_cast<ssize_t>(data.size())) {
        size_t remaining = static_cast<size_t>(data.size() - total_sent);
        ssize_t bytes_sent = send(to_fd, data.c_str() + total_sent, remaining, 0);
        if (bytes_sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else {
                LOG_ERROR("❌ Ошибка отправки данных на fd={}: {}", to_fd, strerror(errno));
                ::close(from_fd);
                ::close(to_fd);
                return false;
            }
        }
        total_sent += bytes_sent;
    }

    LOG_DEBUG("📤 Отправлено {} байт на fd={}", data.size(), to_fd);
    return true;
}

// --- Реализация метода без request_str ---
bool Http1Server::forward_data(int from_fd, int to_fd) noexcept {
    LOG_DEBUG("🔄 Начало forward_data(from_fd={}, to_fd=*) — без request_str", from_fd);

    char buffer[8192];
    std::string data;

    ssize_t bytes_read;
    do {
        bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
        if (bytes_read > 0) {
            data.append(buffer, bytes_read);
        }
    } while (bytes_read > 0);

    if (data.empty()) {
        LOG_WARN("⚠️ Получены пустые данные от fd={}", from_fd);
        return false;
    }

    LOG_DEBUG("📥 Получено {} байт от fd={}", data.size(), from_fd);

    ssize_t total_sent = 0;
    while (total_sent < static_cast<ssize_t>(data.size())) {
        size_t remaining = static_cast<size_t>(data.size() - total_sent);
        ssize_t bytes_sent = send(to_fd, data.c_str() + total_sent, remaining, 0);
        if (bytes_sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            } else {
                LOG_ERROR("❌ Ошибка отправки данных на fd={}: {}", to_fd, strerror(errno));
                ::close(from_fd);
                ::close(to_fd);
                return false;
            }
        }
        total_sent += bytes_sent;
    }

    LOG_DEBUG("📤 Отправлено {} байт на fd={}", data.size(), to_fd);
    return true;
}