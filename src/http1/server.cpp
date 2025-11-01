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

Http1Server::Http1Server(int port, const std::string &backend_ip, int backend_port)
    : listen_fd_(-1), port_(port), backend_ip_(backend_ip), backend_port_(backend_port),
      ssl_ctx_(nullptr)
{
    // Инициализация OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    // Создание SSL-контекста
    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
    // Добавьте это сразу после SSL_CTX_new()
    SSL_CTX_set_min_proto_version(ssl_ctx_, TLS1_VERSION); // Минимум TLS 1.0
    SSL_CTX_set_max_proto_version(ssl_ctx_, TLS1_3_VERSION); // Максимум TLS 1.3
    if (!ssl_ctx_)
    {
        LOG_ERROR("❌ Не удалось создать SSL-контекст");
        return;
    }
    // 🟢 ИСПОЛЬЗУЕМ ПОДГОТОВЛЕННЫЕ ФАЙЛЫ ИЗ /opt/quic-proxy/
    const char *cert_path = "/opt/quic-proxy/fullchain.pem";
    const char *key_path = "/opt/quic-proxy/privkey.pk8";
    // 🟡 ПРОВЕРКА СУЩЕСТВОВАНИЯ ФАЙЛОВ
    if (access(cert_path, R_OK) != 0)
    {
        LOG_ERROR("❌ Сертификат не найден или недоступен: {}", cert_path);
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    if (access(key_path, R_OK) != 0)
    {
        LOG_ERROR("❌ Приватный ключ не найден или недоступен: {}", key_path);
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    // Загрузка сертификата и ключа
    if (SSL_CTX_use_certificate_file(ssl_ctx_, cert_path, SSL_FILETYPE_PEM) <= 0)
    {
        LOG_ERROR("❌ Не удалось загрузить сертификат: {}", ERR_error_string(ERR_get_error(), nullptr));
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    if (SSL_CTX_use_PrivateKey_file(ssl_ctx_, key_path, SSL_FILETYPE_PEM) <= 0)
    {
        LOG_ERROR("❌ Не удалось загрузить приватный ключ: {}", ERR_error_string(ERR_get_error(), nullptr));
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    // Проверка соответствия ключа и сертификата
    if (!SSL_CTX_check_private_key(ssl_ctx_))
    {
        LOG_ERROR("❌ Ключ и сертификат не совпадают");
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
        return;
    }
    LOG_INFO("✅ SSL-контекст успешно создан и настроен");
}

Http1Server::~Http1Server()
{
    if (ssl_ctx_)
    {
        SSL_CTX_set_max_send_fragment(ssl_ctx_, 16384); // 16KB фрагменты
        SSL_CTX_set_read_ahead(ssl_ctx_, 1);            // Включить read-ahead
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
    // Очистка всех SSL-соединений
    for (auto &[fd, ssl] : ssl_connections_)
    {
        SSL_free(ssl);
    }
    ssl_connections_.clear();
}

bool Http1Server::run()
{
    // Создаем сокет для прослушивания
    listen_fd_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listen_fd_ < 0)
    {
        LOG_ERROR("Не удалось создать сокет для прослушивания: {}", strerror(errno));
        return false;
    }
    // Устанавливаем опции
    int opt = 1;
    if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        LOG_ERROR("setsockopt SO_REUSEADDR failed: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }
    if (setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
    {
        LOG_ERROR("setsockopt SO_REUSEPORT failed: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }
    // Устанавливаем неблокирующий режим
    if (!set_nonblocking(listen_fd_))
    {
        LOG_ERROR("Не удалось установить неблокирующий режим для сокета прослушивания");
        ::close(listen_fd_);
        return false;
    }
    // Привязываемся к адресу и порту
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);
    if (bind(listen_fd_, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        LOG_ERROR("Не удалось привязать сокет к порту {}: {}", port_, strerror(errno));
        ::close(listen_fd_);
        return false;
    }
    // Начинаем прослушивать
    if (listen(listen_fd_, SOMAXCONN) < 0)
    {
        LOG_ERROR("Не удалось начать прослушивание: {}", strerror(errno));
        ::close(listen_fd_);
        return false;
    }
    LOG_INFO("HTTP/1.1 сервер запущен на порту {}", port_);

    // Главный цикл
    while (running_)
    {
        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        // Добавляем сокет прослушивания
        FD_SET(listen_fd_, &read_fds);
        // Добавляем все активные соединения
        for (const auto &conn : connections_)
        {
            int client_fd = conn.first;
            const ConnectionInfo &info = conn.second;
            // Проверяем, что дескрипторы валидны
            if (client_fd >= 0 && info.backend_fd >= 0)
            {
                FD_SET(client_fd, &read_fds);
                FD_SET(info.backend_fd, &read_fds);
            }
            else
            {
                LOG_WARN("⚠️ Невалидный дескриптор в connections_: client_fd={}, backend_fd={}", client_fd, info.backend_fd);
            }
        }

        // Выбираем максимальный дескриптор
        int max_fd = listen_fd_;
        LOG_DEBUG("🔍 Текущие дескрипторы: listen_fd={}, max_fd={}", listen_fd_, max_fd);
        for (const auto &conn : connections_)
        {
            int client_fd = conn.first;
            const ConnectionInfo &info = conn.second;
            LOG_DEBUG("   ➤ client_fd={}, backend_fd={}", client_fd, info.backend_fd);
        }

        timeval timeout{.tv_sec = 1, .tv_usec = 0}; // Таймаут 1 секунда
        // 🛡️ ИСПРАВЛЕНИЕ: Обработка EINTR для select
        int activity;
        do {
            activity = select(max_fd + 1, &read_fds, &write_fds, nullptr, &timeout);
        } while (activity < 0 && errno == EINTR);

        if (activity < 0) {
            LOG_ERROR("Ошибка select: {}", strerror(errno));
            continue;
        }

        if (activity > 0)
        {
            // Обработка новых соединений
            if (FD_ISSET(listen_fd_, &read_fds))
            {
                handle_new_connection();
            }
            // Обработка данных от клиентов и сервера
            handle_io_events();
        }

        // Проверка таймаутов
        time_t now = time(nullptr);
        for (auto it = timeouts_.begin(); it != timeouts_.end();)
        {
            if (now - it->second > 60) // 👈 Увеличенный таймаут до 60 секунд
            {
                int client_fd = it->first;
                ::close(client_fd);
                connections_.erase(client_fd);
                timeouts_.erase(it++);
                LOG_INFO("TCP-соединение закрыто по таймауту: клиент {}", client_fd);
            }
            else
            {
                ++it;
            }
        }
    }

    // Закрываем все соединения
    for (const auto &conn : connections_)
    {
        int client_fd = conn.first;
        const ConnectionInfo &info = conn.second;
        ::close(client_fd);
        ::close(info.backend_fd);
    }
    connections_.clear();
    if (listen_fd_ != -1)
    {
        ::close(listen_fd_);
    }
    LOG_INFO("HTTP/1.1 сервер остановлен.");
    return true;
}

void Http1Server::stop()
{
    running_ = false;
}

bool Http1Server::set_nonblocking(int fd) noexcept
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

int Http1Server::connect_to_backend() noexcept
{
    int backend_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (backend_fd < 0)
    {
        LOG_ERROR("Не удалось создать сокет для подключения к серверу в России: {}", strerror(errno));
        return -1;
    }
    // Устанавливаем неблокирующий режим
    if (!set_nonblocking(backend_fd))
    {
        LOG_ERROR("Не удалось установить неблокирующий режим для сокета сервера");
        ::close(backend_fd);
        return -1;
    }
    // Устанавливаем адрес сервера
    struct sockaddr_in backend_addr{};
    backend_addr.sin_family = AF_INET;
    backend_addr.sin_port = htons(backend_port_);
    if (inet_pton(AF_INET, backend_ip_.c_str(), &backend_addr.sin_addr) <= 0)
    {
        LOG_ERROR("Не удалось преобразовать IP-адрес сервера: {}", backend_ip_);
        ::close(backend_fd);
        return -1;
    }
    // Подключаемся к серверу
    if (connect(backend_fd, (struct sockaddr *)&backend_addr, sizeof(backend_addr)) < 0)
    {
        if (errno != EINPROGRESS)
        {
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
        if (activity <= 0)
        {
            LOG_ERROR("❌ Таймаут подключения к бэкенду {}:{} (errno={})", backend_ip_, backend_port_, errno);
            ::close(backend_fd);
            return -1;
        }
        // Проверяем, успешно ли подключились
        int error = 0;
        socklen_t len = sizeof(error);
        if (getsockopt(backend_fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0)
        {
            LOG_ERROR("❌ Не удалось получить статус подключения: {}", strerror(errno));
            ::close(backend_fd);
            return -1;
        }
        if (error != 0)
        {
            LOG_ERROR("❌ Ошибка подключения к бэкенду {}:{}: {}", backend_ip_, backend_port_, strerror(error));
            ::close(backend_fd);
            return -1;
        }
        LOG_INFO("✅ Подключение к бэкенду {}:{} успешно установлено", backend_ip_, backend_port_);
    }
    else
    {
        LOG_INFO("✅ Подключение к бэкенду {}:{} успешно установлено (мгновенно)", backend_ip_, backend_port_);
    }
    return backend_fd;
}

void Http1Server::handle_new_connection() noexcept
{
    // 🟡 СТРУКТУРА ДЛЯ ХРАНЕНИЯ АДРЕСА КЛИЕНТА
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    // 🟢 ПРИЕМ НОВОГО СОЕДИНЕНИЯ
    int client_fd = accept(listen_fd_, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            LOG_ERROR("❌ Ошибка accept: {}", strerror(errno));
        }
        return;
    }
    // 🟣 УСТАНОВКА НЕБЛОКИРУЮЩЕГО РЕЖИМА
    if (!set_nonblocking(client_fd))
    {
        LOG_ERROR("❌ Не удалось установить неблокирующий режим для клиента");
        ::close(client_fd);
        return;
    }
    // 🟤 ЛОГИРОВАНИЕ ИНФОРМАЦИИ О КЛИЕНТЕ
    std::string client_ip_str = inet_ntoa(client_addr.sin_addr);
    uint16_t client_port_num = ntohs(client_addr.sin_port);
    LOG_INFO("🟢 Новое соединение от клиента: {}:{} (fd={})",
             client_ip_str, client_port_num, client_fd);

    // 🔒 Проверка лимита соединений
    if (active_connections_ >= MAX_CONNECTIONS) {
        LOG_WARN("⚠️ Достигнут лимит соединений ({}). Отказываем новому клиенту.", MAX_CONNECTIONS);
        ::close(client_fd);
        return;
    }
    active_connections_++; // Увеличиваем счётчик

    // 🟢 ОБЪЯВЛЯЕМ backend_fd ВНАЧАЛЕ МЕТОДА
    int backend_fd = -1;
    // Подключаемся к серверу в России
    backend_fd = connect_to_backend();
    if (backend_fd == -1)
    {
        LOG_ERROR("❌ Не удалось подключиться к серверу в России. Закрываем соединение с клиентом.");
        ::close(client_fd);
        return;
    }
    // 🟢 СОЗДАНИЕ SSL-ОБЪЕКТА ДЛЯ TLS-ШИФРОВАНИЯ
    SSL *ssl = SSL_new(ssl_ctx_);
    if (!ssl) {
        LOG_ERROR("❌ Не удалось создать SSL-объект для клиента");
        ::close(client_fd);
        return;
    }
    // 🟠 ПРИВЯЗКА SSL К СОКЕТУ
    if (SSL_set_fd(ssl, client_fd) != 1) {
        LOG_ERROR("❌ Не удалось привязать SSL к сокету");
        SSL_free(ssl);
        ::close(client_fd);
        return;
    }
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
    LOG_INFO("✅ TLS-соединение создано, но handshake не завершён. Ожидаем данные для продолжения.");

    // 🟢 ЗАПУСКАЕМ TLS HANDSHAKE
    if (!perform_tls_handshake(client_fd, info)) {
        // Если handshake не удался, закрываем соединение
        close_connection(client_fd, info);
        return;
    }

    LOG_INFO(" ✅ TLS-соединение успешно установлено для клиента: {}:{} (fd={})",
             client_ip_str, client_port_num, client_fd);
}

void Http1Server::handle_io_events() noexcept
{
    // Создаём копию карты соединений — чтобы избежать модификации во время итерации
    auto connections_copy = connections_;

    // Итерируем по копии — используем неконстантную ссылку
    for (auto &conn : connections_copy)
    {
        int client_fd = conn.first;               // Дескриптор клиента
        ConnectionInfo &info = conn.second;       // Информация о соединении — теперь можно изменять

        // 🟡 ПРОВЕРКА: ЭТО SSL-СОЕДИНЕНИЕ?
        bool is_ssl = info.ssl != nullptr;

        // 🟠 ЕСЛИ HANDSHAKE НЕ ЗАВЕРШЁН — ПОПЫТКА ЗАВЕРШИТЬ ЕГО
        if (is_ssl && !info.handshake_done)
        {
            if (!perform_tls_handshake(client_fd, info)) {
                // Если handshake не удался, закрываем соединение
                close_connection(client_fd, info);
                continue;
            }
        }

        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(client_fd, &read_fds);
        FD_SET(info.backend_fd, &read_fds);

        // 🛡️ ПРОВЕРКА ВАЛИДНОСТИ ДЕСКРИПТОРОВ ПЕРЕД ВЫЧИСЛЕНИЕМ max_fd
        if (client_fd < 0 || info.backend_fd < 0) {
            LOG_WARN("⚠️ Невалидный дескриптор при обработке IO: client_fd={}, backend_fd={}",
                     client_fd, info.backend_fd);
            continue; // Пропускаем это соединение
        }

        int max_fd = std::max(client_fd, info.backend_fd); // Без {} — безопаснее для C++23
        timeval timeout{.tv_sec = 0, .tv_usec = 1000};     // 1 мс — ускоряем реакцию
        int activity = select(max_fd + 1, &read_fds, &write_fds, nullptr, &timeout);
        if (activity <= 0)
        {
            continue;
        }

        // 🟢 ПЕРЕДАЧА ДАННЫХ ОТ КЛИЕНТА К СЕРВЕРУ
        if (FD_ISSET(client_fd, &read_fds))
        {
            handle_client_data(client_fd, info);
        }

        if (FD_ISSET(info.backend_fd, &read_fds))
        {
            handle_backend_data(client_fd, info);
        }
    }
}

SSL *Http1Server::get_ssl_for_fd(int fd) noexcept
{
    // Используем ssl_connections_ напрямую для эффективного поиска
    auto it = ssl_connections_.find(fd);
    if (it != ssl_connections_.end()) {
        return it->second;
    }
    return nullptr;
}

bool Http1Server::forward_data(int from_fd, int to_fd, SSL *ssl) noexcept
{
    LOG_DEBUG(" 🔄 Начало forward_data(from_fd={}, to_fd={}, ssl={})",
              from_fd, to_fd, ssl ? "true" : "false");

    // 🟡 ЧТЕНИЕ ДАННЫХ
    char buffer[8192];
    bool use_ssl = (ssl != nullptr);
    ssize_t bytes_read = 0;
    if (use_ssl)
    {
        LOG_INFO("[READ] 🔐 Попытка чтения через SSL из fd={}", from_fd);
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read < 0)
        {
            int ssl_error = SSL_get_error(ssl, bytes_read);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
            {
                LOG_WARN("[READ] ⏳ SSL_ERROR_WANT_READ/WRITE — повторная попытка позже");
                return true; // ✅ Возвращаем true — соединение активно, нужно повторить
            }
            else if (ssl_error == SSL_ERROR_ZERO_RETURN)
            {
                LOG_INFO("[READ] ✅ Клиент корректно закрыл соединение (SSL_ERROR_ZERO_RETURN)");
                return false;
            }
            else
            {
                LOG_ERROR("[READ] ❌ Фатальная ошибка SSL: {}", ERR_error_string(ERR_get_error(), nullptr));
                return false; // ✅ Добавлено
            }
        }
        else if (bytes_read == 0)
        {
            LOG_WARN("[READ] ⚠️ SSL_read вернул 0 — возможно, соединение закрыто.");
            return false;
        }
        else
        {
            LOG_INFO("[READ] ✅ Прочитано {} байт через SSL", bytes_read);
        }
    }
    else
    {
        LOG_INFO("[READ] 📥 Попытка чтения через recv из fd={}", from_fd);
        bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
        if (bytes_read < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                LOG_WARN("[READ] ⏳ recv() вернул EAGAIN/EWOULDBLOCK — буфер пуст");
                return true;
            }
            else
            {
                LOG_ERROR("[READ] ❌ recv ошибка: {} (errno={})", strerror(errno), errno);
                return false; // ✅ Добавлено
            }
        }
        else if (bytes_read == 0)
        {
            LOG_WARN("[READ] ⚠️ recv вернул 0 — соединение закрыто.");
            return false;
        }
        else
        {
            LOG_INFO("[READ] ✅ Прочитано {} байт через recv", bytes_read);
        }
    }

    // 🛑 Проверка: есть ли данные для отправки?
    if (bytes_read <= 0)
    {
        LOG_WARN("[FORWARD] ❗ Нет данных для отправки — завершаем соединение");
        return false;
    }

    LOG_INFO("✅ Получено {} байт данных от {} (fd={})",
             bytes_read, use_ssl ? "клиента" : "сервера", from_fd);

    // 🟢 ПРОВЕРКА: ЕСТЬ ЛИ НЕЗАВЕРШЁННЫЕ ОТПРАВКИ?
    if (!pending_sends_.empty() && pending_sends_.find(to_fd) != pending_sends_.end() && !pending_sends_[to_fd].empty())
    {
        LOG_INFO("[PENDING] 🕒 Есть незавершённые отправки для fd={}", to_fd);
        if (!process_pending_sends(to_fd)) {
            return false;
        }
    }

    // 🟢 ЗАПИСЬ НОВЫХ ДАННЫХ
    LOG_INFO("[NEW] 🆕 Создаём новый элемент для отправки {} байт на fd={}", bytes_read, to_fd);
    PendingSend new_send;
    new_send.fd = to_fd;
    new_send.len = static_cast<size_t>(bytes_read);
    new_send.sent = 0;
    new_send.data = std::make_unique<char[]>(new_send.len);
    std::memcpy(new_send.data.get(), buffer, new_send.len);

    // Пытаемся отправить сразу
    LOG_INFO("[NEW] 📤 Попытка немедленной отправки {} байт на fd={}", new_send.len, to_fd);
    ssize_t bytes_sent = try_send(to_fd, new_send.data.get(), new_send.len, get_ssl_for_fd(to_fd));

    if (bytes_sent <= 0)
    {
        LOG_WARN("[NEW] ⏳ send() вернул EAGAIN/EWOULDBLOCK — добавляем в очередь");
        pending_sends_[to_fd].push(std::move(new_send));
        return true;
    }

    // Успешно отправили всё сразу
    LOG_SUCCESS("🎉 Успешно передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
    LOG_DEBUG(" 🔄 Конец forward_data — соединение остаётся активным");
    return true;
}

void Http1Server::handle_client_data(int client_fd, ConnectionInfo& info) noexcept
{
    LOG_INFO(" 📥 Получены данные от клиента {} (fd={})", client_fd, client_fd);
    LOG_DEBUG("🔄 Начало обработки данных через forward_data: from_fd={}, to_fd={}", client_fd, info.backend_fd);

    // 🟢 СНАЧАЛА ПРОВЕРЯЕМ НЕЗАВЕРШЁННЫЕ ОТПРАВКИ ДЛЯ БЭКЕНДА
    if (!pending_sends_.empty() && pending_sends_.find(info.backend_fd) != pending_sends_.end() && !pending_sends_[info.backend_fd].empty())
    {
        if (!process_pending_sends(info.backend_fd)) {
            close_connection(client_fd, info);
            return;
        }
    }

    // 🟢 ТЕПЕРЬ ЧИТАЕМ НОВЫЕ ДАННЫЕ ОТ КЛИЕНТА
    bool keep_alive = forward_data(client_fd, info.backend_fd, info.ssl); // 👈 Передаём ssl
    if (!keep_alive)
    {
        close_connection(client_fd, info);
    }
    else
    {
        timeouts_[client_fd] = time(nullptr);
    }
}

void Http1Server::handle_backend_data(int client_fd, ConnectionInfo& info) noexcept
{
    LOG_INFO("📤 Получены данные от сервера {}", info.backend_fd);

    // 🔴 ПРОВЕРКА: ЗАВЕРШЁН ЛИ HANDSHAKE?
    if (info.ssl != nullptr && !info.handshake_done)
    {
        LOG_WARN("❗ Нельзя отправлять данные клиенту, пока handshake не завершён. Пропускаем.");
        return; // Пропускаем эту итерацию, ждём завершения handshake
    }

    // 🟢 Передаём данные
    bool keep_alive = forward_data(info.backend_fd, client_fd, nullptr); // 👈 Передаём nullptr, так как данные от бэкенда не шифруются
    if (!keep_alive)
    {
        close_connection(client_fd, info);
    }
    else
    {
        // 🟢 ПРОВЕРЯЕМ, ЗАВЕРШЕН ЛИ ЧАНК
        if (chunked_complete_.find(client_fd) != chunked_complete_.end())
        {
            if (chunked_complete_[client_fd])
            {
                // 🟢 Чанки завершены — можно закрыть соединение
                LOG_INFO("✅ Все чанки отправлены. Закрываем соединение для клиента {}", client_fd);
                close_connection(client_fd, info);
            }
            else
            {
                // 🟡 Чанки ещё не завершены — обновляем таймаут
                timeouts_[client_fd] = time(nullptr);
            }
        }
        else
        {
            // 🟡 Неизвестное состояние — обновляем таймаут
            timeouts_[client_fd] = time(nullptr);
        }
    }
}

void Http1Server::close_connection(int client_fd, ConnectionInfo& info) noexcept
{
    // 🟢 Сохраняем указатель на SSL перед удалением из карты
    SSL* ssl_to_free = nullptr;
    if (info.ssl)
    {
        ssl_to_free = info.ssl;
    }

    // 🟢 Закрываем сокеты
    ::close(client_fd);
    ::close(info.backend_fd);

    // 🟢 Удаляем из карт (это удаляет ConnectionInfo, включая ssl)
    connections_.erase(client_fd);
    timeouts_.erase(client_fd);

    // 🟢 Освобождаем SSL-объект (только если он был)
    if (ssl_to_free)
    {
        SSL_free(ssl_to_free);
    }

    LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, info.backend_fd);
    active_connections_--; // Уменьшаем счётчик при закрытии соединения
}

bool Http1Server::perform_tls_handshake(int client_fd, ConnectionInfo& info) noexcept
{
    int ssl_accept_result = SSL_accept(info.ssl);
    if (ssl_accept_result <= 0)
    {
        int ssl_error = SSL_get_error(info.ssl, ssl_accept_result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE ||
            ssl_error == SSL_ERROR_WANT_CONNECT || ssl_error == SSL_ERROR_WANT_ACCEPT) {
            LOG_DEBUG("⏸️ TLS handshake требует повторной попытки ({}).", SSL_state_string_long(info.ssl));
            // 🟢 Не логируем каждый раз — только при первом входе в handshake
            if (!info.handshake_done && !info.logged_handshake_want)
            {
                LOG_DEBUG("⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE)");
                info.logged_handshake_want = true; // 👈 Установка флага
            }
            return false; // Повторить позже
        }
        else
        {
            // 🟢 Сброс флага при новой попытке handshake
            info.logged_handshake_want = false;

            // 🆕 ДОБАВЛЕННОЕ ЛОГИРОВАНИЕ
            const char *client_protocol = SSL_get_cipher_name(info.ssl);
            if (client_protocol) {
                LOG_ERROR("❌ Клиент пытается использовать шифр: {}", client_protocol);
            } else {
                LOG_ERROR("❌ Не удалось определить шифр клиента");
            }
            LOG_ERROR("❌ TLS handshake не удался: {}", ERR_error_string(ERR_get_error(), nullptr));

            return false;
        }
    }

    // 🟢 HANDSHAKE УСПЕШНО ЗАВЕРШЁН
    LOG_INFO("✅ TLS handshake успешно завершён для клиента: {} (fd={})", client_fd, client_fd);
    // Обновляем информацию — помечаем handshake как завершённый
    info.handshake_done = true;
    return true;
}

bool Http1Server::process_pending_sends(int fd) noexcept
{
    auto &pending_queue = pending_sends_[fd];
    while (!pending_queue.empty())
    {
        auto &pending = pending_queue.front();
        if (pending.fd != fd)
        {
            LOG_WARN("[PENDING] 🗑️ Некорректный fd в очереди — пропускаем элемент");
            pending_queue.pop();
            continue;
        }

        // 🟠 ПОПЫТКА ОТПРАВИТЬ ОСТАВШИЕСЯ ДАННЫЕ
        LOG_DEBUG("[PENDING] 📤 Отправка оставшихся {} байт из {} (уже отправлено {})",
                  pending.len - pending.sent, pending.len, pending.sent);

        ssize_t bytes_sent = try_send(pending.fd, pending.data.get() + pending.sent, pending.len - pending.sent, get_ssl_for_fd(pending.fd));

        if (bytes_sent <= 0)
        {
            if (bytes_sent == -1) {
                // Ошибка при отправке
                LOG_ERROR("[PENDING] ❌ send() фатальная ошибка: {}", strerror(errno));
                pending_queue.pop();
                return false;
            }
            // EAGAIN/EWOULDBLOCK или SSL_ERROR_WANT_READ/WRITE
            LOG_WARN("[PENDING] ⏳ send() вернул EAGAIN/EWOULDBLOCK — оставляем в очереди");
            return true;
        }

        pending.sent += static_cast<size_t>(bytes_sent);
        LOG_DEBUG("[PENDING] 📈 Отправлено {} байт, всего {}/{}", bytes_sent, pending.sent, pending.len);
        if (pending.sent >= pending.len)
        {
            LOG_SUCCESS("[PENDING] ✅ Полностью отправлена порция данных ({} байт)", pending.len);
            pending_queue.pop(); // Успешно отправили всю порцию
        }
        else
        {
            LOG_INFO("[PENDING] 📥 Остались неотправленные данные: {} байт", pending.len - pending.sent);
            return true; // Остались неотправленные данные
        }
    }
    return true;
}

ssize_t Http1Server::try_send(int fd, const char* data, size_t len, SSL* ssl) noexcept
{
    if (ssl != nullptr)
    {
        LOG_INFO("[PENDING] 🔐 SSL_write для fd={}", fd);
        ssize_t bytes_sent = SSL_write(ssl, data, len);
        if (bytes_sent <= 0)
        {
            int ssl_error = SSL_get_error(ssl, bytes_sent);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
            {
                LOG_WARN("[PENDING] ⏳ SSL_write требует повторной попытки — оставляем в очереди");
                return -1; // Сигнализируем, что нужно повторить
            }
            else
            {
                LOG_ERROR("[PENDING] ❌ SSL_write фатальная ошибка: {}",
                          ERR_error_string(ERR_get_error(), nullptr));
                return -1;
            }
        }
        return bytes_sent;
    }
    else
    {
        LOG_INFO("[PENDING] 📤 send() для fd={}", fd);
        ssize_t bytes_sent = send(fd, data, len, MSG_NOSIGNAL);
        if (bytes_sent <= 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                LOG_WARN("[PENDING] ⏳ send() вернул EAGAIN/EWOULDBLOCK — буфер заполнен");
                return -1;
            }
            else
            {
                LOG_ERROR("[PENDING] ❌ send() фатальная ошибка: {}", strerror(errno));
                return -1;
            }
        }
        return bytes_sent;
    }
}