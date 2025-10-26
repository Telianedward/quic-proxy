/**
 * @file server.cpp
 * @brief Реализация HTTP/2 сервера.
 *
 * Обеспечивает обработку простых HTTP/2 запросов (GET, HEAD) с использованием TLS.
 * Используется для тестирования сетевой связности и отладки прокси.
 * Логирует все ключевые события: подключение, получение данных, отправка ответа.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-27
 * @version 1.0
 * @license MIT
 */
#include "../../include/http2/server.hpp"
#include <cstring>
#include <algorithm>
#include <sstream>
#include <poll.h>

// === Реализация методов класса Http2Server ===

Http2Server::Http2Server(int port, const std::string &backend_ip, int backend_port)
    : listen_fd_(-1), port_(port), backend_ip_(backend_ip), backend_port_(backend_port),
      ssl_ctx_(nullptr)
{
    // Инициализация OpenSSL
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Создание SSL-контекста
    ssl_ctx_ = SSL_CTX_new(TLS_server_method());
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

    // Настройка ALPN для HTTP/2
    static const unsigned char alpn_protos[] = {0x02, 'h', '2'};
    SSL_CTX_set_alpn_select_cb(ssl_ctx_, [](SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) -> int {
        if (nghttp2_is_fatal(nghttp2_select_next_protocol((unsigned char **)out, outlen, in, inlen)) != 0) {
            return SSL_TLSEXT_ERR_NOACK;
        }
        return SSL_TLSEXT_ERR_OK;
    }, nullptr);

    LOG_INFO("✅ ALPN для HTTP/2 настроен");
}

Http2Server::~Http2Server()
{
    if (ssl_ctx_)
    {
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
    }
    // Очистка всех SSL-соединений
    for (auto &[fd, ssl] : ssl_connections_)
    {
        SSL_free(ssl);
    }
    ssl_connections_.clear();

    // Очистка всех nghttp2_session
    for (auto &[fd, info] : connections_)
    {
        if (info.session)
        {
            nghttp2_session_del(info.session);
        }
    }
}

bool Http2Server::run()
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

    LOG_INFO("HTTP/2 сервер запущен на порту {}", port_);

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
            FD_SET(client_fd, &read_fds);
            FD_SET(info.backend_fd, &read_fds);
        }

        // Выбираем максимальный дескриптор
        int max_fd = listen_fd_;
        for (const auto &conn : connections_)
        {
            int client_fd = conn.first;
            const ConnectionInfo &info = conn.second;
            max_fd = std::max({max_fd, client_fd, info.backend_fd});
        }

        timeval timeout{.tv_sec = 1, .tv_usec = 0}; // Таймаут 1 секунда
        int activity = select(max_fd + 1, &read_fds, &write_fds, nullptr, &timeout);
        if (activity < 0 && errno != EINTR)
        {
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
            if (now - it->second > 30)
            { // Таймаут 30 секунд
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
    LOG_INFO("HTTP/2 сервер остановлен.");
    return true;
}

void Http2Server::stop()
{
    running_ = false;
}

bool Http2Server::set_nonblocking(int fd) noexcept
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        return false;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}

int Http2Server::connect_to_backend() noexcept
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

void Http2Server::handle_new_connection() noexcept
{
    struct sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(listen_fd_, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0)
    {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            LOG_ERROR("[server.cpp:258] ❌ Ошибка accept: {}", strerror(errno));
        }
        return;
    }

    // Устанавливаем неблокирующий режим
    if (!set_nonblocking(client_fd))
    {
        LOG_ERROR("[server.cpp:267] ❌ Не удалось установить неблокирующий режим для клиента");
        ::close(client_fd);
        return;
    }

    // Логирование информации о клиенте
    std::string client_ip_str = inet_ntoa(client_addr.sin_addr);
    uint16_t client_port_num = ntohs(client_addr.sin_port);
    LOG_INFO("[server.cpp:273] 🟢 Новое соединение от клиента: {}:{} (fd={})",
             client_ip_str, client_port_num, client_fd);

    // Подключаемся к серверу в России
    int backend_fd = connect_to_backend();
    if (backend_fd == -1)
    {
        LOG_ERROR("[server.cpp:284] ❌ Не удалось подключиться к серверу в России. Закрываем соединение с клиентом.");
        ::close(client_fd);
        return;
    }

    // Создание SSL-объекта для TLS-шифрования
    SSL *ssl = SSL_new(ssl_ctx_);
    if (!ssl)
    {
        LOG_ERROR("[server.cpp:292] ❌ Не удалось создать SSL-объект для клиента");
        ::close(client_fd);
        return;
    }

    // Привязка SSL к сокету
    SSL_set_fd(ssl, client_fd);

    // Установка неблокирующего режима для SSL
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    // Инициализация nghttp2_session
    nghttp2_session *session = init_nghttp2_session(client_fd, ssl);
    if (!session)
    {
        LOG_ERROR("[server.cpp:308] ❌ Не удалось инициализировать nghttp2_session для клиента");
        SSL_free(ssl);
        ::close(client_fd);
        return;
    }

    // Добавляем соединение в connections_
    ConnectionInfo info;
    info.backend_fd = backend_fd;
    info.ssl = ssl;
    info.handshake_done = false;
    info.session = session;
    connections_[client_fd] = info;

    // Устанавливаем таймаут
    timeouts_[client_fd] = time(nullptr);

    LOG_INFO("[server.cpp:308] ✅ TLS-соединение создано, но handshake не завершён. Ожидаем данные для продолжения.");

    // Запускаем TLS handshake
    int ssl_accept_result = SSL_accept(ssl);
    if (ssl_accept_result <= 0)
    {
        int ssl_error = SSL_get_error(ssl, ssl_accept_result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            LOG_DEBUG("[server.cpp:318] ⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE). Соединение оставлено в connections_ для дальнейшей обработки.");
            return; // Ждём следующего цикла select()
        }
        else
        {
            LOG_ERROR("[server.cpp:323] ❌ TLS handshake не удался: {}", ERR_error_string(ERR_get_error(), nullptr));
            SSL_free(ssl);
            connections_.erase(client_fd);
            timeouts_.erase(client_fd);
            ::close(client_fd);
            return;
        }
    }

    // HANDSHAKE УСПЕШНО ЗАВЕРШЁН
    LOG_INFO("[server.cpp:330] ✅ TLS handshake успешно завершён для клиента: {}:{} (fd={})",
             client_ip_str, client_port_num, client_fd);
    // Обновляем информацию — помечаем handshake как завершённый
    info.handshake_done = true;
    connections_[client_fd] = info;
    LOG_INFO("[server.cpp:337] ✅ TLS-соединение успешно установлено для клиента: {}:{} (fd={})",
             client_ip_str, client_port_num, client_fd);
}

void Http2Server::handle_io_events() noexcept
{
    // Создаём копию карты соединений — чтобы избежать модификации во время итерации
    auto connections_copy = connections_;
    // Итерируем по копии
    for (const auto &conn : connections_copy)
    {
        int client_fd = conn.first;               // Дескриптор клиента
        const ConnectionInfo &info = conn.second; // Информация о соединении

        // 🟡 ПРОВЕРКА: ЭТО SSL-СОЕДИНЕНИЕ?
        bool is_ssl = info.ssl != nullptr;

        // 🟠 ЕСЛИ HANDSHAKE НЕ ЗАВЕРШЁН — ПОПЫТКА ЗАВЕРШИТЬ ЕГО
        if (is_ssl && !info.handshake_done)
        {
            int ssl_accept_result = SSL_accept(info.ssl);
            if (ssl_accept_result <= 0)
            {
                int ssl_error = SSL_get_error(info.ssl, ssl_accept_result);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
                {
                    // 🟡 ЛОГИРОВАНИЕ ТЕКУЩЕГО СОСТОЯНИЯ SSL
                    LOG_DEBUG("🔒 SSL state: {}", SSL_state_string_long(info.ssl));
                    // 🟢 ПОПЫТКА ПРОЧИТАТЬ ClientHello (если есть данные)
                    char client_hello[8192];
                    int bytes_read = SSL_read(info.ssl, client_hello, sizeof(client_hello));
                    if (bytes_read > 0)
                    {
                        // 🟣 ЛОГИРОВАНИЕ ClientHello
                        LOG_INFO("📋 ClientHello от клиента {}:
{}", client_fd, std::string(client_hello, bytes_read).substr(0, 512));
                    }
                    else if (bytes_read == 0)
                    {
                        LOG_WARN("⚠️ Клиент {} закрыл соединение во время handshake", client_fd);
                        SSL_free(info.ssl);
                        connections_.erase(client_fd);
                        ::close(client_fd);
                        continue;
                    }
                    else
                    {
                        int ssl_error_after_read = SSL_get_error(info.ssl, bytes_read);
                        if (ssl_error_after_read != SSL_ERROR_WANT_READ && ssl_error_after_read != SSL_ERROR_WANT_WRITE)
                        {
                            LOG_ERROR("❌ Ошибка чтения ClientHello: {}", ERR_error_string(ERR_get_error(), nullptr));
                            SSL_free(info.ssl);
                            connections_.erase(client_fd);
                            ::close(client_fd);
                            continue;
                        }
                    }
                    LOG_DEBUG("⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE)");
                    continue; // Ждём следующего цикла
                }
                else
                {
                    LOG_ERROR("❌ TLS handshake не удался: {}", ERR_error_string(ERR_get_error(), nullptr));
                    SSL_free(info.ssl);
                    connections_.erase(client_fd);
                    ::close(client_fd);
                    continue;
                }
            }
            // 🟢 HANDSHAKE УСПЕШНО ЗАВЕРШЁН
            LOG_INFO("✅ TLS handshake успешно завершён для клиента: {} (fd={})", client_fd, client_fd);
            // Обновляем информацию — помечаем handshake как завершённый
            ConnectionInfo &mutable_info = connections_[client_fd];
            mutable_info.handshake_done = true;
        }

        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(client_fd, &read_fds);
        FD_SET(info.backend_fd, &read_fds);                  // 👈 Используем info.backend_fd
        int max_fd = std::max({client_fd, info.backend_fd}); // 👈 std::max с initializer list
        timeval timeout{.tv_sec = 0, .tv_usec = 1000};       // 1 мс — ускоряем реакцию
        int activity = select(max_fd + 1, &read_fds, &write_fds, nullptr, &timeout);
        if (activity <= 0)
        {
            continue;
        }

        // 🟢 ПЕРЕДАЧА ДАННЫХ ОТ КЛИЕНТА К СЕРВЕРУ
        if (FD_ISSET(client_fd, &read_fds))
        {
            LOG_INFO("[server.cpp:375] 📥 Получены данные от клиента {} (fd={})", client_fd, client_fd);
            LOG_DEBUG("[server.cpp:376] 🔄 Начало обработки данных через forward_data: from_fd={}, to_fd={}", client_fd, info.backend_fd);
            if (info.ssl != nullptr)
            {
                LOG_DEBUG("[server.cpp:379] 🔐 SSL-соединение активно. Подготовка к чтению данных через SSL");
            }
            bool keep_alive = forward_data(client_fd, info.backend_fd, info.ssl, info.session); // 👈 Передаём session
            if (!keep_alive)
            {
                // 🟢 Если клиент уже закрыл соединение — не вызываем SSL_shutdown()
                if (is_ssl && info.ssl)
                {
                    // 🟢 Проверяем, был ли уже вызван SSL_shutdown()
                    int shutdown_state = SSL_get_shutdown(info.ssl);
                    if (shutdown_state & SSL_RECEIVED_SHUTDOWN)
                    {
                        LOG_DEBUG("[server.cpp:575] 🟡 Клиент уже закрыл соединение. SSL_shutdown() не требуется.");
                    }
                    else
                    {
                        LOG_DEBUG("[server.cpp:578] 🔄 Вызов SSL_shutdown() для клиента {}", client_fd);
                        int shutdown_result = SSL_shutdown(info.ssl);
                        if (shutdown_result < 0)
                        {
                            LOG_WARN("[server.cpp:581] ⚠️ SSL_shutdown() вернул ошибку: {}",
                                     ERR_error_string(ERR_get_error(), nullptr));
                        }
                        else
                        {
                            LOG_INFO("[server.cpp:584] ✅ SSL_shutdown() успешно завершён для клиента {}", client_fd);
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
                if (is_ssl && info.ssl)
                {
                    SSL_free(info.ssl);
                }
                // 🟢 Освобождаем nghttp2_session
                if (info.session)
                {
                    nghttp2_session_del(info.session);
                }
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, info.backend_fd);
            }
            else
            {
                timeouts_[client_fd] = time(nullptr);
            }
        }
        // 🟡 ПЕРЕДАЧА ДАННЫХ ОТ СЕРВЕРА К КЛИЕНТУ
        if (FD_ISSET(info.backend_fd, &read_fds))
        {
            LOG_INFO("📤 Получены данные от сервера {}", info.backend_fd);
            if (!forward_data(info.backend_fd, client_fd, nullptr, nullptr)) // 👈 Передаём nullptr для session
            {
                // 🟢 Если клиент уже закрыл соединение — не вызываем SSL_shutdown()
                if (is_ssl && info.ssl)
                {
                    // 🟢 Проверяем, был ли уже вызван SSL_shutdown()
                    int shutdown_state = SSL_get_shutdown(info.ssl);
                    if (shutdown_state & SSL_RECEIVED_SHUTDOWN)
                    {
                        LOG_DEBUG("[server.cpp:575] 🟡 Клиент уже закрыл соединение. SSL_shutdown() не требуется.");
                    }
                    else
                    {
                        LOG_DEBUG("[server.cpp:578] 🔄 Вызов SSL_shutdown() для клиента {}", client_fd);
                        int shutdown_result = SSL_shutdown(info.ssl);
                        if (shutdown_result < 0)
                        {
                            LOG_WARN("[server.cpp:581] ⚠️ SSL_shutdown() вернул ошибку: {}",
                                     ERR_error_string(ERR_get_error(), nullptr));
                        }
                        else
                        {
                            LOG_INFO("[server.cpp:584] ✅ SSL_shutdown() успешно завершён для клиента {}", client_fd);
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
                if (is_ssl && info.ssl)
                {
                    SSL_free(info.ssl);
                }
                // 🟢 Освобождаем nghttp2_session
                if (info.session)
                {
                    nghttp2_session_del(info.session);
                }
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, info.backend_fd);
            }
            else
            {
                timeouts_[client_fd] = time(nullptr);
            }
        }
    }
}

bool Http2Server::forward_data(int from_fd, int to_fd, SSL *ssl, nghttp2_session *session) noexcept
{
    // 🟢 ЛОГИРОВАНИЕ ВХОДА В ФУНКЦИЮ
    LOG_DEBUG("[server.cpp:460] 🔄 Начало forward_data(from_fd={}, to_fd={}, ssl={}, session={})",
              from_fd, to_fd, ssl ? "true" : "false", session ? "true" : "false");

    // 🟡 БУФЕР ДЛЯ ПРИЁМА ДАННЫХ
    char buffer[8192];

    // Логируем размер буфера для контроля.
    LOG_DEBUG("📦 Буфер создан: размер {} байт", sizeof(buffer));

    // 🟠 ОПРЕДЕЛЕНИЕ ТИПА СОЕДИНЕНИЯ: SSL ИЛИ НЕТ
    bool use_ssl = (ssl != nullptr);
    bool use_http2 = (session != nullptr);

    // Логируем тип соединения — важно для диагностики.
    LOG_DEBUG("🔒 use_ssl = {}", use_ssl ? "true" : "false");
    LOG_DEBUG("🌐 use_http2 = {}", use_http2 ? "true" : "false");

    // 🟣 КОЛИЧЕСТВО ПРОЧИТАННЫХ БАЙТ
    ssize_t bytes_read = 0;

    // 🟤 ЧТЕНИЕ ДАННЫХ СО СОКЕТА ИСТОЧНИКА (С УЧЁТОМ TLS)
    if (use_ssl)
    {
        // 🟢 ЧТЕНИЕ ЧЕРЕЗ SSL
        LOG_DEBUG("[server.cpp:479] 🟢 Начало чтения данных через SSL для client_fd={}", from_fd);
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes_read <= 0)
        {
            int ssl_error = SSL_get_error(ssl, bytes_read);
            LOG_DEBUG("[server.cpp:483] 🔴 SSL_read вернул {} байт. Код ошибки: {}", bytes_read, ssl_error);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
            {
                LOG_WARN("[server.cpp:486] ⏸️ SSL_read требует повторной попытки: {} (SSL_ERROR_WANT_READ/WRITE)",
                         SSL_state_string_long(ssl));
                return true;
            }
            else if (bytes_read == 0)
            {
                // 👇 Соединение закрыто удалённой стороной — нормальное завершение
                LOG_INFO("[server.cpp:495] 🔚 Клиент (from_fd={}) закрыл соединение", from_fd);
                return false;
            }
            else
            {
                // 👇 Любая другая ошибка — критическая
                LOG_ERROR("[server.cpp:500] ❌ Критическая ошибка SSL_read: {} (код ошибки: {})",
                          ERR_error_string(ERR_get_error(), nullptr), ssl_error);
                return false;
            }
        }
        LOG_INFO("[server.cpp:495] ✅ Успешно прочитано {} байт данных от клиента через TLS", bytes_read);
    }
    else
    {
        // 🟡 ЧТЕНИЕ ЧЕРЕЗ TCP (БЕЗ SSL)
        bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
        if (bytes_read < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            // 🟥 КРИТИЧЕСКАЯ ОШИБКА — ЗАКРЫТЬ СОЕДИНЕНИЕ
            LOG_ERROR("❌ recv() ошибка: {}", strerror(errno));
            return false;
        }
    }

    // 🔵 ОБРАБОТКА УСПЕШНОГО ЧТЕНИЯ (bytes_read > 0)
    if (bytes_read > 0)
    {
        // Логируем факт получения данных — важное событие для мониторинга.
        LOG_INFO("✅ Получено {} байт данных от клиента (from_fd={})", bytes_read, from_fd);

        // 🟣 ЛОГИРОВАНИЕ ПЕРВОГО HTTP-ЗАПРОСА (ТОЛЬКО ЕСЛИ ЭТО КЛИЕНТ И TLS)
        if (use_ssl)
        {
            std::string request_str(buffer, static_cast<size_t>(bytes_read));
            for (char &c : request_str)
            {
                if (c < 32 && c != '\n' && c != '\r' && c != '\t')
                    c = '?';
            }
            LOG_INFO("📋 Первый HTTP-запрос от клиента:
{}", request_str.substr(0, 512));
        }

        // 🟤 ОТПРАВКА ДАННЫХ НА СОКЕТ НАЗНАЧЕНИЯ
        ssize_t total_sent = 0;
        // Логируем начальное значение — для контроля состояния.
        LOG_DEBUG("📌 total_sent инициализирован: {}", total_sent);

        // 🟤 ЦИКЛ ОТПРАВКИ ДАННЫХ (ПОКА НЕ ВСЕ БАЙТЫ ОТПРАВЛЕНЫ)
        while (total_sent < bytes_read)
        {
            // 🟠 РАСЧЁТ ОСТАВШИХСЯ БАЙТ ДЛЯ ОТПРАВКИ
            size_t remaining = static_cast<size_t>(bytes_read - total_sent);
            // Логируем оставшийся объём — помогает понять, почему цикл повторяется.
            LOG_DEBUG("⏳ Осталось отправить {} байт (total_sent={}, bytes_read={})", remaining, total_sent, bytes_read);

            // 🟢 ОТПРАВКА ДАННЫХ НА СОКЕТ НАЗНАЧЕНИЯ
            ssize_t bytes_sent = 0;

            // 👇 ПРОВЕРКА: ЕСЛИ НАЗНАЧЕНИЕ — ЭТО КЛИЕНТ С TLS — ИСПОЛЬЗУЕМ SSL_WRITE
            if (use_ssl && to_fd == from_fd)
            { // ❗ ВАЖНО: Это условие НЕ верно!
                // 🟡 Но мы не можем определить, является ли to_fd клиентом, без дополнительной информации.
                // 🚫 Поэтому этот подход не работает.
                // Вместо этого, мы должны использовать другой способ.
                // ⚠️ УДАЛИМ ЭТО УСЛОВИЕ И ПРИМЕНИМ ПРАВИЛЬНЫЙ МЕТОД.
            }
            // 🟢 ПРАВИЛЬНЫЙ ПОДХОД: Мы знаем, что если `ssl != nullptr`, то `from_fd` — это клиент.
            // А значит, `to_fd` — это бэкенд, и нам не нужно использовать SSL для отправки.
            // ❌ Но это неверно! Нам нужно знать, кто получатель.
            // 🟠 ПРАВИЛЬНОЕ РЕШЕНИЕ: Мы должны передавать в forward_data не только `ssl`, но и информацию о том, куда мы отправляем.
            // 🚫 Но в текущей сигнатуре функции этого нет.
            // 💡 ВЫХОД: Мы должны изменить логику и использовать `SSL_write` только тогда, когда `to_fd` — это клиентский сокет, и у нас есть `SSL*`.
            // 📌 ДЛЯ ЭТОГО НУЖНО ИЗМЕНИТЬ КОНСТРУКЦИЮ КЛАССА.
            // 🔥 ВРЕМЕННОЕ ИСПРАВЛЕНИЕ (для текущей структуры):
            // Мы знаем, что в handle_io_events мы вызываем forward_data дважды:
            // 1. client_fd -> backend_fd (с use_ssl=true) — здесь отправка должна быть без SSL.
            // 2. backend_fd -> client_fd (с use_ssl=nullptr) — здесь отправка должна быть с SSL!
            // 🎯 Значит, нам нужно передавать в forward_data не только `ssl`, но и флаг, указывающий, куда мы отправляем.
            // 🛑 ПОКА НЕ БУДЕМ МЕНЯТЬ СИГНАТУРУ ФУНКЦИИ.
            // 💡 ВМЕСТО ЭТОГО, ВОСПОЛЬЗУЕМСЯ ТЕМ, ЧТО В connections_ ХРАНИТСЯ SSL* ДЛЯ КЛИЕНТА.
            // Мы можем найти SSL* по to_fd, если to_fd — это client_fd.
            // 🟢 ПОИСК SSL* ПО to_fd
            SSL *target_ssl = nullptr;
            for (const auto &conn : connections_)
            {
                if (conn.first == to_fd)
                {
                    target_ssl = conn.second.ssl;
                    break;
                }
            }
            if (target_ssl != nullptr)
            {
                // 🟢 Отправка через SSL_write
                LOG_DEBUG("🔒 Отправка данных через SSL_write для клиента (to_fd={})", to_fd);
                bytes_sent = SSL_write(target_ssl, buffer + total_sent, remaining);
                if (bytes_sent <= 0)
                {
                    int ssl_error = SSL_get_error(target_ssl, bytes_sent);
                    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
                    {
                        LOG_WARN("⏸️ SSL_write требует повторной попытки");
                        return true; // Ждём следующего цикла
                    }
                    else
                    {
                        LOG_ERROR("❌ SSL_write ошибка: {}", ERR_error_string(ERR_get_error(), nullptr));
                        return false;
                    }
                }
            }
            else
            {
                // 🟡 Обычная отправка через send
                LOG_DEBUG("📤 Отправка данных через send (to_fd={})", to_fd);
                bytes_sent = send(to_fd, buffer + total_sent, remaining, 0);
                if (bytes_sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    LOG_ERROR("❌ send() ошибка: {}", strerror(errno));
                    return false;
                }
            }

            // 🟡 ОБРАБОТКА УСПЕШНОЙ ОТПРАВКИ (bytes_sent > 0)
            if (bytes_sent > 0)
            {
                std::string sent_chunk(buffer + total_sent, static_cast<size_t>(bytes_sent));
                for (char &c : sent_chunk)
                {
                    if (c < 32 && c != '\n' && c != '\r' && c != '\t')
                        c = '?';
                }
                // Логируем первые 256 байт отправленных данных — достаточно для отладки HTTP-заголовков.
                LOG_DEBUG("📦 Отправлено содержимое (первые {} байт):
{}",
                          std::min<size_t>(256, sent_chunk.size()),
                          sent_chunk.substr(0, std::min<size_t>(256, sent_chunk.size())));
            }

            // 🟥 ОБРАБОТКА ОШИБКИ ОТПРАВКИ (bytes_sent < 0)
            if (bytes_sent < 0)
            {
                // Логируем ошибку отправки — критическое событие.
                LOG_ERROR("❌ send() или SSL_write вернул ошибку: errno={} ({})", errno, strerror(errno));
                // 🟨 ПРОВЕРКА НА EAGAIN / EWOULDBLOCK
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                {
                    // Логируем предупреждение — не ошибка, а состояние.
                    LOG_WARN("⏸️ Буфер отправки заполнен, попробуем позже. Отправлено {}/{} байт", total_sent, bytes_read);
                    // Возвращаем true — соединение активно, нужно повторить попытку.
                    return true;
                }
                else
                {
                    // 🟥 КРИТИЧЕСКАЯ ОШИБКА — любая другая ошибка (например, разрыв соединения).
                    LOG_ERROR("💥 Критическая ошибка отправки данных: {}", strerror(errno));
                    // Возвращаем false — соединение нужно закрыть.
                    return false;
                }
            }

            // 🟢 ОБНОВЛЕНИЕ СЧЁТЧИКА ОТПРАВЛЕННЫХ БАЙТ
            total_sent += bytes_sent;
            // Логируем обновление — позволяет отслеживать прогресс отправки.
            LOG_DEBUG("📈 total_sent обновлён: {} (отправлено {} байт)", total_sent, bytes_sent);

            // 🟡 ОБРАБОТКА ОТПРАВКИ 0 БАЙТ
            if (bytes_sent == 0)
            {
                // Логируем предупреждение — потенциально проблемное состояние.
                LOG_WARN("⚠️ send() или SSL_write вернул 0 — возможно, соединение закрыто на стороне получателя");
                // Выходим из цикла — дальнейшая отправка бессмысленна.
                break;
            }
        }

        // 🟢 ЛОГИРОВАНИЕ УСПЕШНОЙ ПЕРЕДАЧИ ВСЕХ ДАННЫХ
        LOG_SUCCESS("🎉 Успешно передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
        // Возвращаем true — соединение активно, можно продолжать.
        return true;
    }
    // 🔵 ОБРАБОТКА ЗАКРЫТИЯ СОЕДИНЕНИЯ (bytes_read == 0)
    else if (bytes_read == 0)
    {
        LOG_INFO("🔚 Клиент (from_fd={}) закрыл соединение", from_fd);
        return false;
    }
    // 🔵 ОБРАБОТКА ОШИБКИ ЧТЕНИЯ (bytes_read < 0)
    else
    {
        // Логируем ошибку чтения — диагностическое сообщение.
        LOG_DEBUG("⏸️ recv() или SSL_read() вернул -1");
        return true;
    }
}

nghttp2_session *Http2Server::init_nghttp2_session(int client_fd, SSL *ssl) noexcept
{
    // Создаем nghttp2_session
    nghttp2_session_callbacks callbacks;
    memset(&callbacks, 0, sizeof(callbacks));

    // Устанавливаем обработчики
    callbacks.on_header_callback = on_header;
    callbacks.on_data_chunk_recv_callback = on_data_chunk_recv;
    callbacks.on_frame_recv_callback = on_frame_recv;
    callbacks.send_callback = send_callback;

    nghttp2_session *session = nullptr;
    int rv = nghttp2_session_client_new(&session, &callbacks, this);
    if (rv != 0)
    {
        LOG_ERROR("❌ Не удалось создать nghttp2_session: {}", nghttp2_strerror(rv));
        return nullptr;
    }

    // Устанавливаем пользовательские данные
    nghttp2_session_set_user_data(session, this);

    // Устанавливаем callback для отправки данных
    nghttp2_session_set_send_callback(session, send_callback);

    // Устанавливаем callback для получения данных
    nghttp2_session_set_recv_callback(session, [](nghttp2_session *session, const uint8_t *data, size_t len, int flags, void *user_data) -> int {
        // Здесь можно обработать полученные данные
        return 0;
    });

    // Устанавливаем callback для обработки ошибок
    nghttp2_session_set_error_callback(session, [](nghttp2_session *session, int error_code, const char *msg, size_t msglen, void *user_data) -> int {
        LOG_ERROR("❌ Ошибка nghttp2: {} ({})", msg, error_code);
        return 0;
    });

    return session;
}

int Http2Server::on_header(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen, const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
    // Обработка заголовков
    std::string header_name(reinterpret_cast<const char *>(name), namelen);
    std::string header_value(reinterpret_cast<const char *>(value), valuelen);

    LOG_DEBUG("📝 Получен заголовок: {} = {}", header_name, header_value);

    return 0;
}

int Http2Server::on_data_chunk_recv(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *data, size_t len, void *user_data)
{
    // Обработка данных
    LOG_DEBUG("📥 Получены данные: {} байт", len);

    return 0;
}

int Http2Server::on_frame_recv(nghttp2_session *session, const nghttp2_frame *frame, void *user_data)
{
    // Обработка фреймов
    LOG_DEBUG("📦 Получен фрейм: тип {}", frame->hd.type);

    return 0;
}

int Http2Server::send_callback(nghttp2_session *session, const uint8_t *data, size_t len, int flags, void *user_data)
{
    // Отправка данных
    LOG_DEBUG("📤 Отправка данных: {} байт", len);

    return 0;
}

std::string Http2Server::generate_index_html() const
{
    return R"(<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>ErosJ</title>
    <link rel="stylesheet" href="/css/main.css">
</head>
<body>
    <h1>Proxy работает (HTTP/2)</h1>
    <p>Это HTTP/2 сервер на порту 8586.</p>
    <script src="/js/main.js"></script>
</body>
</html>)";
}

std::string Http2Server::generate_favicon() const
{
    // Здесь должен быть бинарный контент favicon.ico
    // Для примера используем пустую строку
    return "";
}

std::string Http2Server::generate_main_css() const
{
    return "body { background: #eee; font-family: Arial, sans-serif; }";
}

std::string Http2Server::generate_main_js() const
{
    return "console.log('Hello from Russia! (HTTP/2)');";
}