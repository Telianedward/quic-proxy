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
    if (!ssl_ctx_)
    {
        LOG_ERROR("❌ Не удалось создать SSL-контекст");
        return;
    }

    // 🟢 НАСТРОЙКИ SSL ДО ЗАГРУЗКИ СЕРТИФИКАТОВ
    SSL_CTX_set_options(ssl_ctx_, SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_mode(ssl_ctx_, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_CTX_set_read_ahead(ssl_ctx_, 1);


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
        SSL_CTX_free(ssl_ctx_);
        ssl_ctx_ = nullptr;
            SSL_CTX_set_max_send_fragment(ssl_ctx_, 16384); // 16KB фрагменты
            SSL_CTX_set_read_ahead(ssl_ctx_, 1); // Включить read-ahead
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
            LOG_ERROR("[server.cpp:258] ❌ Ошибка accept: {}", strerror(errno));
        }
        return;
    }

    // 🟣 УСТАНОВКА НЕБЛОКИРУЮЩЕГО РЕЖИМА
    if (!set_nonblocking(client_fd))
    {
        LOG_ERROR("[server.cpp:267] ❌ Не удалось установить неблокирующий режим для клиента");
        ::close(client_fd);
        return;
    }

    // 🟤 ЛОГИРОВАНИЕ ИНФОРМАЦИИ О КЛИЕНТЕ
    std::string client_ip_str = inet_ntoa(client_addr.sin_addr);
    uint16_t client_port_num = ntohs(client_addr.sin_port);
    LOG_INFO("[server.cpp:273] 🟢 Новое соединение от клиента: {}:{} (fd={})",
             client_ip_str, client_port_num, client_fd);

    // 🟢 ОБЪЯВЛЯЕМ backend_fd ВНАЧАЛЕ МЕТОДА
    int backend_fd = -1;

    // Подключаемся к серверу в России
    backend_fd = connect_to_backend();
    if (backend_fd == -1)
    {
        LOG_ERROR("[server.cpp:284] ❌ Не удалось подключиться к серверу в России. Закрываем соединение с клиентом.");
        ::close(client_fd);
        return;
    }

    // 🟢 СОЗДАНИЕ SSL-ОБЪЕКТА ДЛЯ TLS-ШИФРОВАНИЯ
    SSL *ssl = SSL_new(ssl_ctx_);
    if (!ssl)
    {
        LOG_ERROR("[server.cpp:292] ❌ Не удалось создать SSL-объект для клиента");
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

    // 🟢 УСТАНАВЛИВАЕМ ТАЙМАУТ
    timeouts_[client_fd] = time(nullptr);

    LOG_INFO("[server.cpp:308] ✅ TLS-соединение создано, но handshake не завершён. Ожидаем данные для продолжения.");

    // 🟢 ЗАПУСКАЕМ TLS HANDSHAKE
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

    // 🟢 HANDSHAKE УСПЕШНО ЗАВЕРШЁН
    LOG_INFO("[server.cpp:330] ✅ TLS handshake успешно завершён для клиента: {}:{} (fd={})",
             client_ip_str, client_port_num, client_fd);

    // Обновляем информацию — помечаем handshake как завершённый
    info.handshake_done = true;
    connections_[client_fd] = info;

    LOG_INFO("[server.cpp:337] ✅ TLS-соединение успешно установлено для клиента: {}:{} (fd={})",
             client_ip_str, client_port_num, client_fd);
}
/**
 * @brief Обрабатывает события ввода-вывода для всех активных соединений.
 *
 * Проверяет, есть ли данные для чтения от клиентов или бэкенда,
 * и передаёт их через forward_data. Также проверяет таймауты и закрывает неактивные соединения.
 *
 * @throws Никаких исключений — используется noexcept.
 * @note Этот метод вызывается из main loop при событии select().
 */
void Http1Server::handle_io_events() noexcept
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
                        LOG_INFO("📋 ClientHello от клиента {}:\n{}", client_fd, std::string(client_hello, bytes_read).substr(0, 512));
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

            bool keep_alive = forward_data(client_fd, info.backend_fd, info.ssl); // 👈 Передаём ssl

            if (!keep_alive)
            {
                // 🟢 ОБРАБОТКА SSL SHUTDOWN ПЕРЕД ЗАКРЫТИЕМ
                if (is_ssl && info.ssl)
                {
                    // 🟢 Проверяем, был ли уже вызван SSL_shutdown()
                    int shutdown_state = SSL_get_shutdown(info.ssl);
                    if (shutdown_state & SSL_RECEIVED_SHUTDOWN)
                    {
                        LOG_DEBUG("🟡 Клиент уже закрыл соединение. SSL_shutdown() не требуется.");
                    }
                    else
                    {
                        LOG_DEBUG("🔄 Вызов SSL_shutdown() для клиента {}", client_fd);
                        int shutdown_result = SSL_shutdown(info.ssl);
                        if (shutdown_result < 0)
                        {
                            LOG_WARN("⚠️ SSL_shutdown() вернул ошибку: {}",
                                    ERR_error_string(ERR_get_error(), nullptr));
                        }
                        else
                        {
                            LOG_INFO("✅ SSL_shutdown() успешно завершён для клиента {}", client_fd);
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
            if (!forward_data(info.backend_fd, client_fd, nullptr))
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

                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, info.backend_fd);
            }
            else
            {
                timeouts_[client_fd] = time(nullptr);
            }
        }
    }
}

SSL* Http1Server::get_ssl_for_fd(int fd) noexcept
{
    for (const auto &conn : connections_)
    {
        if (conn.first == fd)
        {
            return conn.second.ssl;
        }
    }
    return nullptr;
}

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
/**
 * @brief Передаёт данные между двумя сокетами (клиент ↔ бэкенд) в неблокирующем режиме, с поддержкой TLS.
 */
bool Http1Server::forward_data(int from_fd, int to_fd, SSL *ssl) noexcept
{
    LOG_DEBUG("[server.cpp:460] 🔄 Начало forward_data(from_fd={}, to_fd={}, ssl={})",
              from_fd, to_fd, ssl ? "true" : "false");

    // 🟢 ОГРАНИЧИВАЕМ РАЗМЕР БУФЕРА ДЛЯ SSL
    const size_t MAX_SSL_BUFFER = 16384; // 16KB - максимальный размер для TLS записи
    char buffer[MAX_SSL_BUFFER];
    bool use_ssl = (ssl != nullptr);

    // 🟡 ЧТЕНИЕ ДАННЫХ
    ssize_t bytes_read = 0;
    if (use_ssl) {
        // 🟢 ЧИТАЕМ МЕНЬШИЕ ЧАНКИ ДЛЯ SSL
        bytes_read = SSL_read(ssl, buffer, sizeof(buffer));
    } else {
        bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
    }

    if (bytes_read <= 0) {
        // Обработка ошибок (существующий код)
        if (use_ssl) {
            int ssl_error = SSL_get_error(ssl, bytes_read);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                return true;
            } else if (bytes_read == 0) {
                LOG_INFO("🔚 SSL соединение закрыто клиентом (from_fd={})", from_fd);
                return false;
            }
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return true;
            } else if (bytes_read == 0) {
                LOG_INFO("🔚 Соединение закрыто клиентом (from_fd={})", from_fd);
                return false;
            }
        }
        LOG_ERROR("❌ Ошибка чтения: bytes_read={}, use_ssl={}", bytes_read, use_ssl);
        return false;
    }

    LOG_INFO("✅ Получено {} байт данных от {} (fd={})", bytes_read, use_ssl ? "клиента" : "сервера", from_fd);

    // 🟢 ПЕРЕДАЧА ДАННЫХ С УЧЁТОМ ОГРАНИЧЕНИЙ SSL
    SSL *target_ssl = get_ssl_for_fd(to_fd);
    ssize_t total_sent = 0;

    while (total_sent < bytes_read) {
        size_t remaining = static_cast<size_t>(bytes_read - total_sent);

        // 🟢 ОГРАНИЧИВАЕМ РАЗМЕР ЗАПИСИ ДЛЯ SSL
        size_t chunk_size = remaining;
        if (target_ssl != nullptr) {
            // Для SSL используем меньшие чанки
            chunk_size = std::min(remaining, static_cast<size_t>(4096)); // 4KB максимум для SSL
        }

        LOG_DEBUG("📦 Отправка чанка {}/{} байт", chunk_size, remaining);

        ssize_t bytes_sent = 0;

        // 🟢 ПРОВЕРКА СОСТОЯНИЯ SSL ПЕРЕД ЗАПИСЬЮ
        if (target_ssl != nullptr) {
            if (!SSL_is_init_finished(target_ssl)) {
                LOG_ERROR("❌ SSL соединение не готово для записи");
                return false;
            }

            // 🟢 ИСПОЛЬЗУЕМ SSL_write С ОГРАНИЧЕННЫМ РАЗМЕРОМ
            bytes_sent = SSL_write(target_ssl, buffer + total_sent, chunk_size);
        } else {
            bytes_sent = send(to_fd, buffer + total_sent, chunk_size, MSG_NOSIGNAL);
        }
        // В методе forward_data после SSL_write можно добавить:
        if (target_ssl != nullptr) {
            int pending = SSL_pending(target_ssl);
            if (pending > 0) {
                LOG_DEBUG("📊 SSL_pending: {} байт в буфере", pending);
            }
        }
        if (bytes_sent <= 0) {
            if (target_ssl != nullptr) {
                int ssl_error = SSL_get_error(target_ssl, bytes_sent);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE) {
                    LOG_WARN("⏸️ SSL_write требует повторной попытки (осталось {}/{} байт)", remaining, bytes_read);

                    // 🟢 СОХРАНЯЕМ СОСТОЯНИЕ ДЛЯ ПОВТОРНОЙ ОТПРАВКИ
                    // В реальной реализации нужно добавить pending sends для SSL
                    return true;
                } else if (ssl_error == SSL_ERROR_SSL) {
                    LOG_ERROR("❌ Критическая ошибка SSL: {}", ERR_error_string(ERR_get_error(), nullptr));
                    return false;
                } else {
                    LOG_ERROR("❌ SSL_write ошибка: код={}, {}", ssl_error, ERR_error_string(ERR_get_error(), nullptr));
                    return false;
                }
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    LOG_WARN("⏸️ Буфер отправки заполнен (осталось {}/{} байт)", remaining, bytes_read);
                    return true;
                } else if (errno == EPIPE || errno == ECONNRESET) {
                    LOG_WARN("🔌 Соединение разорвано клиентом");
                    return false;
                } else {
                    LOG_ERROR("❌ send() ошибка: {} (errno={})", strerror(errno), errno);
                    return false;
                }
            }
        }

        total_sent += bytes_sent;
        LOG_DEBUG("📈 Отправлено {} байт, всего {}/{}", bytes_sent, total_sent, bytes_read);

        // 🟢 КОРОТКАЯ ПАУЗА ДЛЯ SSL, ЧТОБЫ ИЗБЕЖАТЬ ПЕРЕПОЛНЕНИЯ БУФЕРОВ
        if (target_ssl != nullptr && bytes_sent > 0) {
            std::this_thread::sleep_for(std::chrono::microseconds(50));
        }
    }

    LOG_SUCCESS("🎉 Успешно передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
    return true;
}