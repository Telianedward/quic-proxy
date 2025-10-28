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
bool Http1Server::forward_data(int from_fd, int to_fd, SSL *ssl) noexcept
{
    // 🟢 ЛОГИРОВАНИЕ ВХОДА В ФУНКЦИЮ
    LOG_DEBUG("[server.cpp:460] 🔄 Начало forward_data(from_fd={}, to_fd={}, ssl={})",
              from_fd, to_fd, ssl ? "true" : "false");
    bool is_chunked = false;
    size_t expected_chunk_size = 0;
    size_t received_chunk_size = 0;
    std::string chunk_buffer;
    // 🟡 БУФЕР ДЛЯ ПРИЁМА ДАННЫХ
    /**
     * @brief Буфер для временного хранения данных, полученных из сокета.
     * @details Выделяется статически на стеке — 8 КБ (8192 байта).
     * Размер выбран как оптимальный для TCP-прокси: достаточно для одного пакета,
     * не слишком велик для стека, обеспечивает хорошую производительность.
     * Это стандартный размер для TCP-буфера, обеспечивает хорошую производительность без избыточного выделения памяти.
     */
    char buffer[8192];
    // Логируем размер буфера для контроля.
    LOG_DEBUG("📦 Буфер создан: размер {} байт", sizeof(buffer));

    // 🟠 ОПРЕДЕЛЕНИЕ ТИПА СОЕДИНЕНИЯ: SSL ИЛИ НЕТ
    /**
     * @brief Флаг, указывающий, использует ли соединение TLS-шифрование.
     * @details true — если `ssl != nullptr` (то есть это клиентское TLS-соединение).
     *          false — если это обычное TCP-соединение (например, с бэкендом).
     */
    bool use_ssl = (ssl != nullptr);
    // Логируем тип соединения — важно для диагностики.
    LOG_DEBUG("🔒 use_ssl = {}", use_ssl ? "true" : "false");

    // 🟣 КОЛИЧЕСТВО ПРОЧИТАННЫХ БАЙТ
    /**
     * @brief Количество байт, успешно прочитанных из сокета `from_fd`.
     * @details Значения:
     *          - >0: количество прочитанных байт.
     *          - 0: удалённая сторона закрыла соединение.
     *          - -1: ошибка чтения (errno содержит код ошибки).
     * @note Для TLS-соединений значение возвращается функцией SSL_read(), для TCP — recv().
     */
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
        /**
         * @brief Прочитать данные из обычного TCP-соединения.
         * @details recv() — системный вызов для чтения данных из сокета.
         *          Параметры:
         *            - from_fd: дескриптор сокета, откуда читаем.
         *            - buffer: указатель на буфер для записи данных.
         *            - sizeof(buffer): максимальное количество байт для чтения.
         *            - 0: флаги — без специальных опций.
         * @return Количество прочитанных байт, или -1 при ошибке.
         * @note EAGAIN/EWOULDBLOCK — нормальное поведение в неблокирующем режиме.
         */
        bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
        if (bytes_read < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                LOG_DEBUG("⏳ Буфер чтения пуст, ждем...");
                return true; // Ждём следующего цикла select()
            }
            else
            {
                // 🟥 КРИТИЧЕСКАЯ ОШИБКА — ЗАКРЫТЬ СОЕДИНЕНИЕ
                LOG_ERROR("❌ recv() ошибка: {}", strerror(errno));
                return false;
            }
        }
    }
    if (bytes_read > 0)
    {
        // Логируем факт получения данных
        LOG_INFO("✅ Получено {} байт данных от клиента (from_fd={})", bytes_read, from_fd);

        // Парсим заголовки, если это первый пакет
        if (!is_chunked)
        {
            std::string data(buffer, static_cast<size_t>(bytes_read));
            size_t headers_end = data.find("\r\n\r\n");
            if (headers_end != std::string::npos)
            {
                std::string headers = data.substr(0, headers_end);
                if (headers.find("Transfer-Encoding: chunked") != std::string::npos)
                {
                    is_chunked = true;
                    LOG_DEBUG("🟢 Обнаружен Transfer-Encoding: chunked");
                }
            }
        }

        // Если это chunked-ответ — обрабатываем по чанкам
        if (is_chunked)
        {
            // Обработка чанков
            std::string data(buffer, static_cast<size_t>(bytes_read));
            size_t pos = 0;
            while (pos < data.size())
            {
                if (expected_chunk_size == 0)
                {
                    // Читаем размер чанка
                    size_t end_pos = data.find("\r\n", pos);
                    if (end_pos == std::string::npos)
                    {
                        // Не хватает данных — сохраняем остаток
                        chunk_buffer = data.substr(pos);
                        break;
                    }
                    std::string chunk_size_str = data.substr(pos, end_pos - pos);
                    try
                    {
                        expected_chunk_size = std::stoul(chunk_size_str, nullptr, 16);
                    }
                    catch (...)
                    {
                        LOG_ERROR("❌ Неверный размер чанка: {}", chunk_size_str);
                        return false;
                    }
                    pos = end_pos + 2; // Пропускаем \r\n
                }

                if (expected_chunk_size > 0)
                {
                    // Читаем данные чанка
                    size_t available = data.size() - pos;
                    size_t to_read = std::min(available, expected_chunk_size - received_chunk_size);
                    chunk_buffer.append(data.substr(pos, to_read));
                    pos += to_read;
                    received_chunk_size += to_read;

                    if (received_chunk_size == expected_chunk_size)
                    {
                        // Чанк полностью получен — отправляем его
                        LOG_DEBUG("📤 Отправка чанка размером {} байт", expected_chunk_size);
                        // Отправляем чанк на to_fd (через SSL_write или send)
                        ssize_t sent = 0;
                        if (target_ssl != nullptr)
                        {
                            sent = SSL_write(target_ssl, chunk_buffer.c_str(), chunk_buffer.size());
                        }
                        else
                        {
                            sent = send(to_fd, chunk_buffer.c_str(), chunk_buffer.size(), 0);
                        }
                        if (sent < 0)
                        {
                            LOG_ERROR("❌ Ошибка отправки чанка: {}", strerror(errno));
                            return false;
                        }
                        // Отправляем завершающий \r\n
                        if (target_ssl != nullptr)
                        {
                            SSL_write(target_ssl, "\r\n", 2);
                        }
                        else
                        {
                            send(to_fd, "\r\n", 2, 0);
                        }
                        // Сбрасываем состояние
                        chunk_buffer.clear();
                        received_chunk_size = 0;
                        expected_chunk_size = 0;
                    }
                }
                else
                {
                    // Это финальный чанк (0)
                    if (data.substr(pos).find("0\r\n\r\n") != std::string::npos)
                    {
                        // Отправляем финальный чанк
                        if (target_ssl != nullptr)
                        {
                            SSL_write(target_ssl, "0\r\n\r\n", 5);
                        }
                        else
                        {
                            send(to_fd, "0\r\n\r\n", 5, 0);
                        }
                        LOG_SUCCESS("🎉 Успешно передан финальный чанк");
                        return false; // Закрываем соединение
                    }
                    break;
                }
            }
        }
        else
        {
            // Обычная передача (не chunked)
            // Ваш текущий код отправки данных
            ssize_t total_sent = 0;
            while (total_sent < bytes_read)
            {
                size_t remaining = static_cast<size_t>(bytes_read - total_sent);
                ssize_t bytes_sent = 0;

                if (target_ssl != nullptr)
                {
                    bytes_sent = SSL_write(target_ssl, buffer + total_sent, remaining);
                }
                else
                {
                    bytes_sent = send(to_fd, buffer + total_sent, remaining, 0);
                }

                if (bytes_sent <= 0)
                {
                    // Обработка ошибок
                    if (target_ssl != nullptr)
                    {
                        int ssl_error = SSL_get_error(target_ssl, bytes_sent);
                        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
                        {
                            LOG_WARN("⏸️ SSL_write требует повторной попытки");
                            return true;
                        }
                        else
                        {
                            LOG_ERROR("❌ SSL_write ошибка: {}", ERR_error_string(ERR_get_error(), nullptr));
                            return false;
                        }
                    }
                    else
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            LOG_WARN("⏸️ Буфер отправки заполнен");
                            return true;
                        }
                        else
                        {
                            LOG_ERROR("❌ send() ошибка: {}", strerror(errno));
                            return false;
                        }
                    }
                }

                total_sent += bytes_sent;
                LOG_DEBUG("📈 total_sent обновлён: {} (отправлено {} байт)", total_sent, bytes_sent);
            }
            LOG_SUCCESS("🎉 Успешно передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
        }
    }
    // // 🔵 ОБРАБОТКА УСПЕШНОГО ЧТЕНИЯ (bytes_read > 0)
    // if (bytes_read > 0)
    // {
    //     // Логируем факт получения данных — важное событие для мониторинга.
    //     LOG_INFO("✅ Получено {} байт данных от клиента (from_fd={})", bytes_read, from_fd);

    //     // 🟣 ЛОГИРОВАНИЕ ПЕРВОГО HTTP-ЗАПРОСА (ТОЛЬКО ЕСЛИ ЭТО КЛИЕНТ И TLS)
    //     /**
    //      * @brief Логирование первого HTTP-запроса от клиента (если это TLS-соединение).
    //      * @details Только если:
    //      *          - соединение использует SSL (use_ssl == true),
    //      *          - источник — клиент (from_fd — это client_fd).
    //      *          Выводится первые 512 символов запроса в читаемом виде.
    //      * @note Для этого требуется знать, что `from_fd` — это клиент. В текущей реализации это не всегда возможно — см. ниже.
    //      */
    //     if (use_ssl)
    //     {
    //         // ⚠️ Внимание: мы не можем точно определить, является ли from_fd клиентом, без дополнительной информации.
    //         // Но если мы знаем, что это клиент (например, по контексту вызова), можно добавить условие.
    //         // Для отладки — логируем всегда, когда use_ssl == true.
    //         std::string request_str(buffer, static_cast<size_t>(bytes_read));
    //         for (char &c : request_str)
    //         {
    //             if (c < 32 && c != '\n' && c != '\r' && c != '\t')
    //                 c = '?';
    //         }
    //         LOG_INFO("📋 Первый HTTP-запрос от клиента:\n{}", request_str.substr(0, 512));
    //     }

    //     // // 🟡 ПРОВЕРКА: ЭТО ОТВЕТ ОТ БЭКЕНДА? (use_ssl == false)
    //     // if (!use_ssl)
    //     // {
    //     //     // 🟠 ПРОВЕРКА: ЕСТЬ ЛИ ЗАГОЛОВОК Content-Length?
    //     //     std::string response_str(buffer, bytes_read);
    //     //     size_t content_length_pos = response_str.find("Content-Length:");
    //     //     if (content_length_pos != std::string::npos)
    //     //     {
    //     //         // 🟡 УДАЛЯЕМ Content-Length
    //     //         size_t end_of_line = response_str.find("\r\n", content_length_pos);
    //     //         if (end_of_line != std::string::npos)
    //     //         {
    //     //             response_str.erase(content_length_pos, end_of_line - content_length_pos + 2);
    //     //             LOG_INFO("[server.cpp:830] 🟡 Удалён заголовок Content-Length");
    //     //         }

    //     //         // // 🟢 ДОБАВЛЯЕМ Transfer-Encoding: chunked
    //     //         // size_t headers_end = response_str.find("\r\n\r\n");
    //     //         // if (headers_end != std::string::npos)
    //     //         // {
    //     //         //     response_str.insert(headers_end, "\r\nTransfer-Encoding: chunked");
    //     //         //     LOG_INFO("[server.cpp:835] 🟢 Добавлен заголовок Transfer-Encoding: chunked");
    //     //         // }

    //     //         // 🟣 ПЕРЕЗАПИСЫВАЕМ БУФЕР
    //     //         bytes_read = static_cast<ssize_t>(response_str.size());
    //     //         memcpy(buffer, response_str.c_str(), bytes_read);
    //     //     }
    //     // }

    //     // 🟤 ОТПРАВКА ДАННЫХ НА СОКЕТ НАЗНАЧЕНИЯ
    //     /**
    //      * @brief Счётчик количества байт, уже успешно отправленных в сокет `to_fd`.
    //      * @details Инициализируется нулём перед началом цикла отправки.
    //      *          Инкрементируется после каждого успешного вызова send() или SSL_write().
    //      */
    //     ssize_t total_sent = 0;
    //     // Логируем начальное значение — для контроля состояния.
    //     LOG_DEBUG("📌 total_sent инициализирован: {}", total_sent);

    //     // 🟤 ЦИКЛ ОТПРАВКИ ДАННЫХ (ПОКА НЕ ВСЕ БАЙТЫ ОТПРАВЛЕНЫ)
    //     while (total_sent < bytes_read)
    //     {
    //         // 🟠 РАСЧЁТ ОСТАВШИХСЯ БАЙТ ДЛЯ ОТПРАВКИ
    //         size_t remaining = static_cast<size_t>(bytes_read - total_sent);
    //         LOG_DEBUG("⏳ Осталось отправить {} байт (total_sent={}, bytes_read={})", remaining, total_sent, bytes_read);

    //         // 🟢 ОТПРАВКА ДАННЫХ НА СОКЕТ НАЗНАЧЕНИЯ
    //         ssize_t bytes_sent = 0;

    //         // 🟢 ПОИСК SSL* ПО to_fd
    //         SSL *target_ssl = nullptr;
    //         for (const auto &conn : connections_)
    //         {
    //             if (conn.first == to_fd)
    //             {
    //                 target_ssl = conn.second.ssl;
    //                 break;
    //             }
    //         }

    //         if (target_ssl != nullptr)
    //         {
    //             // 🟢 Отправка через SSL_write
    //             LOG_DEBUG("🔒 Отправка данных через SSL_write для клиента (to_fd={})", to_fd);
    //             bytes_sent = SSL_write(target_ssl, buffer + total_sent, remaining);
    //             if (bytes_sent <= 0)
    //             {
    //                 int ssl_error = SSL_get_error(target_ssl, bytes_sent);
    //                 if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
    //                 {
    //                     LOG_WARN("⏸️ SSL_write требует повторной попытки");
    //                     return true; // Ждём следующего цикла
    //                 }
    //                 else
    //                 {
    //                     LOG_ERROR("❌ SSL_write ошибка: {}", ERR_error_string(ERR_get_error(), nullptr));
    //                     return false;
    //                 }
    //             }
    //         }
    //         else
    //         {
    //             // 🟡 Обычная отправка через send
    //             LOG_DEBUG("📤 Отправка данных через send (to_fd={})", to_fd);
    //             bytes_sent = send(to_fd, buffer + total_sent, remaining, 0);
    //             if (bytes_sent < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
    //             {
    //                 LOG_ERROR("❌ send() ошибка: {}", strerror(errno));
    //                 return false;
    //             }
    //         }

    //         // 🟡 ОБРАБОТКА УСПЕШНОЙ ОТПРАВКИ (bytes_sent > 0)
    //         if (bytes_sent > 0)
    //         {
    //             std::string sent_chunk(buffer + total_sent, static_cast<size_t>(bytes_sent));
    //             for (char &c : sent_chunk)
    //             {
    //                 if (c < 32 && c != '\n' && c != '\r' && c != '\t')
    //                     c = '?';
    //             }
    //             LOG_DEBUG("📦 Отправлено содержимое (первые {} байт):\n{}",
    //                       std::min<size_t>(256, sent_chunk.size()),
    //                       sent_chunk.substr(0, std::min<size_t>(256, sent_chunk.size())));
    //         }

    //         // 🟥 ОБРАБОТКА ОШИБКИ ОТПРАВКИ (bytes_sent < 0)
    //         if (bytes_sent < 0)
    //         {
    //             LOG_ERROR("❌ send() или SSL_write вернул ошибку: errno={} ({})", errno, strerror(errno));
    //             if (errno == EAGAIN || errno == EWOULDBLOCK)
    //             {
    //                 LOG_WARN("⏸️ Буфер отправки заполнен, попробуем позже. Отправлено {}/{} байт", total_sent, bytes_read);
    //                 return true; // Ждём следующего цикла
    //             }
    //             else
    //             {
    //                 LOG_ERROR("💥 Критическая ошибка отправки данных: {}", strerror(errno));
    //                 return false;
    //             }
    //         }

    //         // 🟢 ОБНОВЛЕНИЕ СЧЁТЧИКА ОТПРАВЛЕННЫХ БАЙТ
    //         total_sent += bytes_sent;
    //         LOG_DEBUG("📈 total_sent обновлён: {} (отправлено {} байт)", total_sent, bytes_sent);

    //         // 🟡 ОБРАБОТКА ОТПРАВКИ 0 БАЙТ
    //         if (bytes_sent == 0)
    //         {
    //             LOG_WARN("⚠️ send() или SSL_write вернул 0 — возможно, соединение закрыто на стороне получателя");
    //             break;
    //         }
    //     }

    //     // 🟢 ЛОГИРОВАНИЕ УСПЕШНОЙ ПЕРЕДАЧИ ВСЕХ ДАННЫХ
    //     LOG_SUCCESS("🎉 Успешно передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
    //     return true; // Соединение активно, можно продолжать
    // }
    // // 🔵 ОБРАБОТКА ЗАКРЫТИЯ СОЕДИНЕНИЯ (bytes_read == 0)
    // else if (bytes_read == 0)
    // {
    //     /**
    //      * @brief Обработка закрытия соединения удалённой стороной.
    //      * @details recv() или SSL_read() вернули 0 — это сигнал, что клиент или бэкенд закрыли соединение.
    //      *          Соединение нужно закрыть и очистить ресурсы.
    //      */
    //     LOG_INFO("🔚 Клиент (from_fd={}) закрыл соединение", from_fd);
    //     return false;
    // }
    // // 🔵 ОБРАБОТКА ОШИБКИ ЧТЕНИЯ (bytes_read < 0)
    // else
    // {
    //     // Логируем ошибку чтения — диагностическое сообщение.
    //     LOG_DEBUG("⏸️ recv() или SSL_read() вернул -1");
    //     return true;
    // }
}