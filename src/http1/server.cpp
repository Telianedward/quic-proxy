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

    // chunked_complete_[client_fd] = false; // Для нового соединения
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
    if (!ssl)
    {
        LOG_ERROR(" ❌ Не удалось создать SSL-объект для клиента");
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

    LOG_INFO("✅ TLS-соединение создано, но handshake не завершён. Ожидаем данные для продолжения.");

    // 🟢 ЗАПУСКАЕМ TLS HANDSHAKE
    int ssl_accept_result = SSL_accept(ssl);
    if (ssl_accept_result <= 0)
    {
        int ssl_error = SSL_get_error(ssl, ssl_accept_result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            if (!info.logged_handshake_want)
            {
                LOG_DEBUG("⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE)");
                info.logged_handshake_want = true;
            }
            return true;
        }
        else
        {
            info.logged_handshake_want = false; // Сброс при новой попытке
        }
    }

    // 🟢 HANDSHAKE УСПЕШНО ЗАВЕРШЁН
    LOG_INFO(" ✅ TLS handshake успешно завершён для клиента: {}:{} (fd={})",
             client_ip_str, client_port_num, client_fd);

    // Обновляем информацию — помечаем handshake как завершённый
    info.handshake_done = true;
    connections_[client_fd] = info;

    LOG_INFO(" ✅ TLS-соединение успешно установлено для клиента: {}:{} (fd={})",
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

                    // 🟢 Не логируем каждый раз — только при первом входе в handshake
                    if (!info.handshake_done && !info.logged_handshake_want)
                    {
                        LOG_DEBUG("⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE)");
                        info.logged_handshake_want = true; // 👈 Установка флага
                    }
                    return; // ✅ Функция void — return без значения
                }
                else
                {
                    // 🟢 Сброс флага при новой попытке handshake
                    info.logged_handshake_want = false;

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
            LOG_INFO(" 📥 Получены данные от клиента {} (fd={})", client_fd, client_fd);
            LOG_DEBUG("🔄 Начало обработки данных через forward_data: from_fd={}, to_fd={}", client_fd, info.backend_fd);

            if (info.ssl != nullptr)
            {
                LOG_DEBUG(" 🔐 SSL-соединение активно. Подготовка к чтению данных через SSL");
            }

            // 🟢 СНАЧАЛА ПРОВЕРЯЕМ НЕЗАВЕРШЁННЫЕ ОТПРАВКИ ДЛЯ БЭКЕНДА
            if (!pending_sends_.empty() && pending_sends_.find(info.backend_fd) != pending_sends_.end() && !pending_sends_[info.backend_fd].empty())
            {
                auto &pending_queue = pending_sends_[info.backend_fd];
                while (!pending_queue.empty())
                {
                    auto &pending = pending_queue.front();
                    if (pending.fd != info.backend_fd)
                    {
                        pending_queue.pop();
                        continue;
                    }

                    ssize_t bytes_sent = send(pending.fd, pending.data.get() + pending.sent, pending.len - pending.sent, MSG_NOSIGNAL);
                    if (bytes_sent <= 0)
                    {
                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                        {
                            LOG_WARN("⏸️ Буфер отправки на бэкенд заполнен");
                            continue; // Оставляем в очереди
                        }
                        else
                        {
                            LOG_ERROR("❌ send() ошибка при отправке на бэкенд: {}", strerror(errno));
                            pending_queue.pop();
                            continue;
                        }
                    }

                    pending.sent += bytes_sent;
                    LOG_DEBUG("📈 Отправлено {} байт на бэкенд, всего {}/{}", bytes_sent, pending.sent, pending.len);

                    if (pending.sent >= pending.len)
                    {
                        pending_queue.pop(); // Успешно отправили всю порцию
                    }
                    else
                    {
                        continue; // Остались неотправленные данные
                    }
                }
            }

            // 🟢 ТЕПЕРЬ ЧИТАЕМ НОВЫЕ ДАННЫЕ ОТ КЛИЕНТА
            bool keep_alive = forward_data(client_fd, info.backend_fd, info.ssl); // 👈 Передаём ssl

            if (!keep_alive)
            {
                // 🟢 Если клиент уже закрыл соединение — не вызываем SSL_shutdown()
                if (is_ssl && info.ssl)
                {
                    // 🟢 ПРОВЕРЯЕМ, ГОТОВ ЛИ SSL К SHUTDOWN
                    if (SSL_is_init_finished(info.ssl))
                    {
                        LOG_DEBUG("🔄 Вызов SSL_shutdown() для клиента {}", client_fd);
                        int shutdown_result = SSL_shutdown(info.ssl);
                        if (shutdown_result < 0)
                        {
                            int ssl_error = SSL_get_error(info.ssl, shutdown_result);
                            if (ssl_error != SSL_ERROR_SYSCALL && ssl_error != SSL_ERROR_SSL)
                            {
                                LOG_DEBUG("⚠️ SSL_shutdown() в процессе: {}", ssl_error);
                            }
                        }
                    }
                    else
                    {
                        LOG_DEBUG("⏸️ SSL не готов к shutdown - пропускаем");
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
        if (FD_ISSET(info.backend_fd, &read_fds))
        {
            LOG_INFO("📤 Получены данные от сервера {}", info.backend_fd);

            // 🔴 ПРОВЕРКА: ЗАВЕРШЁН ЛИ HANDSHAKE?
            if (info.ssl != nullptr && !info.handshake_done)
            {
                LOG_WARN("❗ Нельзя отправлять данные клиенту, пока handshake не завершён. Пропускаем.");
                continue; // Пропускаем эту итерацию, ждём завершения handshake
            }

            // 🟢 Передаём данные
            bool keep_alive = forward_data(info.backend_fd, client_fd, nullptr); // 👈 Передаём nullptr, так как данные от бэкенда не шифруются

            if (!keep_alive)
            {
                // 🟢 Если клиент уже закрыл соединение — не вызываем SSL_shutdown()
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
                        LOG_DEBUG(" 🔄 Вызов SSL_shutdown() для клиента {}", client_fd);
                        int shutdown_result = SSL_shutdown(info.ssl);
                        if (shutdown_result < 0)
                        {
                            LOG_WARN(" ⚠️ SSL_shutdown() вернул ошибку: {}",
                                     ERR_error_string(ERR_get_error(), nullptr));
                        }
                        else
                        {
                            LOG_INFO(" ✅ SSL_shutdown() успешно завершён для клиента {}", client_fd);
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
                // 🟢 ПРОВЕРЯЕМ, ЗАВЕРШЕН ЛИ ЧАНК
                if (chunked_complete_.find(client_fd) != chunked_complete_.end())
                {
                    if (chunked_complete_[client_fd])
                    {
                        // 🟢 Чанки завершены — можно закрыть соединение
                        LOG_INFO("✅ Все чанки отправлены. Закрываем соединение для клиента {}", client_fd);
                        ::close(client_fd);
                        ::close(info.backend_fd);
                        connections_.erase(client_fd);
                        timeouts_.erase(client_fd);
                        if (is_ssl && info.ssl)
                        {
                            SSL_free(info.ssl);
                        }
                        LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, info.backend_fd);
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
    }
}

SSL *Http1Server::get_ssl_for_fd(int fd) noexcept
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
                return true;
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

    // 🟢 ПРОСТАЯ ПЕРЕДАЧА ДАННЫХ БЕЗ CHUNKED PROCESSING
    SSL *target_ssl = get_ssl_for_fd(to_fd);
    LOG_DEBUG("[WRITE] 🎯 Целевой fd={} имеет SSL? {}", to_fd, target_ssl ? "да" : "нет");

    // 🟢 ПРОВЕРКА: ЕСТЬ ЛИ НЕЗАВЕРШЁННЫЕ ОТПРАВКИ?
    if (!pending_sends_.empty() && pending_sends_.find(to_fd) != pending_sends_.end() && !pending_sends_[to_fd].empty())
    {
        LOG_INFO("[PENDING] 🕒 Есть незавершённые отправки для fd={}", to_fd);
        auto &pending_queue = pending_sends_[to_fd];

        while (!pending_queue.empty())
        {
            auto &pending = pending_queue.front();
            if (pending.fd != to_fd)
            {
                LOG_WARN("[PENDING] 🗑️ Некорректный fd в очереди — пропускаем элемент");
                pending_queue.pop();
                continue;
            }

            // 🟠 ПОПЫТКА ОТПРАВИТЬ ОСТАВШИЕСЯ ДАННЫЕ
            LOG_DEBUG("[PENDING] 📤 Отправка оставшихся {} байт из {} (уже отправлено {})",
                      pending.len - pending.sent, pending.len, pending.sent);

            ssize_t bytes_sent = 0;
            if (target_ssl != nullptr)
            {
                LOG_INFO("[PENDING] 🔐 SSL_write для fd={}", to_fd);
                bytes_sent = SSL_write(target_ssl, pending.data.get() + pending.sent, pending.len - pending.sent);
            }
            else
            {
                LOG_INFO("[PENDING] 📤 send() для fd={}", to_fd);
                bytes_sent = send(to_fd, pending.data.get() + pending.sent, pending.len - pending.sent, MSG_NOSIGNAL);
            }

            if (bytes_sent <= 0)
            {
                if (target_ssl != nullptr)
                {
                    int ssl_error = SSL_get_error(target_ssl, bytes_sent);
                    if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
                    {
                        LOG_WARN("[PENDING] ⏳ SSL_write требует повторной попытки — оставляем в очереди");
                        return true; // Оставляем в очереди
                    }
                    else
                    {
                        LOG_ERROR("[PENDING] ❌ SSL_write фатальная ошибка: {}",
                                  ERR_error_string(ERR_get_error(), nullptr));
                        pending_queue.pop(); // Удаляем из очереди при фатальной ошибке
                        return false;
                    }
                }
                else
                {
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                    {
                        LOG_WARN("[PENDING] ⏳ send() вернул EAGAIN/EWOULDBLOCK — буфер заполнен");
                        return true;
                    }
                    else
                    {
                        LOG_ERROR("[PENDING] ❌ send() фатальная ошибка: {}", strerror(errno));
                        pending_queue.pop();
                        return false;
                    }
                }
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

    ssize_t bytes_sent = 0;
    if (target_ssl != nullptr)
    {
        LOG_INFO("[NEW] 🔐 SSL_write для нового блока на fd={}", to_fd);
        bytes_sent = SSL_write(target_ssl, new_send.data.get(), new_send.len);
    }
    else
    {
        LOG_INFO("[NEW] 📤 send() для нового блока на fd={}", to_fd);
        bytes_sent = send(to_fd, new_send.data.get(), new_send.len, MSG_NOSIGNAL);
    }

    if (bytes_sent <= 0)
    {
        if (target_ssl != nullptr)
        {
            int ssl_error = SSL_get_error(target_ssl, bytes_sent);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
            {
                LOG_WARN("[NEW] ⏳ SSL_write требует повторной попытки — добавляем в очередь");
                pending_sends_[to_fd].push(std::move(new_send));
                return true;
            }
            else
            {
                LOG_ERROR("[NEW] ❌ SSL_write фатальная ошибка: {}",
                          ERR_error_string(ERR_get_error(), nullptr));
                return false;
            }
        }
        else
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                LOG_WARN("[NEW] ⏳ send() вернул EAGAIN/EWOULDBLOCK — буфер заполнен");
                pending_sends_[to_fd].push(std::move(new_send));
                return true;
            }
            else
            {
                LOG_ERROR("[NEW] ❌ send() фатальная ошибка: {}", strerror(errno));
                return false;
            }
        }
    }

    // Успешно отправили всё сразу
    LOG_SUCCESS("🎉 Успешно передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
    LOG_DEBUG(" 🔄 Конец forward_data — соединение остаётся активным");
    return true;
}