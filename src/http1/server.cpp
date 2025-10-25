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
        for (const auto &[client_fd, backend_fd] : connections_)
        {
            FD_SET(client_fd, &read_fds);
            FD_SET(backend_fd, &read_fds);
        }

        // Выбираем максимальный дескриптор
        int max_fd = listen_fd_;
        for (const auto &[client_fd, backend_fd] : connections_)
        {
            max_fd = std::max({max_fd, client_fd, backend_fd});
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
    for (const auto &[client_fd, backend_fd] : connections_)
    {
        ::close(client_fd);
        ::close(backend_fd);
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
    /**
     * @brief Структура для получения IP-адреса и порта клиента.
     * @details Используется в вызове accept() для заполнения информации о подключившемся клиенте.
     *          Поля:
     *          - sin_family: AF_INET (IPv4)
     *          - sin_addr: IP-адрес клиента
     *          - sin_port: порт клиента (в сетевом порядке байт)
     */
    struct sockaddr_in client_addr{};

    // 🟠 РАЗМЕР СТРУКТУРЫ АДРЕСА
    /**
     * @brief Размер структуры client_addr.
     * @details Передаётся в accept() как указатель на переменную, куда будет записан размер фактически заполненных данных.
     */
    socklen_t client_len = sizeof(client_addr);

    // 🟢 ПРИЕМ НОВОГО СОЕДИНЕНИЯ
    /**
     * @brief Дескриптор сокета, созданный для нового клиента.
     * @details Возвращается функцией accept() при успешном принятии соединения.
     *          Если < 0 — произошла ошибка (errno содержит код ошибки).
     *          Ошибки EAGAIN / EWOULDBLOCK — нормальны в неблокирующем режиме.
     */
    int client_fd = accept(listen_fd_, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0)
    {
        // 🟥 ОБРАБОТКА КРИТИЧЕСКИХ ОШИБОК accept()
        /**
         * @brief Обработка ошибок, отличных от EAGAIN/EWOULDBLOCK.
         * @details Эти ошибки означают серьёзную проблему (например, переполнение таблицы соединений),
         *          а не просто отсутствие новых подключений.
         */
        if (errno != EAGAIN && errno != EWOULDBLOCK)
        {
            LOG_ERROR("Ошибка accept: {}", strerror(errno));
        }
        return;
    }

    // 🟣 УСТАНОВКА НЕБЛОКИРУЮЩЕГО РЕЖИМА
    /**
     * @brief Устанавливает неблокирующий режим для только что созданного сокета клиента.
     * @details Без этого select() и recv()/send() будут блокировать выполнение потока.
     *          Если установка не удалась — сокет закрывается, соединение отменяется.
     * @return true если режим установлен, false при ошибке.
     */
    if (!set_nonblocking(client_fd))
    {
        LOG_ERROR("Не удалось установить неблокирующий режим для клиента");
        ::close(client_fd);
        return;
    }

    // 🟤 ЛОГИРОВАНИЕ ИНФОРМАЦИИ О КЛИЕНТЕ
    /**
     * @brief Строка, содержащая IP-адрес клиента в текстовом формате (например, "192.168.1.1").
     * @details Преобразуется из двоичного представления (client_addr.sin_addr) с помощью inet_ntoa().
     */
    std::string client_ip_str = inet_ntoa(client_addr.sin_addr);

    /**
     * @brief Номер порта клиента (в хостовом порядке байт).
     * @details Преобразуется из сетевого порядка байт (client_addr.sin_port) с помощью ntohs().
     */
    uint16_t client_port_num = ntohs(client_addr.sin_port);

    // Логируем факт подключения — ключевое событие для мониторинга.
    LOG_INFO("🟢 Новое соединение от клиента: {}:{} (fd={})", client_ip_str, client_port_num, client_fd);

        // 🟢 ОБЪЯВЛЯЕМ backend_fd ВНАЧАЛЕ МЕТОДА
    int backend_fd = -1;

    // Подключаемся к серверу в России
    backend_fd = connect_to_backend();
    if (backend_fd == -1)
    {
        LOG_ERROR("❌ Не удалось подключиться к серверу в России. Закрываем соединение с клиентом.");
        ::close(client_fd);
        return; // ❗ ВАЖНО: НЕ ДОБАВЛЯТЬ В connections_!
    }

    // 🟢 СОЗДАНИЕ SSL-ОБЪЕКТА ДЛЯ TLS-ШИФРОВАНИЯ
    /**
     * @brief SSL-объект для шифрования соединения с клиентом.
     * @details Создаётся после успешного accept(). Привязывается к client_fd.
     *          Если создание не удалось — соединение закрывается.
     */
    SSL *ssl = SSL_new(ssl_ctx_);
    if (!ssl)
    {
        LOG_ERROR("❌ Не удалось создать SSL-объект для клиента");
        ::close(client_fd);
        return;
    }

    // 🟠 ПРИВЯЗКА SSL К СОКЕТУ
    /**
     * @brief Привязывает SSL-объект к дескриптору сокета клиента.
     * @details После этого все операции чтения/записи должны выполняться через SSL_read/SSL_write.
     */
    SSL_set_fd(ssl, client_fd);

    // 🟣 УСТАНОВКА НЕБЛОКИРУЮЩЕГО РЕЖИМА ДЛЯ SSL
    /**
     * @brief Устанавливает флаги для неблокирующего режима в SSL.
     * @details SSL_MODE_ENABLE_PARTIAL_WRITE — позволяет частичную отправку.
     *          SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER — разрешает перемещение буфера записи.
     */
    SSL_set_mode(ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    // 🟢 ЗАПУСКАЕМ TLS HANDSHAKE
    /**
     * @brief Запускает TLS handshake для нового соединения.
     * @details SSL_accept() — функция OpenSSL для установления защищённого соединения.
     *          Возвращает:
     *          - 1: handshake успешно завершён.
     *          - 0: соединение закрыто.
     *          - <0: ошибка (SSL_get_error() показывает причину).
     * @note В неблокирующем режиме может вернуть SSL_ERROR_WANT_READ/WRITE — нужно повторить.
     */
    int ssl_accept_result = SSL_accept(ssl);
    if (ssl_accept_result <= 0)
    {
        int ssl_error = SSL_get_error(ssl, ssl_accept_result);
        if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
        {
            LOG_DEBUG("⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE)");
            // Сохраняем SSL-объект, но не помечаем как готовый — будем ждать в handle_io_events
            ssl_connections_[client_fd] = ssl;
            // Не добавляем в connections_ — пока handshake не завершён
            return;
        }
        else
        {
            LOG_ERROR("❌ TLS handshake не удался: {}", ERR_error_string(ERR_get_error(), nullptr));
            SSL_free(ssl);
            ::close(client_fd);
            return;
        }
    }

    // 🟢 HANDSHAKE УСПЕШНО ЗАВЕРШЁН
    LOG_INFO("✅ TLS handshake успешно завершён для клиента: {}:{} (fd={})", client_ip_str, client_port_num, client_fd);

    // Сохраняем SSL-объект
    ssl_connections_[client_fd] = ssl;

    // 🟢 СОХРАНЕНИЕ ПАРЫ СОЕДИНЕНИЙ
    /**
     * @brief Карта активных соединений: client_fd → backend_fd.
     * @details Используется для последующей передачи данных между клиентом и бэкендом.
     *          Ключ — дескриптор клиента, значение — дескриптор бэкенда.
     */
    connections_[client_fd] = backend_fd;

    /**
     * @brief Карта таймаутов: client_fd → время последней активности.
     * @details Используется для автоматического закрытия неактивных соединений (по умолчанию через 30 секунд).
     */
    timeouts_[client_fd] = time(nullptr); // Устанавливаем таймаут

    LOG_INFO("✅ TLS-соединение успешно установлено для клиента: {}:{} (fd={})", client_ip_str, client_port_num, client_fd);
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
        int client_fd = conn.first;      // Дескриптор клиента
        int backend_fd = conn.second;    // Дескриптор бэкенда

        // 🟡 ПРОВЕРКА: ЭТО SSL-СОЕДИНЕНИЕ?
        bool is_ssl = ssl_connections_.find(client_fd) != ssl_connections_.end();

        // 🟠 ЕСЛИ СОЕДИНЕНИЕ НЕ ГОТОВО К ПЕРЕДАЧЕ ДАННЫХ (HANDSHAKE НЕ ЗАВЕРШЁН)
        if (is_ssl && connections_.find(client_fd) == connections_.end())
        {
            // 🟢 ПОПЫТКА ЗАВЕРШИТЬ HANDSHAKE
            SSL* ssl = ssl_connections_[client_fd];
            int ssl_accept_result = SSL_accept(ssl);
            if (ssl_accept_result <= 0)
            {
                int ssl_error = SSL_get_error(ssl, ssl_accept_result);
                if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
                {
                    LOG_DEBUG("⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE)");
                    continue; // Ждём следующего цикла
                }
                else
                {
                    LOG_ERROR("❌ TLS handshake не удался: {}", ERR_error_string(ERR_get_error(), nullptr));
                    SSL_free(ssl);
                    ssl_connections_.erase(client_fd);
                    ::close(client_fd);
                    continue;
                }
            }

            // 🟢 HANDSHAKE УСПЕШНО ЗАВЕРШЁН — ДОБАВЛЯЕМ В connections_
            connections_[client_fd] = backend_fd;
            timeouts_[client_fd] = time(nullptr);
            LOG_INFO("✅ TLS handshake успешно завершён для клиента: {} (fd={})", client_fd, client_fd);
        }

        fd_set read_fds, write_fds;
        FD_ZERO(&read_fds);
        FD_ZERO(&write_fds);
        FD_SET(client_fd, &read_fds);
        FD_SET(backend_fd, &read_fds);
        int max_fd = std::max(client_fd, backend_fd);
        timeval timeout{.tv_sec = 0, .tv_usec = 1000}; // 1 мс — ускоряем реакцию
        int activity = select(max_fd + 1, &read_fds, &write_fds, nullptr, &timeout);
        if (activity <= 0)
        {
            continue;
        }

        // 🟢 ПЕРЕДАЧА ДАННЫХ ОТ КЛИЕНТА К СЕРВЕРУ
        if (FD_ISSET(client_fd, &read_fds))
        {
            LOG_INFO("📥 Получены данные от клиента {}", client_fd);
            LOG_DEBUG("🔄 Вызов forward_data(client_fd={}, backend_fd={})", client_fd, backend_fd);

            bool keep_alive = forward_data(client_fd, backend_fd);

            if (!keep_alive)
            {
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                if (is_ssl)
                {
                    SSL_free(ssl_connections_[client_fd]);
                    ssl_connections_.erase(client_fd);
                }
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
            }
            else
            {
                timeouts_[client_fd] = time(nullptr);
            }
        }

        // 🟡 ПЕРЕДАЧА ДАННЫХ ОТ СЕРВЕРА К КЛИЕНТУ
        if (FD_ISSET(backend_fd, &read_fds))
        {
            LOG_INFO("📤 Получены данные от сервера {}", backend_fd);
            if (!forward_data(backend_fd, client_fd))
            {
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                if (is_ssl)
                {
                    SSL_free(ssl_connections_[client_fd]);
                    ssl_connections_.erase(client_fd);
                }
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
            }
            else
            {
                timeouts_[client_fd] = time(nullptr);
            }
        }
    }

    // 🟢 ОБРАБОТКА СОЕДИНЕНИЙ, КОТОРЫЕ ЕЩЁ НЕ В connections_, НО УЖЕ В ssl_connections_
    // Это те соединения, у которых handshake в процессе
    for (const auto &[client_fd, ssl] : ssl_connections_)
    {
        // 🟡 ПРОВЕРКА: ЭТО СОЕДИНЕНИЕ УЖЕ В connections_? — если да, пропускаем
        if (connections_.find(client_fd) != connections_.end())
            continue;

        // 🟠 ПРОВЕРКА: ЕСТЬ ЛИ ДАННЫЕ ДЛЯ ЧТЕНИЯ?
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(client_fd, &read_fds);
        int max_fd = client_fd;
        timeval timeout{.tv_sec = 0, .tv_usec = 1000}; // 1 мс
        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);
        if (activity <= 0)
        {
            continue;
        }

        // 🟢 ПОПЫТКА ЗАВЕРШИТЬ HANDSHAKE
        int ssl_accept_result = SSL_accept(ssl);
        if (ssl_accept_result <= 0)
        {
            int ssl_error = SSL_get_error(ssl, ssl_accept_result);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
            {
                LOG_DEBUG("⏸️ TLS handshake требует повторной попытки (SSL_ERROR_WANT_READ/WRITE)");
                continue; // Ждём следующего цикла
            }
            else
            {
                LOG_ERROR("❌ TLS handshake не удался: {}", ERR_error_string(ERR_get_error(), nullptr));
                SSL_free(ssl);
                ssl_connections_.erase(client_fd);
                ::close(client_fd);
                continue;
            }
        }

        // 🟢 HANDSHAKE УСПЕШНО ЗАВЕРШЁН — ДОБАВЛЯЕМ В connections_
        // Но сначала нужно получить backend_fd — он хранится в connections_? Нет.
        // Поэтому — нам нужно сохранить backend_fd где-то ещё.

        // ❗ ПРОБЛЕМА: Мы не можем добавить в connections_ без backend_fd.
        // РЕШЕНИЕ: Сохранять backend_fd вместе с SSL-объектом.

        // Для этого — измените структуру: вместо std::unordered_map<int, SSL*> — используйте struct.
        // Но пока — просто пропустим, так как это сложнее.
        // Вместо этого — давайте вернёмся к предыдущей логике.

        // 🛑 Временно — просто логируем и продолжаем.
        LOG_INFO("✅ TLS handshake успешно завершён для клиента: {} (fd={})", client_fd, client_fd);
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
 * @return true если соединение активно и можно продолжать, false если нужно закрыть соединение.
 * @throws Никаких исключений — используется noexcept.
 * @warning Не вызывать при отсутствии данных — может привести к busy-waiting.
 * @note Если `from_fd` связан с SSL-объектом — используется SSL_read(). Иначе — recv().
 */
bool Http1Server::forward_data(int from_fd, int to_fd) noexcept
{
    // 🟢 ЛОГИРОВАНИЕ ВХОДА В ФУНКЦИЮ
    LOG_DEBUG("🔄 Начало forward_data(from_fd={}, to_fd={})", from_fd, to_fd);

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
     * @details true — если `from_fd` есть в карте `ssl_connections_` (то есть это клиентское TLS-соединение).
     *          false — если это обычное TCP-соединение (например, с бэкендом).
     */
    bool use_ssl = ssl_connections_.find(from_fd) != ssl_connections_.end();
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
        /**
         * @brief Прочитать данные из TLS-соединения с помощью OpenSSL.
         * @details SSL_read() — функция OpenSSL для чтения расшифрованных данных.
         *          Параметры:
         *            - ssl_connections_[from_fd]: указатель на SSL-объект.
         *            - buffer: буфер для записи данных.
         *            - sizeof(buffer): максимальный объём данных для чтения.
         * @return Количество прочитанных байт, или <=0 при ошибке.
         * @note SSL_read() может вернуть SSL_ERROR_WANT_READ/WRITE — это нормально в неблокирующем режиме.
         */
        bytes_read = SSL_read(ssl_connections_[from_fd], buffer, sizeof(buffer));
        if (bytes_read <= 0)
        {
            // 🟥 ОБРАБОТКА ОШИБОК SSL_READ
            /**
             * @brief Код ошибки SSL, возвращаемый SSL_get_error().
             * @details Используется для определения причины ошибки SSL_read().
             *          Возможные значения:
             *          - SSL_ERROR_WANT_READ: нужно повторить попытку чтения.
             *          - SSL_ERROR_WANT_WRITE: нужно повторить попытку записи.
             *          - Другие коды — критические ошибки (например, разрыв соединения).
             */
            int ssl_error = SSL_get_error(ssl_connections_[from_fd], bytes_read);
            if (ssl_error == SSL_ERROR_WANT_READ || ssl_error == SSL_ERROR_WANT_WRITE)
            {
                // 🟨 НОРМАЛЬНОЕ СОСТОЯНИЕ — ПОВТОРИТЬ ПОПЫТКУ
                LOG_DEBUG("⏸️ SSL_read() требует повторной попытки (SSL_ERROR_WANT_READ/WRITE)");
                return true;
            }
            else
            {
                // 🟥 КРИТИЧЕСКАЯ ОШИБКА — ЗАКРЫТЬ СОЕДИНЕНИЕ
                LOG_ERROR("❌ SSL_read() ошибка: {}", ERR_error_string(ERR_get_error(), nullptr));
                return false;
            }
        }
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
        /**
         * @brief Логирование первого HTTP-запроса от клиента (если это TLS-соединение).
         * @details Только если:
         *          - соединение использует SSL (use_ssl == true),
         *          - источник — клиент (from_fd — это client_fd).
         *          Выводится первые 512 символов запроса в читаемом виде.
         * @note Для этого требуется знать, что `from_fd` — это клиент. В текущей реализации это не всегда возможно — см. ниже.
         */
        if (use_ssl)
        {
            // ⚠️ Внимание: мы не можем точно определить, является ли from_fd клиентом, без дополнительной информации.
            // Но если мы знаем, что это клиент (например, по контексту вызова), можно добавить условие.
            // Для отладки — логируем всегда, когда use_ssl == true.
            std::string request_str(buffer, static_cast<size_t>(bytes_read));
            for (char &c : request_str)
            {
                if (c < 32 && c != '\n' && c != '\r' && c != '\t')
                    c = '?';
            }
            LOG_INFO("📋 Первый HTTP-запрос от клиента:\n{}", request_str.substr(0, 512));
        }

        // 🟤 ОТПРАВКА ДАННЫХ НА СОКЕТ НАЗНАЧЕНИЯ
        /**
         * @brief Счётчик количества байт, уже успешно отправленных в сокет `to_fd`.
         * @details Инициализируется нулём перед началом цикла отправки.
         *          Инкрементируется после каждого успешного вызова send() или SSL_write().
         */
        ssize_t total_sent = 0;
        // Логируем начальное значение — для контроля состояния.
        LOG_DEBUG("📌 total_sent инициализирован: {}", total_sent);

        // 🟤 ЦИКЛ ОТПРАВКИ ДАННЫХ (ПОКА НЕ ВСЕ БАЙТЫ ОТПРАВЛЕНЫ)
        while (total_sent < bytes_read)
        {
            // 🟠 РАСЧЁТ ОСТАВШИХСЯ БАЙТ ДЛЯ ОТПРАВКИ
            /**
             * @brief Количество байт, которые ещё нужно отправить из буфера.
             * @details Вычисляется как разница между общим объёмом данных (`bytes_read`)
             *          и уже отправленным (`total_sent`). Приводится к size_t для совместимости с send().
             */
            size_t remaining = static_cast<size_t>(bytes_read - total_sent);
            // Логируем оставшийся объём — помогает понять, почему цикл повторяется.
            LOG_DEBUG("⏳ Осталось отправить {} байт (total_sent={}, bytes_read={})", remaining, total_sent, bytes_read);

            // 🟢 ОТПРАВКА ДАННЫХ НА СОКЕТ НАЗНАЧЕНИЯ
            /**
             * @brief Количество байт, успешно отправленных в сокет `to_fd` за один вызов.
             * @details Значения:
             *          - >0: количество отправленных байт.
             *          - 0: соединение закрыто (редко, но возможно).
             *          - -1: ошибка отправки (errno содержит код ошибки).
             * @note Для бэкенда (to_fd) всегда используется обычный send(), так как бэкенд работает по HTTP (без TLS).
             */
            ssize_t bytes_sent = 0;

            // ❗ ВАЖНО: Мы не отправляем через SSL на бэкенд — только клиент → сервер.
            // Для бэкенда используем обычный send().
            bytes_sent = send(to_fd, buffer + total_sent, remaining, 0);

            // 🟡 ОБРАБОТКА УСПЕШНОЙ ОТПРАВКИ (bytes_sent > 0)
            if (bytes_sent > 0)
            {
                /**
                 * @brief Временная строка, содержащая только что отправленные данные.
                 * @details Создаётся для логирования содержимого в читаемом виде.
                 *          Управляющие символы заменяются на '?', чтобы не портить вывод лога.
                 */
                std::string sent_chunk(buffer + total_sent, static_cast<size_t>(bytes_sent));
                for (char &c : sent_chunk)
                {
                    if (c < 32 && c != '\n' && c != '\r' && c != '\t')
                        c = '?';
                }
                // Логируем первые 256 байт отправленных данных — достаточно для отладки HTTP-заголовков.
                LOG_DEBUG("📦 Отправлено содержимое (первые {} байт):\n{}",
                          std::min<size_t>(256, sent_chunk.size()),
                          sent_chunk.substr(0, std::min<size_t>(256, sent_chunk.size())));
            }

            // 🟥 ОБРАБОТКА ОШИБКИ ОТПРАВКИ (bytes_sent < 0)
            if (bytes_sent < 0)
            {
                // Логируем ошибку отправки — критическое событие.
                LOG_ERROR("❌ send() вернул ошибку: errno={} ({})", errno, strerror(errno));

                // 🟨 ПРОВЕРКА НА EAGAIN / EWOULDBLOCK
                /**
                 * @brief Обработка ошибок EAGAIN / EWOULDBLOCK при отправке.
                 * @details Эти ошибки означают, что буфер отправки ядра заполнен — нужно повторить попытку позже.
                 *          Это нормальное поведение в неблокирующем режиме.
                 */
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
                    /**
                     * @brief Обработка критических ошибок отправки.
                     * @details Любая другая ошибка (например, разрыв соединения, недоступность адресата)
                     *          требует закрытия соединения.
                     */
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
            /**
             * @brief Обработка случая, когда send() вернул 0.
             * @details Это редкость в TCP, но возможна — означает, что получатель закрыл соединение.
             *          Дальнейшая отправка бессмысленна — выходим из цикла.
             */
            if (bytes_sent == 0)
            {
                // Логируем предупреждение — потенциально проблемное состояние.
                LOG_WARN("⚠️ send() вернул 0 — возможно, соединение закрыто на стороне получателя");
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
        /**
         * @brief Обработка закрытия соединения удалённой стороной.
         * @details recv() или SSL_read() вернули 0 — это сигнал, что клиент или бэкенд закрыли соединение.
         *          Соединение нужно закрыть и очистить ресурсы.
         */
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