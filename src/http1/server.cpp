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
    : listen_fd_(-1), port_(port), backend_ip_(backend_ip), backend_port_(backend_port) {}

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
/**
 * @brief Обрабатывает новое входящее TCP-соединение от клиента.
 *
 * Принимает соединение с помощью accept(), устанавливает неблокирующий режим,
 * логирует адрес клиента, подключается к бэкенд-серверу в России через WireGuard,
 * и сохраняет пару (клиентский сокет — бэкендовый сокет) для дальнейшего проксирования.
 *
 * @throws Никаких исключений — используется noexcept.
 * @warning Если подключение к бэкенду не удалось — соединение с клиентом закрывается без добавления в connections_.
 * @note Этот метод вызывается из main loop при событии FD_ISSET(listen_fd_, &read_fds).
 */
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

    // 🟠 ПОДКЛЮЧЕНИЕ К БЭКЕНДУ В РОССИИ
    /**
     * @brief Дескриптор сокета, подключённого к бэкенд-серверу в России.
     * @details Создаётся с помощью connect_to_backend(). Если == -1 — подключение не удалось.
     *          В этом случае соединение с клиентом закрывается без добавления в connections_.
     */
    int backend_fd = connect_to_backend();
    if (backend_fd == -1)
    {
        LOG_ERROR("❌ Не удалось подключиться к серверу в России. Закрываем соединение с клиентом.");
        ::close(client_fd);
        return; // ❗ ВАЖНО: НЕ ДОБАВЛЯТЬ В connections_!
    }

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
}


void Http1Server::handle_io_events() noexcept
{
    auto connections_copy = connections_;
    for (const auto &[client_fd, backend_fd] : connections_copy)
    {
        if (backend_fd == -1)
        { // 👈 Защита от некорректных дескрипторов
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
        if (activity <= 0)
        {
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
        if (FD_ISSET(client_fd, &read_fds))
        {
            LOG_INFO("📥 Получены данные от клиента {}", client_fd);
            LOG_DEBUG("🔄 Вызов forward_data(client_fd={}, backend_fd={})", client_fd, backend_fd);

            // 🟢 ЛОГИРОВАНИЕ ПЕРВОГО HTTP-ЗАПРОСА (СЫРОЙ ДАННЫХ)
            /**
             * @brief Буфер для временного хранения первых байт HTTP-запроса.
             * @details Размер 1024 байта — достаточно для заголовков и начала тела запроса.
             */
            char request_buffer[1024];
            // Попробуем прочитать данные без удаления из очереди (Peek)
            ssize_t peeked = recv(client_fd, request_buffer, sizeof(request_buffer), MSG_PEEK);
            if (peeked > 0)
            {
                // Создаём строку для логирования (без нулевого символа — безопасно)
                std::string request_str(request_buffer, static_cast<size_t>(peeked));
                // Убираем непечатаемые символы для читаемости
                for (char &c : request_str)
                {
                    if (c < 32 && c != '\n' && c != '\r' && c != '\t')
                        c = '?';
                }
                LOG_INFO("📋 Первый HTTP-запрос от клиента:\n{}", request_str.substr(0, 512)); // первые 512 символов
            }
            else if (peeked == 0)
            {
                LOG_WARN("⚠️ Клиент {} закрыл соединение до отправки данных", client_fd);
            }
            else if (peeked < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
            {
                LOG_ERROR("❌ Ошибка peek() для клиента {}: {}", client_fd, strerror(errno));
            }

            bool keep_alive = forward_data(client_fd, backend_fd);

            LOG_DEBUG("⬅️ forward_data вернул: {}", keep_alive ? "true" : "false");

            if (!keep_alive)
            {
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
            }
            else
            {
                timeouts_[client_fd] = time(nullptr);
                LOG_DEBUG("⏱️ Таймаут обновлён для client_fd={}: {}", client_fd, timeouts_[client_fd]);
            }
        }

        // Передача данных от сервера к клиенту
        if (FD_ISSET(backend_fd, &read_fds))
        {
            LOG_INFO("📤 Получены данные от сервера {}", backend_fd);
            if (!forward_data(backend_fd, client_fd))
            {
                ::close(client_fd);
                ::close(backend_fd);
                connections_.erase(client_fd);
                timeouts_.erase(client_fd);
                LOG_INFO("TCP-соединение закрыто: клиент {}, бэкенд {}", client_fd, backend_fd);
            }
            else
            {
                timeouts_[client_fd] = time(nullptr);
            }
        }
    }
}

/**
 * @brief Передаёт данные между двумя сокетами (клиент ↔ бэкенд) в неблокирующем режиме.
 *
 * Основная задача — прочитать данные с одного сокета (`from_fd`) и отправить их на другой (`to_fd`),
 * при этом корректно обрабатывая частичную отправку (EAGAIN/EWOULDBLOCK), ошибки и закрытие соединения.
 * Используется для проксирования HTTP/1.1 трафика через WireGuard-туннель.
 *
 * @param from_fd Дескриптор сокета источника (клиент или бэкенд).
 * @param to_fd Дескриптор сокета назначения (бэкенд или клиент).
 * @return true если соединение активно и можно продолжать, false если нужно закрыть соединение.
 * @throws Никаких исключений — используется noexcept.
 * @warning Не вызывать при отсутствии данных — может привести к busy-waiting.
 */
bool Http1Server::forward_data(int from_fd, int to_fd) noexcept
{
    // 🟢 ЛОГИРОВАНИЕ ВХОДА В ФУНКЦИЮ
    // Уровень DEBUG: информационный вывод для отладки потока данных.
    LOG_DEBUG("🔄 Начало forward_data(from_fd={}, to_fd={})", from_fd, to_fd);

    // 🟡 БУФЕР ДЛЯ ПРИЁМА ДАННЫХ
    /**
     * @brief Буфер для временного хранения данных, полученных из сокета.
     * Выделяется статически на стеке — 8 КБ (8192 байта).
     * @details Размер 8192 байта выбран как оптимальный для TCP-прокси: достаточно для одного пакета,
     *          не слишком велик для стека, обеспечивает хорошую производительность.
     * Это стандартный размер для TCP-буфера, обеспечивает хорошую производительность без избыточного выделения памяти
     */
    char buffer[8192];
    // Логируем размер буфера для контроля.
    LOG_DEBUG("📦 Буфер создан: размер {} байт", sizeof(buffer));

    // 🟠 ЧТЕНИЕ ДАННЫХ СО СОКЕТА ИСТОЧНИКА
        /**
     * @brief Количество байт, успешно прочитанных из сокета `from_fd`.
    * recv() — системный вызов для чтения данных из сокета.
    * @details Параметры:
    *           - from_fd: дескриптор сокета, откуда читаем (клиент или бэкенд).
    *           - buffer: указатель на буфер для записи данных.
    *           - sizeof(buffer): максимальное количество байт для чтения.
    *           - 0: флаги — без специальных опций.
     * @details Значения:
     *          - >0: количество прочитанных байт.
     *          - 0: удалённая сторона закрыла соединение.
     *          - -1: ошибка чтения (errno содержит код ошибки).
     */

    ssize_t bytes_read = recv(from_fd, buffer, sizeof(buffer), 0);
    // Логируем результат чтения — ключевое событие для трассировки.
    LOG_DEBUG("📥 recv(from_fd={}, buffer_size={}) вернул bytes_read={}", from_fd, sizeof(buffer), bytes_read);

    // 🔵 ОБРАБОТКА УСПЕШНОГО ЧТЕНИЯ (bytes_read > 0)
    if (bytes_read > 0)
    {
        // Логируем факт получения данных — важное событие для мониторинга.
        LOG_INFO("✅ Получено {} байт данных от клиента (from_fd={})", bytes_read, from_fd);

              // 🟣 ПЕРЕМЕННАЯ ДЛЯ СЧЁТА ОТПРАВЛЕННЫХ БАЙТ
        /**
         * @brief Счётчик количества байт, уже успешно отправленных в сокет `to_fd`.
         * @details Инициализируется нулём перед началом цикла отправки.
         *          Инкрементируется после каждого успешного вызова send().
         *  total_sent — сколько байт уже было успешно отправлено из буфера.
         */
        ssize_t total_sent = 0;
        // Логируем начальное значение — для контроля состояния.
        LOG_DEBUG("📌 total_sent инициализирован: {}", total_sent);

        // 🟤 ЦИКЛ ОТПРАВКИ ДАННЫХ (ПОКА НЕ ВСЕ БАЙТЫ ОТПРАВЛЕНЫ)
        // Цикл нужен потому, что send() может отправить не все данные за один вызов,
        // особенно в неблокирующем режиме или при заполнении буфера ядра.
        while (total_sent < bytes_read)
        {

            // 🟠 РАСЧЁТ ОСТАВШИХСЯ БАЙТ ДЛЯ ОТПРАВКИ
            /**
             * @brief Количество байт, которые ещё нужно отправить из буфера.
             * @details Вычисляется как разница между общим объёмом данных (`bytes_read`)
             *          и уже отправленным (`total_sent`). Приводится к size_t для совместимости с send().
             * remaining — сколько байт ещё нужно отправить
             * иводим тип к size_t, так как send() ожидает size_t.
             */
            size_t remaining = static_cast<size_t>(bytes_read - total_sent);
            // Логируем оставшийся объём — помогает понять, почему цикл повторяется.
            LOG_DEBUG("⏳ Осталось отправить {} байт (total_sent={}, bytes_read={})", remaining, total_sent, bytes_read);

            // 🟢 ОТПРАВКА ДАННЫХ НА СОКЕТ НАЗНАЧЕНИЯ
            /**
             * @brief Количество байт, успешно отправленных в сокет `to_fd` за один вызов send().
             *             // send() — системный вызов для отправки данных.
            * @details  Параметры:
            *           - to_fd: дескриптор сокета, куда отправляем.
            *           - buffer + total_sent: указатель на начало части буфера, которую ещё не отправили.
            *           - remaining: количество байт, которые нужно отправить сейчас.
            *           - 0: флаги — без специальных опций.
            * @details Значения:
            *          - >0: количество отправленных байт.
            *          - 0: соединение закрыто (редко, но возможно).
            *          - -1: ошибка отправки (errno содержит код ошибки).
            */
            ssize_t bytes_sent = send(to_fd, buffer + total_sent, remaining, 0);
            // Логируем результат отправки — ключевой момент для диагностики.
            LOG_DEBUG("📤 send(to_fd={}, offset={}, size={}) вернул bytes_sent={}",
                      to_fd, total_sent, remaining, bytes_sent);

            // 🟡 ОБРАБОТКА УСПЕШНОЙ ОТПРАВКИ (bytes_sent > 0)
            if (bytes_sent > 0)
            {
                /**
                 * @brief Временная строка, содержащая только что отправленные данные.
                 * @details Создаётся для логирования содержимого в читаемом виде.
                 *          Управляющие символы заменяются на '?', чтобы не портить вывод лога.
                 * sent_chunk — временная строка, содержащая только что отправленные данные.
                 * Используется для вывода содержимого в лог (в ограниченном объёме).
                 */
                std::string sent_chunk(buffer + total_sent, static_cast<size_t>(bytes_sent));
                // Убираем непечатаемые символы для читаемости лога (не влияет на передачу).
                for (char &c : sent_chunk)
                {
                    // Если символ — управляющий (меньше 32), кроме \n, \r, \t — заменяем на '?'
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
            // Прибавляем количество успешно отправленных байт к общему счётчику.
            total_sent += bytes_sent;
            // Логируем обновление — позволяет отслеживать прогресс отправки.
            LOG_DEBUG("📈 total_sent обновлён: {} (отправлено {} байт)", total_sent, bytes_sent);

            // 🟡 ОБРАБОТКА ОТПРАВКИ 0 БАЙТ
            /**
             * @brief Обработка случая, когда send() вернул 0.
             * @details Это редкость в TCP, но возможна — означает, что получатель закрыл соединение.
             *          Дальнейшая отправка бессмысленна — выходим из цикла.
             * end() вернул 0 — это не ошибка, но может означать, что получатель закрыл соединение.
             * В стандарте TCP это редкость, но возможна.
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
        // Уровень SUCCESS — успешное завершение операции.
        LOG_SUCCESS("🎉 Успешно передано {} байт от {} к {}", bytes_read, from_fd, to_fd);
        // Возвращаем true — соединение активно, можно продолжать.
        return true;
    }
    // 🔵 ОБРАБОТКА ЗАКРЫТИЯ СОЕДИНЕНИЯ (bytes_read == 0)
    else if (bytes_read == 0)
    {

                /**
         * @brief Обработка закрытия соединения удалённой стороной.
         * @details recv() вернул 0 — это сигнал, что клиент или бэкенд закрыли соединение.
         *          Соединение нужно закрыть и очистить ресурсы.
         */
        // Логируем факт закрытия соединения — важное событие для мониторинга.
        LOG_INFO("🔚 Клиент (from_fd={}) закрыл соединение (recv вернул 0)", from_fd);
        // Возвращаем false — соединение нужно закрыть.
        return false;
    }
    // 🔵 ОБРАБОТКА ОШИБКИ ЧТЕНИЯ (bytes_read < 0)
    else
    {
        // Логируем ошибку чтения — диагностическое сообщение.
        LOG_DEBUG("⏸️ recv() вернул -1: errno={} ({})", errno, strerror(errno));

        // 🟨 ПРОВЕРКА НА EAGAIN / EWOULDBLOCK
        // Эти ошибки означают, что данных нет — нужно попробовать позже.
        // Это нормально в неблокирующем режиме.
                /**
         * @brief Обработка ошибок EAGAIN / EWOULDBLOCK при чтении.
         * @details Эти ошибки означают, что данных нет — нужно повторить попытку позже.
         *          Это нормальное поведение в неблокирующем режиме.
         */
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // Логируем информационное сообщение — не ошибка, а состояние.
            LOG_DEBUG("🔁 recv() вернул EAGAIN/EWOULDBLOCK — это нормально в неблокирующем режиме");
            // Возвращаем true — соединение активно, нужно повторить попытку.
            return true;
        }
        else
        {
                        /**
             * @brief Обработка критических ошибок чтения.
             * @details Любая другая ошибка (например, разрыв соединения, недоступность адресата)
             *          требует закрытия соединения.
             */
            // 🟥 КРИТИЧЕСКАЯ ОШИБКА — любая другая ошибка (например, разрыв соединения).
            LOG_ERROR("❌ Ошибка чтения данных от клиента (from_fd={}): {}", from_fd, strerror(errno));
            // Возвращаем false — соединение нужно закрыть.
            return false;
        }
    }
}