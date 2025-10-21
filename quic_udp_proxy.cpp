/**
 * @file quic_udp_proxy.cpp
 * @brief Реализация методов, объявленных в соответствующем .h файле.
 *
 * Здесь реализуются методы, утилитные функции, бизнес-логика.
 * Файл работает с PostgreSQL через libpqxx и соответствует стандартам C++23.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-09-29
 * @version 1.0
 * @license MIT
 */

#include "quic_udp_proxy.hpp"
#include "include/quic_udp_deduplicator.hpp"
#include "include/client_key.hpp"
#include "server/logger.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <csignal>
#include <cerrno>
#include <sys/select.h>
#include <cstdio>
#include <ctime>  // Для std::time(nullptr)
#include <random> // Для std::mt19937, std::uniform_int_distribution

// === Инициализация глобальных переменных ===

// session_map теперь хранит ClientKey → ClientKey
std::unordered_map<ClientKey, ClientKey, ClientKeyHash> session_map;
// deduplicator — экземпляр класса для дедупликации
Deduplicator deduplicator;
// === Реализация функций ===



int set_nonblocking(int fd) noexcept
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

bool get_external_ip(std::string &ip_out) noexcept
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0)
        return false;

    struct sockaddr_in temp_addr{};
    temp_addr.sin_family = AF_INET;
    temp_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &temp_addr.sin_addr);

    if (::connect(sock, (struct sockaddr *)&temp_addr, sizeof(temp_addr)) < 0)
    {
        ::close(sock);
        return false;
    }

    socklen_t len = sizeof(temp_addr);
    if (getsockname(sock, (struct sockaddr *)&temp_addr, &len) < 0)
    {
        ::close(sock);
        return false;
    }

    ip_out = inet_ntoa(temp_addr.sin_addr);
    ::close(sock);
    return true;
}

void print_hex(const uint8_t *data, size_t len, const std::string &label) noexcept
{
    if (!data || len == 0)
    {
        std::printf("[DEBUG] [%s:%d] %s: пустые данные\n", __FILE__, __LINE__, label.c_str());
        return;
    }

    std::printf("[DEBUG] [%s:%d] %s: ", __FILE__, __LINE__, label.c_str());
    for (size_t i = 0; i < std::min(len, 32UL); ++i)
    {
        std::printf("%02x ", data[i]);
    }
    if (len > 32)
        std::printf("...");
    std::printf("\n");
}

volatile sig_atomic_t running = true;

void signal_handler(int sig)
{
    std::printf("[INFO] [quic_udp_proxy.cpp:%d] Получен сигнал %d. Остановка...\n", __LINE__, sig);
    running = false;
}

// === Главный цикл ===

int main()
{
    int udp_fd = -1, wg_fd = -1;
    struct sockaddr_in client_addr{}, backend_addr{}, listen_addr{};
    socklen_t client_len = sizeof(client_addr);
    socklen_t backend_len = sizeof(backend_addr);

    // Инициализация генератора случайных чисел
    std::random_device rd;
    std::mt19937 gen(rd());

    // Регистрация обработчика сигналов
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // --- Создание сокета для клиентов (порт 443) ---
    udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0)
    {
        std::perror("[ERROR] socket udp_fd failed");
        return 1;
    }

    int opt = 1;
    if (setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        std::perror("[ERROR] setsockopt SO_REUSEADDR failed");
    }
    if (setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
    {
        std::perror("[ERROR] setsockopt SO_REUSEPORT failed");
    }

    if (set_nonblocking(udp_fd) == -1)
    {
        std::perror("[ERROR] set_nonblocking udp_fd failed");
        ::close(udp_fd);
        return 1;
    }

    // --- Привязка к порту ---
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(LISTEN_PORT);

    if (bind(udp_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
    {
        std::perror("[ERROR] bind udp_fd failed");
        ::close(udp_fd);
        return 1;
    }

    // --- Создание сокета для отправки в РФ ---
    wg_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (wg_fd < 0)
    {
        std::perror("[ERROR] socket wg_fd failed");
        ::close(udp_fd);
        return 1;
    }

    if (set_nonblocking(wg_fd) == -1)
    {
        std::perror("[ERROR] set_nonblocking wg_fd failed");
        ::close(udp_fd);
        ::close(wg_fd);
        return 1;
    }

    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    inet_pton(AF_INET, BACKEND_IP, &backend_addr.sin_addr);
    backend_addr.sin_port = htons(BACKEND_PORT);

    std::printf("[INFO] [quic_udp_proxy.cpp:%d] Запущен на порту %d, слушает 0.0.0.0, бэкенд: %s:%d\n",
                __LINE__, LISTEN_PORT, BACKEND_IP, BACKEND_PORT);

    char buf[MAX_PACKET_SIZE];
    fd_set read_fds;

    while (running)
    {
        FD_ZERO(&read_fds);
        FD_SET(udp_fd, &read_fds);
        FD_SET(wg_fd, &read_fds);
        int max_fd = std::max(udp_fd, wg_fd);

        timeval timeout{.tv_sec = 0, .tv_usec = 100000};
        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);
        if (activity < 0 && errno != EINTR)
        {
            std::fprintf(stderr, "[ERROR] [quic_udp_proxy.cpp:%d] select error: %s\n", __LINE__, strerror(errno));
            continue;
        }
        // === НАПРАВЛЕНИЕ: КЛИЕНТ → СЕРВЕР ===
        if (FD_ISSET(udp_fd, &read_fds))
        {
            // === Получение пакета от клиента ===
            // n — количество прочитанных байт.
            // buf — буфер, в который записаны данные пакета.
            // client_addr — структура, содержащая IP-адрес и порт клиента.
            // client_len — размер структуры client_addr.
            ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&client_addr, &client_len);

            if (n < 0 || static_cast<size_t>(n) >= MAX_PACKET_SIZE)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    LOG_ERROR("recvfrom client failed: {}", strerror(errno));
                }
                continue;
            }

            // === Извлечение IP-адреса и порта клиента для логирования ===
            // client_ip — строковое представление IPv4-адреса клиента (например, "192.168.1.100").
            // Функция inet_ntoa преобразует 32-битное целое число (в сетевом порядке байт) в строку в формате "A.B.C.D".
            // Аргумент: client_addr.sin_addr.s_addr — это поле структуры sockaddr_in, содержащее IP-адрес клиента.
            std::string client_ip = inet_ntoa(client_addr.sin_addr);

            // client_port — номер порта клиента, на котором он установил соединение.
            // Функция ntohs преобразует 16-битное целое число из сетевого порядка байт (big-endian) в порядок хоста (host byte order).
            // Аргумент: client_addr.sin_port — это поле структуры sockaddr_in, содержащее порт клиента в сетевом порядке байт.
            uint16_t client_port = ntohs(client_addr.sin_port);

            LOG_INFO("=== [CLIENT → SERVER] ===");
            LOG_INFO("Получено {} байт от {}:{}",
                     n,
                     client_ip.c_str(),
                     client_port);
            // Выводим hex-дамп заголовка пакета для отладки.
            print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "HEADER");
            // Проверка минимального размера пакета. QUIC-заголовок не может быть короче 6 байт.
            if (n < 6)
            {
                LOG_WARN("Слишком короткий пакет ({}) байт", n);
                continue;
            }
            // === Парсинг типа пакета ===
            // packet_type — первый байт пакета, определяющий тип заголовка.
            uint8_t packet_type = buf[0];
            // Проверяем, является ли пакет Long Header (биты 7-6 == 11).
            if ((packet_type & 0xC0) != 0xC0)
            {
                LOG_DEBUG("Short Header — пропускаем");
                continue;
            }

            // === Обработка Retry-пакета ===
            // Если пакет начинается с 0xF0 и его длина >= 9, это Retry-пакет.
            if (n >= 9 && static_cast<unsigned char>(buf[0]) == 0xF0)
            {
                LOG_INFO("Received Retry packet");
                // === Извлечение токена из Retry-пакета ===
                // token_offset — смещение до токена (байт 9).
                size_t token_offset = 9;
                // token_len — длина токена (хранится в байте 9).
                size_t token_len = buf[token_offset];
                // token — вектор, содержащий сам токен.
                std::vector<uint8_t> token(buf + token_offset + 1, buf + token_offset + 1 + token_len);
                // === Создание ключа для хранения токена ===
                // key — объект ClientKey, используемый как ключ в session_map.
                ClientKey key{};
                key.addr = client_addr.sin_addr.s_addr; // IPv4-адрес клиента.
                key.port = client_addr.sin_port;        // Порт клиента.
                                                        // cid — первые 8 байт SCID из Retry-пакета.
                std::memset(key.cid, 0, 8);
                std::memcpy(key.cid, buf + 9, 8); // Первые 8 байт после токена — это SCID.

                // === Сохранение токена в session_map ===
                key.token = token;
                session_map[key] = key;

                // === Пересылка Retry-пакета клиенту ===
                ssize_t sent = sendto(udp_fd, buf, n, 0,
                                      (struct sockaddr *)&client_addr, sizeof(client_addr));

                if (sent < 0)
                {
                    LOG_ERROR("sendto client failed: {}", strerror(errno));
                }
                else
                {
                    LOG_INFO("Retry packet sent to client");
                }
                continue; // Пропускаем дальнейшую обработку этого пакета.
            }

            // === Парсинг версии QUIC ===
            // version — 32-битное число, представляющее версию QUIC.
            uint32_t version = (buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4];

            // === Парсинг длин CID ===
            // pos — смещение до байта длин CID (байт 5).
            size_t pos = 5;
            // dcil — длина DCID (верхние 4 бита байта 5).
            uint8_t dcil = buf[pos];
            // scil — длина SCID (нижние 4 бита байта 5).
            uint8_t scil = buf[pos + 1];

            LOG_INFO("QUIC Версия: 0x{:08x}, DCIL={}, SCIL={}",
                     version,
                     static_cast<int>(dcil),
                     static_cast<int>(scil));

            // Проверка корректности длин CID.
            if (dcil == 0 || scil == 0 || pos + 2 + dcil + scil > static_cast<size_t>(n))
            {
                LOG_WARN("Некорректные CID длины");
                continue;
            }
            // === Извлечение SCID ===
            // scid — указатель на SCID в пакете.
            uint8_t *scid = reinterpret_cast<uint8_t *>(&buf[pos + 2 + dcil]);

            // === Создание ключа для поиска сессии ===
            ClientKey key{};
            key.addr = client_addr.sin_addr.s_addr;
            key.port = client_addr.sin_port;
            std::memset(key.cid, 0, 8);
            std::memcpy(key.cid, scid, std::min(static_cast<size_t>(scil), 8UL));

            // === Проверка на дубликат с помощью Deduplicator ===
            // Создаем объект PacketInfo для передачи в Deduplicator
            // info — объект типа Deduplicator::PacketInfo, содержащий информацию о пакете.
            Deduplicator::PacketInfo info;
            // info.scid — вектор, содержащий SCID из пакета.
            info.scid = std::vector<uint8_t>(scid, scid + scil);
            // info.token — вектор, содержащий токен (изначально пустой, так как это первый пакет).
            info.token = {}; // Изначально токен пустой

            // Проверяем, является ли пакет повторным
            // deduplicator.is_duplicate — метод класса Deduplicator, проверяющий, был ли уже обработан такой пакет.
            // Аргументы:
            //   key — ключ клиента (IP, порт, SCID).
            //   info.scid — SCID из пакета.
            //   info.token — токен из пакета.
            if (deduplicator.is_duplicate(key, info.scid, info.token))
            {
                // Если пакет повторный — игнорируем его.
                LOG_INFO("Повторный пакет — игнорируем");
                continue; // Пропускаем дальнейшую обработку
            }

            // Это первый пакет — добавляем информацию о нем в Deduplicator
            // deduplicator.add_packet — метод класса Deduplicator, сохраняющий информацию о первом пакете.
            // Аргументы:
            //   key — ключ клиента.
            //   info — объект PacketInfo, содержащий SCID и токен.
            deduplicator.add_packet(key, info);

            // === Поиск сессии в session_map ===
            // it — итератор, указывающий на элемент в session_map.
            auto it = session_map.find(key);

            if (it == session_map.end())
            {
                // Новая сессия
                // session_map[key] = key — добавляем новую сессию в session_map.
                session_map[key] = key;
                LOG_INFO("Новая сессия: {}:{} → SCID: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                         client_ip.c_str(),
                         client_port,
                         key.cid[0],
                         key.cid[1],
                         key.cid[2],
                         key.cid[3],
                         key.cid[4],
                         key.cid[5],
                         key.cid[6],
                         key.cid[7]);
            }
            else
            {
                LOG_DEBUG("Reuse SCID: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                          key.cid[0],
                          key.cid[1],
                          key.cid[2],
                          key.cid[3],
                          key.cid[4],
                          key.cid[5],
                          key.cid[6],
                          key.cid[7]);
            }

            // Добавляем токен в пакет
            // it != session_map.end() — проверка, существует ли сессия.
            // it->second.token.size() > 0 — проверка, есть ли токен в сессии.
            if (it != session_map.end() && it->second.token.size() > 0)
            {
                // token_offset — смещение до токена в пакете (байт 9).
                size_t token_offset = 9;
                // Записываем длину токена в байт 9.
                buf[token_offset] = it->second.token.size();
                // Копируем токен в пакет.
                std::memcpy(buf + token_offset + 1, it->second.token.data(), it->second.token.size());
            }

            // === ЛОГИРОВАНИЕ ПАКЕТА ДО ОТПРАВКИ В РФ ===
            LOG_INFO("Пакет до отправки в РФ:");
            print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "SEND_TO_RF");

            // Отправляем пакет без изменений
            ssize_t sent = sendto(wg_fd, buf, n, 0,
                                  (struct sockaddr *)&backend_addr, sizeof(backend_addr));
            if (sent < 0)
            {
                LOG_ERROR("sendto backend failed: {}", strerror(errno));
            }
            else
            {
                LOG_INFO("Переслано {} байт в РФ", sent);
            }
        }
        // == = НАПРАВЛЕНИЕ : СЕРВЕР → КЛИЕНТ == =
        if (FD_ISSET(wg_fd, &read_fds))
        {
            ssize_t n = recvfrom(wg_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&backend_addr, &backend_len);

            if (n < 0 || static_cast<size_t>(n) >= MAX_PACKET_SIZE)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    std::fprintf(stderr, "[ERROR] [quic_udp_proxy.cpp:%d] recvfrom backend failed: %s\n", __LINE__, strerror(errno));
                continue;
            }

            // === ЛОГИРОВАНИЕ ПАКЕТА ПОСЛЕ ПОЛУЧЕНИЯ ОТ РФ (СРАЗУ ПОСЛЕ recvfrom) ===
            std::printf("[INFO] [quic_udp_proxy.cpp:%d] Пакет после получения от РФ:\n", __LINE__);
            print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "RECV_FROM_RF");

            std::printf("\n=== [SERVER → CLIENT] ===\n");
            std::printf("[INFO] [quic_udp_proxy.cpp:%d] Получено %zd байт от сервера\n", __LINE__, n);
            print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "REPLY_HEADER");

            if (n < 6)
            {
                std::printf("[WARNING] [quic_udp_proxy.cpp:%d] Слишком короткий пакет (%zd байт)\n", __LINE__, n);
                continue;
            }

            uint8_t packet_type = buf[0];
            // === Обработка Retry-пакета ===
            if ((packet_type & 0xC0) == 0xC0)
            { // Это Long Header
                // Проверяем, является ли пакет Retry
                if (buf[5] == 0x00 && buf[6] == 0x00 && buf[7] == 0x00 && buf[8] == 0x00)
                {
                    // Это Retry-пакет
                    LOG_INFO("Received Retry packet");
                    // Извлекаем токен из Retry-пакета
                    size_t token_offset = 9;
                    size_t token_len = buf[token_offset];
                    std::vector<uint8_t> token(buf + token_offset + 1, buf + token_offset + 1 + token_len);
                    // Создаём ключ на основе IP и порта клиента (из client_addr)
                    ClientKey key{};
                    key.addr = client_addr.sin_addr.s_addr;
                    key.port = client_addr.sin_port;
                    // Первые 8 байт после токена — это SCID (используем их как CID)
                    std::memset(key.cid, 0, 8);
                    std::memcpy(key.cid, buf + 9, 8); // Первые 8 байт после токена — это SCID
                    // Сохраняем токен в session_map
                    key.token = token;
                    session_map[key] = key; // Записываем весь объект ClientKey
                    // Пересылаем Retry-пакет клиенту
                    ssize_t sent = sendto(udp_fd, buf, n, 0,
                                          (struct sockaddr *)&client_addr, sizeof(client_addr));
                    if (sent < 0)
                    {
                        LOG_ERROR("sendto client failed: {}", strerror(errno));
                    }
                    else
                    {
                        LOG_INFO("Retry packet sent to client");
                    }
                    continue; // Пропускаем дальнейшую обработку этого пакета
                }
            }
            // === Конец обработки Retry-пакета ===

            if ((packet_type & 0xC0) != 0xC0)
            {
                std::printf("[DEBUG] [quic_udp_proxy.cpp:%d] Short Header — пропускаем\n", __LINE__);
                continue;
            }

            size_t pos = 5;
            uint8_t dcil = buf[pos];
            uint8_t scil = buf[pos + 1];

            if (dcil == 0 || scil == 0 || pos + 2 + dcil + scil > static_cast<size_t>(n))
            {
                std::printf("[WARNING] [quic_udp_proxy.cpp:%d] Некорректные CID\n", __LINE__);
                continue;
            }

            uint8_t *dcid = reinterpret_cast<uint8_t *>(&buf[pos + 2]);

            // Используем DCID из пакета для поиска сессии
            ClientKey key{};
            key.addr = client_addr.sin_addr.s_addr;
            key.port = client_addr.sin_port;
            std::memset(key.cid, 0, 8);
            std::memcpy(key.cid, dcid, 8); // DCID из пакета

            auto it = session_map.find(key);
            if (it == session_map.end())
            {
                std::printf("[WARNING] [quic_udp_proxy.cpp:%d] Неизвестный DCID — пакет потерялся\n", __LINE__);
                continue;
            }

            // Отправляем пакет клиенту без изменений
            struct sockaddr_in client_dest{};
            client_dest.sin_family = AF_INET;
            client_dest.sin_addr.s_addr = key.addr;
            client_dest.sin_port = key.port;

            ssize_t sent = sendto(udp_fd, buf, n, 0,
                                  (struct sockaddr *)&client_dest, sizeof(client_dest));

            if (sent < 0)
            {
                std::fprintf(stderr, "[ERROR] [quic_udp_proxy.cpp:%d] sendto client failed: %s\n", __LINE__, strerror(errno));
            }
            else
            {
                std::printf("[INFO] [quic_udp_proxy.cpp:%d] Отправлено %zd байт клиенту %s:%u\n",
                            __LINE__, sent, inet_ntoa(client_dest.sin_addr), ntohs(client_dest.sin_port));
            }
        }
    }

    std::printf("[INFO] [quic_udp_proxy.cpp:%d] Прокси остановлен.\n", __LINE__);
    if (udp_fd != -1)
        ::close(udp_fd);
    if (wg_fd != -1)
        ::close(wg_fd);
    return 0;
}