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

// Исправлено: session_map теперь хранит ClientKey → ClientKey
std::unordered_map<ClientKey, ClientKey, ClientKeyHash> session_map;
std::unordered_map<std::vector<uint8_t>, ClientKey, VectorHash, VectorEqual> reverse_map;

// === Реализация функций ===

size_t VectorHash::operator()(const std::vector<uint8_t> &v) const noexcept
{
    std::hash<uint64_t> hasher;
    size_t result = 0;
    for (size_t i = 0; i < v.size(); ++i)
    {
        result ^= hasher(v[i]) + 2654435761U + (result << 6) + (result >> 2);
    }
    return result;
}

bool VectorEqual::operator()(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) const noexcept
{
    return a == b;
}

bool ClientKey::operator==(const ClientKey &other) const noexcept
{
    return addr == other.addr && port == other.port &&
           std::memcmp(cid, other.cid, 8) == 0 &&
           token == other.token;
}

size_t ClientKeyHash::operator()(const ClientKey &k) const noexcept
{
    size_t result = std::hash<uint32_t>()(k.addr) ^
                   (std::hash<uint16_t>()(k.port) << 1) ^
                   std::hash<uint64_t>()(*reinterpret_cast<const uint64_t *>(k.cid));
    // Хешируем токен
    for (uint8_t b : k.token)
    {
        result ^= std::hash<uint8_t>()(b) + 2654435761U + (result << 6) + (result >> 2);
    }
    return result;
}

int set_nonblocking(int fd) noexcept
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

std::vector<uint8_t> generate_local_cid() noexcept
{
    // Используем std::mt19937 для C++23
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    std::vector<uint8_t> cid(8);
    for (int i = 0; i < 8; ++i)
    {
        cid[i] = static_cast<uint8_t>(dis(gen)); // уникальный SCID
    }
    return cid;
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
            ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&client_addr, &client_len);

         if (n < 0 || static_cast<size_t>(n) >= MAX_PACKET_SIZE)
            {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    std::fprintf(stderr, "[ERROR] [quic_udp_proxy.cpp:%d] recvfrom client failed: %s\n", __LINE__, strerror(errno));
                continue;
            }

            std::string client_ip = inet_ntoa(client_addr.sin_addr);
            uint16_t client_port = ntohs(client_addr.sin_port);

            std::printf("\n=== [CLIENT → SERVER] ===\n");
            std::printf("[INFO] [quic_udp_proxy.cpp:%d] Получено %zd байт от %s:%u\n", __LINE__, n, client_ip.c_str(), client_port);
            print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "HEADER");

            if (n < 6)
            {
                std::printf("[WARNING] [quic_udp_proxy.cpp:%d] Слишком короткий пакет (%zd байт)\n", __LINE__, n);
                continue;
            }

            uint8_t packet_type = buf[0];
            if ((packet_type & 0xC0) != 0xC0)
            {
                std::printf("[DEBUG] [quic_udp_proxy.cpp:%d] Short Header — пропускаем\n", __LINE__);
                continue;
            }

            // === Обработка Retry-пакета ===
            if (n >= 9 && static_cast<unsigned char>(buf[0]) == 0xF0)
            {
                // Это Retry-пакет
                LOG_INFO("Received Retry packet");
                // Извлекаем токен из Retry-пакета
                size_t token_offset = 9;
                size_t token_len = buf[token_offset];
                std::vector<uint8_t> token(buf + token_offset + 1, buf + token_offset + 1 + token_len);
                // Создаём ключ на основе IP и порта клиента
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
                if (sent < 0) {
                    LOG_ERROR("sendto client failed: {}", strerror(errno));
                } else {
                    LOG_INFO("Retry packet sent to client");
                }
                continue; // Пропускаем дальнейшую обработку этого пакета
            }

            uint32_t version = (buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4];
            size_t pos = 5;
            uint8_t dcil = buf[pos];
            uint8_t scil = buf[pos + 1];

            std::printf("[INFO] [quic_udp_proxy.cpp:%d] QUIC Версия: 0x%08x, DCIL=%d, SCIL=%d\n",
                        __LINE__, version, dcil, scil);

            if (dcil == 0 || scil == 0 || pos + 2 + dcil + scil > static_cast<size_t>(n))
            {
                std::printf("[WARNING] [quic_udp_proxy.cpp:%d] Некорректные CID длины\n", __LINE__);
                continue;
            }

            uint8_t *dcid = reinterpret_cast<uint8_t *>(&buf[pos + 2]);
            uint8_t *scid = reinterpret_cast<uint8_t *>(&buf[pos + 2 + dcil]);

            ClientKey key{};
            key.addr = client_addr.sin_addr.s_addr;
            key.port = client_addr.sin_port;
            std::memset(key.cid, 0, 8);
            std::memcpy(key.cid, scid, std::min(static_cast<size_t>(scil), 8UL));

            auto it = session_map.find(key);
            std::vector<uint8_t> local_cid;
            if (it == session_map.end())
            {
                local_cid = generate_local_cid();
                session_map[key] = key; // Записываем весь объект ClientKey
                reverse_map[local_cid] = key;
                std::printf("[INFO] [quic_udp_proxy.cpp:%d] Новая сессия: %s:%u → LocalCID:", __LINE__, client_ip.c_str(), client_port);
                for (uint8_t b : local_cid)
                    printf("%02x", b);
                std::printf("\n");
            }
            else
            {
                local_cid.assign(it->second.cid, it->second.cid + 8);// Используем CID из сохранённого ключа
                std::printf("[DEBUG] [quic_udp_proxy.cpp:%d] Reuse LocalCID:", __LINE__);
                for (uint8_t b : local_cid)
                    printf("%02x", b);
                std::printf("\n");
            }

            // === МОДИФИКАЦИЯ ПАКЕТА: SCIL = 8, SCID = LocalCID ===
            if (scil > 20)
            {
                std::printf("[WARNING] [quic_udp_proxy.cpp:%d] Некорректный SCIL=%d, устанавливаем SCIL=8\n", __LINE__, scil);
                scil = 8;
            }
            buf[5] = (buf[5] & 0xF0) | 8;           // Устанавливаем SCIL = 8
            std::memcpy(scid, local_cid.data(), 8);   // Заменяем SCID на LocalCID
            // Добавляем токен в пакет
            if (it != session_map.end() && it->second.token.size() > 0)
            {
                // Вставляем токен в пакет
                size_t token_offset = 9;
                buf[token_offset] = it->second.token.size();
                std::memcpy(buf + token_offset + 1, it->second.token.data(), it->second.token.size());
            }

            ssize_t sent = sendto(wg_fd, buf, n, 0,
                                  (struct sockaddr *)&backend_addr, sizeof(backend_addr));
            if (sent < 0)
            {
                std::fprintf(stderr, "[ERROR] [quic_udp_proxy.cpp:%d] sendto backend failed: %s\n", __LINE__, strerror(errno));
            }
            else
            {
                std::printf("[INFO] [quic_udp_proxy.cpp:%d] Переслано %zd байт в РФ\n", __LINE__, sent);
            }
        }

        // === НАПРАВЛЕНИЕ: СЕРВЕР → КЛИЕНТ ===
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
            std::vector<uint8_t> local_cid_vec(dcid, dcid + 8);

            auto rev_it = reverse_map.find(local_cid_vec);
            if (rev_it == reverse_map.end())
            {
                std::printf("[WARNING] [quic_udp_proxy.cpp:%d] Неизвестный LocalCID — пакет потерялся\n", __LINE__);
                continue;
            }

            ClientKey orig_key = rev_it->second;

            // === ВОССТАНОВЛЕНИЕ ОРИГИНАЛЬНОГО SCID КАК DCID ===
            buf[5] = (8 << 4) | (buf[5] & 0x0F); // DCIL = 8
            std::memcpy(dcid, orig_key.cid, 8);

            struct sockaddr_in client_dest{};
            client_dest.sin_family = AF_INET;
            client_dest.sin_addr.s_addr = orig_key.addr;
            client_dest.sin_port = orig_key.port;

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