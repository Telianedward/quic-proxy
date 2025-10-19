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

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <csignal>
#include <cerrno>
#include <sys/select.h>
#include <cstdio>
#include <ctime> // Для std::time(nullptr)
#include <random> // Для std::mt19937, std::uniform_int_distribution
#include "server/logger.h" // Для логирования

// Убедиться, что logger.h определяет LOG_INFO, LOG_ERROR и т.д.
#ifndef LOG_INFO
#error "Логгер не определён! Убедитесь, что включён server/logger.h"
#endif

// === Инициализация глобальных переменных ===

std::unordered_map<ClientKey, std::vector<uint8_t>, ClientKeyHash> session_map;
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
           std::memcmp(cid, other.cid, 8) == 0;
}

size_t ClientKeyHash::operator()(const ClientKey &k) const noexcept
{
    return std::hash<uint32_t>()(k.addr) ^
           (std::hash<uint16_t>()(k.port) << 1) ^
           std::hash<uint64_t>()(*reinterpret_cast<const uint64_t *>(k.cid));
}

[[nodiscard]] int set_nonblocking(int fd) noexcept
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

[[nodiscard]] std::vector<uint8_t> generate_local_cid() noexcept
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

[[nodiscard]] bool get_external_ip(std::string &ip_out) noexcept
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
        LOG_DEBUG("[{}:{} in {}] {}: пустые данные", __FILE__, __LINE__, __func__, label);
        return;
    }

    LOG_DEBUG("[{}:{} in {}] {}: ", __FILE__, __LINE__, __func__, label);
    for (size_t i = 0; i < std::min(len, 32UL); ++i)
    {
        LOG_RAW("{:02x} ", data[i]);
    }
    if (len > 32)
        LOG_RAW("...");
    LOG_RAW("\n");
}

volatile sig_atomic_t running = true;

void signal_handler(int sig)
{
    LOG_INFO("[{}] Получен сигнал {}. Остановка...", __func__, sig);
    running = false;
}

// === Главный цикл ===

int main()
{
    try
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
            LOG_ERROR("socket udp_fd failed: {}", strerror(errno));
            return EXIT_FAILURE;
        }

        int opt = 1;
        if (setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            LOG_ERROR("setsockopt SO_REUSEADDR failed: {}", strerror(errno));
        }
        if (setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0)
        {
            LOG_ERROR("setsockopt SO_REUSEPORT failed: {}", strerror(errno));
        }

        if (set_nonblocking(udp_fd) == -1)
        {
            LOG_ERROR("set_nonblocking udp_fd failed: {}", strerror(errno));
            ::close(udp_fd);
            return EXIT_FAILURE;
        }

        // --- Привязка к порту ---
        memset(&listen_addr, 0, sizeof(listen_addr));
        listen_addr.sin_family = AF_INET;
        listen_addr.sin_addr.s_addr = INADDR_ANY;
        listen_addr.sin_port = htons(LISTEN_PORT);

        if (bind(udp_fd, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0)
        {
            LOG_ERROR("bind udp_fd failed: {}", strerror(errno));
            ::close(udp_fd);
            return EXIT_FAILURE;
        }

        // --- Создание сокета для отправки в РФ ---
        wg_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (wg_fd < 0)
        {
            LOG_ERROR("socket wg_fd failed: {}", strerror(errno));
            ::close(udp_fd);
            return EXIT_FAILURE;
        }

        if (set_nonblocking(wg_fd) == -1)
        {
            LOG_ERROR("set_nonblocking wg_fd failed: {}", strerror(errno));
            ::close(udp_fd);
            ::close(wg_fd);
            return EXIT_FAILURE;
        }

        memset(&backend_addr, 0, sizeof(backend_addr));
        backend_addr.sin_family = AF_INET;
        inet_pton(AF_INET, BACKEND_IP, &backend_addr.sin_addr);
        backend_addr.sin_port = htons(BACKEND_PORT);

        LOG_INFO("Запущен на порту {}, слушает 0.0.0.0, бэкенд: {}:{}",
                 LISTEN_PORT, BACKEND_IP, BACKEND_PORT);

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
                LOG_ERROR("select error: {}", strerror(errno));
                continue;
            }

            // === НАПРАВЛЕНИЕ: КЛИЕНТ → СЕРВЕР ===
            if (FD_ISSET(udp_fd, &read_fds))
            {
                ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0,
                                     (struct sockaddr *)&client_addr, &client_len);

                if (n < 0 || n >= MAX_PACKET_SIZE)
                {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        LOG_ERROR("recvfrom client failed: {}", strerror(errno));
                    continue;
                }

                std::string client_ip = inet_ntoa(client_addr.sin_addr);
                uint16_t client_port = ntohs(client_addr.sin_port);

                LOG_INFO("=== [CLIENT → SERVER] ===");
                LOG_INFO("Получено {} байт от {}:{}",
                         n, client_ip, client_port);
                print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "HEADER");

                if (n < 6)
                {
                    LOG_WARN("Слишком короткий пакет ({} байт)", n);
                    continue;
                }

                uint8_t packet_type = buf[0];
                if ((packet_type & 0xC0) != 0xC0)
                {
                    LOG_DEBUG("Short Header — пропускаем");
                    continue;
                }

                uint32_t version = (buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4];
                size_t pos = 5;
                uint8_t dcil = buf[pos];
                uint8_t scil = buf[pos + 1];

                LOG_INFO("QUIC Версия: 0x{:08x}, DCIL={}, SCIL={}",
                         version, dcil, scil);

                if (dcil == 0 || scil == 0 || pos + 2 + dcil + scil > static_cast<size_t>(n))
                {
                    LOG_WARN("Некорректные CID длины");
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
                    session_map[key] = local_cid;
                    reverse_map[local_cid] = key;
                    LOG_INFO("Новая сессия: {}:{} → LocalCID:", client_ip, client_port);
                    for (uint8_t b : local_cid)
                        LOG_RAW("{:02x}", b);
                    LOG_RAW("\n");
                }
                else
                {
                    local_cid = it->second;
                    LOG_DEBUG("Reuse LocalCID:");
                    for (uint8_t b : local_cid)
                        LOG_RAW("{:02x}", b);
                    LOG_RAW("\n");
                }

                // === МОДИФИКАЦИЯ ПАКЕТА: SCIL = 8, SCID = LocalCID ===
                buf[5] = (buf[5] & 0xF0) | 8; // Устанавливаем SCIL = 8
                std::memcpy(scid, local_cid.data(), 8); // Заменяем SCID на LocalCID

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

            // === НАПРАВЛЕНИЕ: СЕРВЕР → КЛИЕНТ ===
            if (FD_ISSET(wg_fd, &read_fds))
            {
                ssize_t n = recvfrom(wg_fd, buf, sizeof(buf), 0,
                                     (struct sockaddr *)&backend_addr, &backend_len);

                if (n < 0 || n >= MAX_PACKET_SIZE)
                {
                    if (errno != EAGAIN && errno != EWOULDBLOCK)
                        LOG_ERROR("recvfrom backend failed: {}", strerror(errno));
                    continue;
                }

                LOG_INFO("=== [SERVER → CLIENT] ===");
                LOG_INFO("Получено {} байт от сервера", n);
                print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "REPLY_HEADER");

                if (n < 6)
                {
                    LOG_WARN("Пакет слишком короткий");
                    continue;
                }

                uint8_t packet_type = buf[0];
                if ((packet_type & 0xC0) != 0xC0)
                {
                    LOG_DEBUG("Short Header — пропускаем");
                    continue;
                }

                size_t pos = 5;
                uint8_t dcil = buf[pos];
                uint8_t scil = buf[pos + 1];

                if (dcil == 0 || scil == 0 || pos + 2 + dcil + scil > static_cast<size_t>(n))
                {
                    LOG_WARN("Некорректные CID");
                    continue;
                }

                uint8_t *dcid = reinterpret_cast<uint8_t *>(&buf[pos + 2]);
                std::vector<uint8_t> local_cid_vec(dcid, dcid + 8);

                auto rev_it = reverse_map.find(local_cid_vec);
                if (rev_it == reverse_map.end())
                {
                    LOG_WARN("Неизвестный LocalCID — пакет потерялся");
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
                    LOG_ERROR("sendto client failed: {}", strerror(errno));
                }
                else
                {
                    LOG_INFO("Отправлено {} байт клиенту {}:{}",
                             sent, inet_ntoa(client_dest.sin_addr), ntohs(client_dest.sin_port));
                }
            }
        }

        LOG_INFO("Прокси остановлен.");
        if (udp_fd != -1)
            ::close(udp_fd);
        if (wg_fd != -1)
            ::close(wg_fd);
        return EXIT_SUCCESS;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Неизвестная ошибка: {}", e.what());
        return EXIT_FAILURE;
    }
    catch (...)
    {
        LOG_ERROR("Неизвестная ошибка (не std::exception)");
        return EXIT_FAILURE;
    }
}