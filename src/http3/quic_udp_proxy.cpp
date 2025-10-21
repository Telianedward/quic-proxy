// src/quic_udp_proxy.cpp
/**
 * @file quic_udp_proxy.cpp
 * @brief Реализация QUIC-UDP прокси.
 *
 * Обеспечивает прозрачное перенаправление QUIC-пакетов от клиента к серверу в России.
 * Использует асинхронный I/O (select) для масштабируемости.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-22
 * @version 1.0
 * @license MIT
 */

#include "../include/quic_udp_proxy.hpp"
#include <cstdio>
#include <ctime>
#include <random>

// === Реализация методов класса QuicUdpProxy ===

QuicUdpProxy::QuicUdpProxy(int listen_port, const std::string& backend_ip, int backend_port)
    : listen_port_(listen_port), backend_port_(backend_port), backend_ip_(backend_ip) {}

bool QuicUdpProxy::run() {
    // Инициализация генератора случайных чисел
    std::random_device rd;
    std::mt19937 gen(rd());

    // Регистрация обработчика сигналов
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    // --- Создание сокета для клиентов (порт 443) ---
    udp_fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd_ < 0) {
        LOG_ERROR("[ERROR] socket udp_fd failed: {}", strerror(errno));
        return false;
    }

    int opt = 1;
    if (setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("[ERROR] setsockopt SO_REUSEADDR failed: {}", strerror(errno));
    }
    if (setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        LOG_ERROR("[ERROR] setsockopt SO_REUSEPORT failed: {}", strerror(errno));
    }
    if (set_nonblocking(udp_fd_) == -1) {
        LOG_ERROR("[ERROR] set_nonblocking udp_fd failed: {}", strerror(errno));
        ::close(udp_fd_);
        return false;
    }

    // --- Привязка к порту ---
    struct sockaddr_in listen_addr{};
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(listen_port_);

    if (bind(udp_fd_, (struct sockaddr *)&listen_addr, sizeof(listen_addr)) < 0) {
        LOG_ERROR("[ERROR] bind udp_fd failed: {}", strerror(errno));
        ::close(udp_fd_);
        return false;
    }

    // --- Создание сокета для отправки в РФ ---
    wg_fd_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (wg_fd_ < 0) {
        LOG_ERROR("[ERROR] socket wg_fd failed: {}", strerror(errno));
        ::close(udp_fd_);
        return false;
    }
    if (set_nonblocking(wg_fd_) == -1) {
        LOG_ERROR("[ERROR] set_nonblocking wg_fd failed: {}", strerror(errno));
        ::close(udp_fd_);
        ::close(wg_fd_);
        return false;
    }

    struct sockaddr_in backend_addr{};
    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    inet_pton(AF_INET, backend_ip_.c_str(), &backend_addr.sin_addr);
    backend_addr.sin_port = htons(backend_port_);

    LOG_INFO("[INFO] Запущен на порту {}, слушает 0.0.0.0, бэкенд: {}:{}",
             listen_port_, backend_ip_, backend_port_);

    char buf[MAX_PACKET_SIZE];
    fd_set read_fds;

    while (running_) {
        FD_ZERO(&read_fds);
        FD_SET(udp_fd_, &read_fds);
        FD_SET(wg_fd_, &read_fds);
        int max_fd = std::max(udp_fd_, wg_fd_);
        timeval timeout{.tv_sec = 0, .tv_usec = 100000}; // 100 мс
        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);

        if (activity < 0 && errno != EINTR) {
            LOG_ERROR("[ERROR] select error: {}", strerror(errno));
            continue;
        }

        // === НАПРАВЛЕНИЕ: КЛИЕНТ → СЕРВЕР ===
        if (FD_ISSET(udp_fd_, &read_fds)) {
            struct sockaddr_in client_addr{};
            socklen_t client_len = sizeof(client_addr);
            ssize_t n = recvfrom(udp_fd_, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&client_addr, &client_len);
            if (n < 0 || static_cast<size_t>(n) >= MAX_PACKET_SIZE) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOG_ERROR("recvfrom client failed: {}", strerror(errno));
                }
                continue;
            }
            handle_client_packet(buf, n, client_addr, client_len);
        }

        // === НАПРАВЛЕНИЕ: СЕРВЕР → КЛИЕНТ ===
        if (FD_ISSET(wg_fd_, &read_fds)) {
            struct sockaddr_in backend_addr{};
            socklen_t backend_len = sizeof(backend_addr);
            ssize_t n = recvfrom(wg_fd_, buf, sizeof(buf), 0,
                                 (struct sockaddr *)&backend_addr, &backend_len);
            if (n < 0 || static_cast<size_t>(n) >= MAX_PACKET_SIZE) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    LOG_ERROR("recvfrom backend failed: {}", strerror(errno));
                }
                continue;
            }
            handle_backend_packet(buf, n, backend_addr, backend_len);
        }
    }

    LOG_INFO("[INFO] Прокси остановлен.");
    if (udp_fd_ != -1) {
        ::close(udp_fd_);
    }
    if (wg_fd_ != -1) {
        ::close(wg_fd_);
    }
    return true;
}

void QuicUdpProxy::stop() {
    running_ = false;
}

int QuicUdpProxy::set_nonblocking(int fd) noexcept {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

std::vector<uint8_t> QuicUdpProxy::generate_local_cid() noexcept {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    std::vector<uint8_t> cid(8);
    for (auto &b : cid) {
        b = static_cast<uint8_t>(dis(gen));
    }
    return cid;
}

bool QuicUdpProxy::get_external_ip(std::string &ip_out) noexcept {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        return false;
    }
    struct sockaddr_in temp_addr{};
    temp_addr.sin_family = AF_INET;
    temp_addr.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &temp_addr.sin_addr);
    if (::connect(sock, (struct sockaddr *)&temp_addr, sizeof(temp_addr)) < 0) {
        ::close(sock);
        return false;
    }
    socklen_t len = sizeof(temp_addr);
    if (getsockname(sock, (struct sockaddr *)&temp_addr, &len) < 0) {
        ::close(sock);
        return false;
    }
    ip_out = inet_ntoa(temp_addr.sin_addr);
    ::close(sock);
    return true;
}

void QuicUdpProxy::print_hex(const uint8_t *data, size_t len, const std::string &label) noexcept {
    if (!data || len == 0) {
        LOG_DEBUG("[DEBUG] {} : пустые данные", label);
        return;
    }
    LOG_DEBUG("[DEBUG] {} : ", label);
    for (size_t i = 0; i < std::min(len, 32UL); ++i) {
        LOG_DEBUG("{:02x} ", data[i]);
    }
    if (len > 32) {
        LOG_DEBUG("...");
    }
    LOG_DEBUG("");
}

void QuicUdpProxy::signal_handler(int sig) {
    LOG_INFO("[INFO] Получен сигнал {}. Остановка...", sig);
    // Для простоты просто выходим из main, где будет вызван stop()
    // В реальном проекте можно использовать atomic_flag
    exit(0);
}

void QuicUdpProxy::handle_client_packet(char *buf, ssize_t n, const sockaddr_in &client_addr, socklen_t client_len) noexcept {
    std::string client_ip = inet_ntoa(client_addr.sin_addr);
    uint16_t client_port = ntohs(client_addr.sin_port);

    LOG_INFO("=== [CLIENT → SERVER] ===");
    LOG_INFO("Получено {} байт от {}:{}",
             n,
             client_ip.c_str(),
             client_port);
    print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "HEADER");

    if (n < 6) {
        LOG_WARN("Слишком короткий пакет ({}) байт", n);
        return;
    }

    uint8_t packet_type = buf[0];

    if ((packet_type & 0xC0) != 0xC0) {
        LOG_DEBUG("Short Header — пропускаем");
        return;
    }

    // Обработка Retry-пакета
    if (n >= 9 && static_cast<unsigned char>(buf[0]) == 0xF0) {
        LOG_INFO("Received Retry packet");
        size_t token_offset = 9;
        size_t token_len = buf[token_offset];
        std::vector<uint8_t> token(buf + token_offset + 1, buf + token_offset + 1 + token_len);

        ClientKey key{};
        key.addr = client_addr.sin_addr.s_addr;
        key.port = client_addr.sin_port;
        std::memset(key.cid, 0, 8);
        std::memcpy(key.cid, buf + 9, 8); // Первые 8 байт после токена — это SCID.

        key.token = token;
        session_map_[key] = key;

        // Отправляем Retry-пакет клиенту
        ssize_t sent = sendto(udp_fd_, buf, n, 0,
                              (struct sockaddr *)&client_addr, sizeof(client_addr));
        if (sent < 0) {
            LOG_ERROR("sendto client failed: {}", strerror(errno));
        } else {
            LOG_INFO("Retry packet sent to client");
        }
        return;
    }

    uint32_t version = (buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4];
    size_t pos = 5;
    uint8_t dcil = (buf[pos] >> 4) & 0x0F;
    uint8_t scil = buf[pos] & 0x0F;

    LOG_INFO("QUIC Версия: 0x{:08x}, DCIL={}, SCIL={}",
             version,
             static_cast<int>(dcil),
             static_cast<int>(scil));

    if (dcil == 0 || scil == 0 || pos + 2 + dcil + scil > static_cast<size_t>(n)) {
        LOG_WARN("Некорректные CID длины");
        return;
    }

    uint8_t *scid = reinterpret_cast<uint8_t *>(&buf[pos + 2 + dcil]);

    ClientKey key{};
    key.addr = client_addr.sin_addr.s_addr;
    key.port = client_addr.sin_port;
    std::memset(key.cid, 0, 8);
    std::memcpy(key.cid, scid, std::min(static_cast<size_t>(scil), 8UL));

    Deduplicator::PacketInfo info;
    info.scid = std::vector<uint8_t>(scid, scid + scil);
    info.token = {};

    size_t cid_offset = pos + 2;
    size_t pn_offset = cid_offset + dcil + scil;
    if (pn_offset >= static_cast<size_t>(n)) {
        LOG_WARN("Пакет слишком короткий для Packet Number");
        return;
    }

    uint64_t packet_number = 0;
    for (size_t i = 0; i < 4 && pn_offset + i < static_cast<size_t>(n); ++i) {
        packet_number = (packet_number << 8) | buf[pn_offset + i];
    }

    if (deduplicator_.is_duplicate(key, info.scid, info.token, packet_number)) {
        LOG_INFO("Повторный пакет — игнорируем");
        return;
    }

    deduplicator_.add_packet(key, info);

    auto it = session_map_.find(key);
    if (it == session_map_.end()) {
        session_map_[key] = key;
        reverse_map_[info.scid] = key;
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
    } else {
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

    if (it != session_map_.end() && !it->second.token.empty()) {
        LOG_INFO("Adding token to packet for SCID: {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                 key.cid[0], key.cid[1], key.cid[2], key.cid[3],
                 key.cid[4], key.cid[5], key.cid[6], key.cid[7]);
        if (static_cast<size_t>(n) < 9 + 1 + it->second.token.size()) {
            LOG_WARN("Packet too short to add token");
            return;
        }
        buf[9] = static_cast<uint8_t>(it->second.token.size());
        std::memcpy(buf + 10, it->second.token.data(), it->second.token.size());
        n = std::max(n, 10 + static_cast<ssize_t>(it->second.token.size()));
    }

    LOG_INFO("Пакет до отправки в РФ:");
    print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "SEND_TO_RF");

    struct sockaddr_in backend_addr{};
    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    inet_pton(AF_INET, backend_ip_.c_str(), &backend_addr.sin_addr);
    backend_addr.sin_port = htons(backend_port_);

    ssize_t sent = sendto(wg_fd_, buf, n, 0,
                          (struct sockaddr *)&backend_addr, sizeof(backend_addr));
    if (sent < 0) {
        LOG_ERROR("sendto backend failed: {}", strerror(errno));
    } else {
        LOG_INFO("Переслано {} байт в РФ", sent);
    }
}

void QuicUdpProxy::handle_backend_packet(char *buf, ssize_t n, const sockaddr_in &backend_addr, socklen_t backend_len) noexcept {
    LOG_INFO("Пакет после получения от РФ:");
    print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "RECV_FROM_RF");
    LOG_INFO("=== [SERVER → CLIENT] ===");
    LOG_INFO("Получено {} байт от сервера", n);
    print_hex(reinterpret_cast<uint8_t *>(buf), static_cast<size_t>(n), "REPLY_HEADER");

    if (n < 6) {
        LOG_WARN("Слишком короткий пакет ({}) байт", n);
        return;
    }

    uint8_t packet_type = buf[0];

    // Обработка Retry-пакета
    if ((packet_type & 0xF0) == 0xF0) {
        LOG_INFO("Received Retry packet from server");
        if (n < 9) {
            LOG_WARN("Retry packet too short");
            return;
        }
        size_t pos = 5;
        uint8_t dcil = (buf[pos] >> 4) & 0x0F;
        uint8_t scil = buf[pos] & 0x0F;
        LOG_INFO("Retry packet: DCIL={}, SCIL={}", static_cast<int>(dcil), static_cast<int>(scil));

        size_t min_retry_size = pos + 1 + dcil + scil + 1;
        if (static_cast<size_t>(n) < min_retry_size) {
            LOG_WARN("Retry packet too short for CID fields");
            return;
        }

        uint8_t *scid = reinterpret_cast<uint8_t *>(&buf[pos + 1 + dcil]);
        size_t token_offset = pos + 1 + dcil + scil;
        size_t token_len = buf[token_offset];
        if (token_offset + 1 + token_len > static_cast<size_t>(n)) {
            LOG_WARN("Invalid token length in Retry packet");
            return;
        }
        std::vector<uint8_t> token(buf + token_offset + 1, buf + token_offset + 1 + token_len);

        ClientKey key{};
        key.addr = 0; // Неизвестно, нужно получить из reverse_map
        key.port = 0;
        std::memset(key.cid, 0, 8);
        std::memcpy(key.cid, scid, std::min(static_cast<size_t>(scil), 8UL));
        key.token = token;

        // Поиск ключа клиента по SCID
        auto it = reverse_map_.find(std::vector<uint8_t>(scid, scid + scil));
        if (it == reverse_map_.end()) {
            LOG_WARN("Неизвестный SCID — пакет потерялся");
            return;
        }
        key = it->second;

        session_map_[key] = key;
        LOG_INFO("Saved Retry token for client: SCID={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                 key.cid[0], key.cid[1], key.cid[2], key.cid[3],
                 key.cid[4], key.cid[5], key.cid[6], key.cid[7]);

        struct sockaddr_in client_dest{};
        client_dest.sin_family = AF_INET;
        client_dest.sin_addr.s_addr = key.addr;
        client_dest.sin_port = key.port;

        ssize_t sent = sendto(udp_fd_, buf, n, 0,
                              (struct sockaddr *)&client_dest, sizeof(client_dest));
        if (sent < 0) {
            LOG_ERROR("sendto client failed: {}", strerror(errno));
        } else {
            LOG_INFO("Retry packet sent to client");
        }
        return;
    }

    // Обработка обычных Long Header пакетов
    if ((packet_type & 0xC0) == 0xC0) {
        size_t pos = 5;
        uint8_t dcil = (buf[pos] >> 4) & 0x0F;
        uint8_t scil = buf[pos] & 0x0F;
        LOG_INFO("Long Header: DCIL={}, SCIL={}", static_cast<int>(dcil), static_cast<int>(scil));

        if (pos + 1 + dcil + scil > static_cast<size_t>(n)) {
            LOG_WARN("Некорректные CID длины: dcil={}, scil={}, packet_size={}",
                     dcil, scil, n);
            return;
        }

        uint8_t *dcid = reinterpret_cast<uint8_t *>(&buf[pos + 1]);
        auto it = reverse_map_.find(std::vector<uint8_t>(dcid, dcid + dcil));
        if (it == reverse_map_.end()) {
            LOG_WARN("Неизвестный DCID — пакет потерялся");
            return;
        }
        ClientKey key = it->second;

        struct sockaddr_in client_dest{};
        client_dest.sin_family = AF_INET;
        client_dest.sin_addr.s_addr = key.addr;
        client_dest.sin_port = key.port;

        ssize_t sent = sendto(udp_fd_, buf, n, 0,
                              (struct sockaddr *)&client_dest, sizeof(client_dest));
        if (sent < 0) {
            LOG_ERROR("sendto client failed: {}", strerror(errno));
        } else {
            LOG_INFO("Отправлено {} байт клиенту {}:{}",
                     sent,
                     inet_ntoa(client_dest.sin_addr),
                     ntohs(client_dest.sin_port));
        }
    } else {
        LOG_DEBUG("Short Header — пропускаем");
    }
}