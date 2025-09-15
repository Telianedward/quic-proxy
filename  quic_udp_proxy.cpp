// quic_udp_proxy.cpp
#include <iostream>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

// Адрес твоего C++ сервера в РФ (через WireGuard)
const char* BACKEND_IP = "10.8.0.11";
const int BACKEND_PORT = 8585;

// Локальный порт для клиентов
const int LISTEN_PORT = 443;

// Максимальный размер QUIC-пакета
const size_t MAX_PACKET_SIZE = 1500;

struct ClientKey {
    uint32_t addr;     // IPv4 клиента
    uint16_t port;     // Порт клиента
    uint8_t cid[8];    // Первые 8 байт Source CID

    bool operator==(const ClientKey& other) const {
        return addr == other.addr && port == other.port &&
               memcmp(cid, other.cid, 8) == 0;
    }
};

// Хеш для unordered_map
struct ClientKeyHash {
    size_t operator()(const ClientKey& k) const {
        return std::hash<uint32_t>()(k.addr) ^
               std::hash<uint16_t>()(k.port) ^
               std::hash<uint64_t>()(*reinterpret_cast<const uint64_t*>(k.cid));
    }
};

// Карта: client + original_cid → local_cid
std::unordered_map<ClientKey, std::vector<uint8_t>, ClientKeyHash> session_map;

// Генератор локальных CID
std::vector<uint8_t> generate_local_cid() {
    static uint64_t counter = 0;
    std::vector<uint8_t> cid(8);
    memcpy(cid.data(), &counter, sizeof(counter));
    counter++;
    return cid;
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

int main() {
    int udp_fd, wg_fd;
    struct sockaddr_in client_addr, backend_addr, listen_addr;
    socklen_t client_len;

    // --- Сокет для клиентов (порт 443) ---
    udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0) {
        perror("socket udp_fd failed");
        return 1;
    }

    if (set_nonblocking(udp_fd) == -1) {
        perror("set_nonblocking udp_fd failed");
        close(udp_fd);
        return 1;
    }

    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(LISTEN_PORT);

    if (bind(udp_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind udp_fd failed");
        close(udp_fd);
        return 1;
    }

    // --- Сокет для отправки в РФ ---
    wg_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (wg_fd < 0) {
        perror("socket wg_fd failed");
        close(udp_fd);
        return 1;
    }

    memset(&backend_addr, 0, sizeof(backend_addr));
    backend_addr.sin_family = AF_INET;
    inet_pton(AF_INET, BACKEND_IP, &backend_addr.sin_addr);
    backend_addr.sin_port = htons(BACKEND_PORT);

    std::cout << "[PROXY] Запущен на порту " << LISTEN_PORT
              << ", бэкенд: " << BACKEND_IP << ":" << BACKEND_PORT << std::endl;

    char buf[MAX_PACKET_SIZE];
    while (true) {
        client_len = sizeof(client_addr);
        ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0,
                             (struct sockaddr*)&client_addr, &client_len);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            perror("recvfrom failed");
            continue;
        }

        if (n < 5) continue;

        // Проверяем, Initial ли это пакет
        uint8_t packet_type = buf[0];
        if ((packet_type & 0xC0) != 0xC0) { // не Initial
            continue;
        }

        uint8_t dcid_len = buf[1];
        uint8_t scid_len = buf[2 + dcid_len];

        if (scid_len < 8) continue;

        uint8_t* scid = (uint8_t*)&buf[2 + dcid_len + 1];

        // Ключ: клиент + оригинальный CID
        ClientKey key;
        key.addr = client_addr.sin_addr.s_addr;
        key.port = client_addr.sin_port;
        memcpy(key.cid, scid, 8);

        // Генерируем или получаем локальный CID
        auto it = session_map.find(key);
        std::vector<uint8_t> local_cid;
        if (it == session_map.end()) {
            local_cid = generate_local_cid();
            session_map[key] = local_cid;
            std::cout << "[PROXY] Новая сессия: "
                      << inet_ntoa(client_addr.sin_addr) << ":"
                      << ntohs(client_addr.sin_port) << "\n";
        } else {
            local_cid = it->second;
        }

        // Заменяем Source CID на локальный
        memcpy(&buf[2 + dcid_len + 1], local_cid.data(), 8);

        // Отправляем в РФ
        if (sendto(wg_fd, buf, n, 0,
                   (struct sockaddr*)&backend_addr, sizeof(backend_addr)) < 0) {
            perror("sendto backend failed");
        }
    }

    close(udp_fd);
    close(wg_fd);
    return 0;
}