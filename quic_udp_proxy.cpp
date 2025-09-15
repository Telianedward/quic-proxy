// quic_udp_proxy.cpp
//
// Простой UDP-прокси для end-to-end HTTP/3.
// Пересылает QUIC-пакеты с порта 443 через WireGuard в РФ.
// Автоматически определяет внешний IP.
//
// Компиляция: g++ -O2 -o quic_proxy quic_udp_proxy.cpp -pthread
// Запуск: sudo ./quic_proxy

#include <iostream>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <csignal>
#include <cerrno>
#include <string>

// Настройки
const char* BACKEND_IP = "10.8.0.11";       // IP твоего C++ сервера в РФ (через WG)
const int BACKEND_PORT = 8585;               // Порт H3-сервера
const int LISTEN_PORT = 443;                 // Порт для клиентов (HTTPS)
const size_t MAX_PACKET_SIZE = 1500;         // Максимальный размер UDP-пакета

// Глобальный флаг для graceful shutdown
volatile bool running = true;

// Обработчик сигналов
void signal_handler(int sig) {
    std::cout << "\n[PROXY] Получен сигнал " << sig << ". Остановка...\n";
    running = false;
}

// Хеш для ClientKey
struct ClientKey {
    uint32_t addr;
    uint16_t port;
    uint8_t cid[8];

    bool operator==(const ClientKey& other) const {
        return addr == other.addr && port == other.port &&
               memcmp(cid, other.cid, 8) == 0;
    }
};

struct ClientKeyHash {
    size_t operator()(const ClientKey& k) const {
        return std::hash<uint32_t>()(k.addr) ^
               std::hash<uint16_t>()(k.port) ^
               std::hash<uint64_t>()(*reinterpret_cast<const uint64_t*>(k.cid));
    }
};

// Карта: оригинальный CID + клиент → локальный CID
std::unordered_map<ClientKey, std::vector<uint8_t>, ClientKeyHash> session_map;

// Неблокирующий режим
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Генератор локальных CID
std::vector<uint8_t> generate_local_cid() {
    static uint64_t counter = 0;
    std::vector<uint8_t> cid(8);
    memcpy(cid.data(), &counter, sizeof(counter));
    counter++;
    return cid;
}

// Автоопределение внешнего IP
bool get_external_ip(std::string& ip_out) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct sockaddr_in temp_addr{};
    temp_addr.sin_family = AF_INET;
    temp_addr.sin_port = htons(53); // DNS
    inet_pton(AF_INET, "8.8.8.8", &temp_addr.sin_addr);

    if (connect(sock, (struct sockaddr*)&temp_addr, sizeof(temp_addr)) < 0) {
        close(sock);
        return false;
    }

    socklen_t len = sizeof(temp_addr);
    if (getsockname(sock, (struct sockaddr*)&temp_addr, &len) < 0) {
        close(sock);
        return false;
    }

    ip_out = inet_ntoa(temp_addr.sin_addr);
    close(sock);
    return true;
}

int main() {
    int udp_fd = -1, wg_fd = -1;
    struct sockaddr_in client_addr, backend_addr, listen_addr;
    socklen_t client_len;

    // Регистрация обработчика сигналов
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // --- Создание сокета для клиентов (порт 443) ---
    udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0) {
        perror("socket udp_fd failed");
        return 1;
    }

    // Устанавливаем опции для повторного использования порта
    int opt = 1;
    if (setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
    }
    if (setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEPORT failed");
    }

    if (set_nonblocking(udp_fd) == -1) {
        perror("set_nonblocking udp_fd failed");
        close(udp_fd);
        return 1;
    }

    // --- Определение внешнего IP ---
    std::string external_ip;
    if (!get_external_ip(external_ip)) {
        std::cerr << "[ERROR] Не удалось определить внешний IP. Использую INADDR_ANY.\n";
        listen_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, external_ip.c_str(), &listen_addr.sin_addr.s_addr);
    }

    // --- Привязка к порту ---
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(LISTEN_PORT);

    if (bind(udp_fd, (struct sockaddr*)&listen_addr, sizeof(listen_addr)) < 0) {
        perror("bind udp_fd failed");
        close(udp_fd);
        return 1;
    }

    // --- Создание сокета для отправки в РФ ---
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
              << ", слушает IP: " << external_ip
              << ", бэкенд: " << BACKEND_IP << ":" << BACKEND_PORT << std::endl;

    char buf[MAX_PACKET_SIZE];
    while (running) {
        client_len = sizeof(client_addr);
        ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0,
                             (struct sockaddr*)&client_addr, &client_len);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                usleep(1000);
                continue;
            }
            std::cerr << "recvfrom failed: " << strerror(errno) << std::endl;
            continue;
        }

        // === ЛОГИРУЕМ КАЖДЫЙ ПАКЕТ ===
        std::cout << "[PACKET] Получено " << n << " байт от "
                  << inet_ntoa(client_addr.sin_addr) << ":"
                  << ntohs(client_addr.sin_port)
                  << " | Первые 16 байт: ";
        for (int i = 0; i < std::min(n, 16L); ++i) {
            printf("%02x ", (uint8_t)buf[i]);
        }
        std::cout << std::endl;

        if (n < 5) continue;

        // Проверяем, Initial ли это пакет
        uint8_t packet_type = buf[0];
        if ((packet_type & 0xC0) != 0xC0) {
            std::cout << "[PACKET] Не Initial Packet (type=0x" << std::hex << (int)packet_type << std::dec << "), пропускаем\n";
            continue;
        }

        uint8_t dcid_len = buf[1];
        if (dcid_len < 1 || dcid_len > 20) {
            std::cout << "[PACKET] Некорректная длина DCID: " << (int)dcid_len << "\n";
            continue;
        }

        size_t offset = 2 + dcid_len;
        if (offset + 1 >= (size_t)n) {
            std::cout << "[PACKET] Слишком короткий пакет для SCID\n";
            continue;
        }

        uint8_t scid_len = buf[offset];
        if (scid_len < 8) {
            std::cout << "[PACKET] SCID слишком короткий: " << (int)scid_len << "\n";
            continue;
        }

        offset += 1;
        if (offset + scid_len > (size_t)n) {
            std::cout << "[PACKET] SCID выходит за пределы пакета\n";
            continue;
        }

        uint8_t* scid = (uint8_t*)&buf[offset];

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
                      << ntohs(client_addr.sin_port)
                      << " [CID:";
            for (int i = 0; i < 8; ++i) printf("%02x", key.cid[i]);
            std::cout << "] -> LocalCID:";
            for (int i = 0; i < 8; ++i) printf("%02x", local_cid[i]);
            std::cout << std::endl;
        } else {
            local_cid = it->second;
        }

        // Заменяем Source CID на локальный
        memcpy(&buf[offset], local_cid.data(), 8);

        // Отправляем в РФ
        ssize_t sent = sendto(wg_fd, buf, n, 0,
                              (struct sockaddr*)&backend_addr, sizeof(backend_addr));
        if (sent < 0) {
            std::cerr << "sendto backend failed: " << strerror(errno) << std::endl;
        } else {
            std::cout << "[FORWARD] Переслано " << sent << " байт в РФ ("
                      << BACKEND_IP << ":" << BACKEND_PORT << ")\n";
        }
    }

    std::cout << "[PROXY] Остановлен." << std::endl;
    if (udp_fd != -1) close(udp_fd);
    if (wg_fd != -1) close(wg_fd);
    return 0;
}