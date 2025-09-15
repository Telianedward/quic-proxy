// quic_udp_proxy.cpp
//
// UDP-прокси для HTTP/3 с поддержкой двусторонней передачи.
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
#include <sys/select.h>
// Хеш для std::vector<uint8_t>
struct VectorHash {
    size_t operator()(const std::vector<uint8_t>& v) const {
        std::hash<uint64_t> hasher;
        size_t result = 0;
        for (size_t i = 0; i < v.size(); ++i) {
            result ^= hasher(v[i]) + 2654435761U + (result << 6) + (result >> 2);
        }
        return result;
    }
};

// Равенство для vector
struct VectorEqual {
    bool operator()(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) const {
        return a == b;
    }
};

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

// Карта: оригинальный SCID + клиент → локальный CID
std::unordered_map<ClientKey, std::vector<uint8_t>, ClientKeyHash> session_map;

// Карта: LocalCID → ClientKey (для обратного пути)
std::unordered_map<std::vector<uint8_t>, ClientKey, VectorHash, VectorEqual> reverse_map;

// Неблокирующий режим
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

// Генератор локальных CID
std::vector<uint8_t> generate_local_cid() {
    std::vector<uint8_t> cid(8);
    for (int i = 0; i < 8; ++i) {
        cid[i] = rand() % 256;
    }
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

// Вывод байтов как hex
void print_hex(const uint8_t* data, size_t len, const std::string& label) {
    std::cout << "[" << label << "] ";
    for (size_t i = 0; i < len; ++i) {
        printf("%02x ", data[i]);
    }
    std::cout << std::endl;
}

int main() {
    int udp_fd = -1, wg_fd = -1;
    struct sockaddr_in client_addr, backend_addr, listen_addr;
    socklen_t client_len = sizeof(client_addr);
    socklen_t backend_len = sizeof(backend_addr);

    // Регистрация обработчика сигналов
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // --- Создание сокета для клиентов (порт 443) ---
    udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0) {
        perror("socket udp_fd failed");
        return 1;
    }

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

    if (set_nonblocking(wg_fd) == -1) {
        perror("set_nonblocking wg_fd failed");
        close(udp_fd);
        close(wg_fd);
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
    fd_set read_fds;

    while (running) {
        FD_ZERO(&read_fds);
        FD_SET(udp_fd, &read_fds);
        FD_SET(wg_fd, &read_fds);
        int max_fd = std::max(udp_fd, wg_fd);

        timeval timeout{.tv_sec = 0, .tv_usec = 100000};
        int activity = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);
        if (activity < 0 && errno != EINTR) {
            std::cerr << "select error: " << strerror(errno) << std::endl;
            continue;
        }

        // === НАПРАВЛЕНИЕ: КЛИЕНТ → СЕРВЕР (в РФ) ===
        if (FD_ISSET(udp_fd, &read_fds)) {
            ssize_t n = recvfrom(udp_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&client_addr, &client_len);

            if (n < 0 || n >= MAX_PACKET_SIZE) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    std::cerr << "recvfrom client failed: " << strerror(errno) << std::endl;
                continue;
            }

            std::string client_ip = inet_ntoa(client_addr.sin_addr);
            uint16_t client_port = ntohs(client_addr.sin_port);

            std::cout << "\n=== [CLIENT → SERVER] ===" << std::endl;
            std::cout << "[PACKET] Получено " << n << " байт от " << client_ip << ":" << client_port << std::endl;
            print_hex((uint8_t*)buf, std::min(n, 32L), "HEADER");

            if (n < 6) {
                std::cout << "[PACKET] Слишком короткий пакет" << std::endl;
                continue;
            }

            uint8_t packet_type = buf[0];
            if ((packet_type & 0xC0) != 0xC0) {
                std::cout << "[PACKET] Short Header — пропускаем" << std::endl;
                continue;
            }

            uint32_t version = (buf[1] << 24) | (buf[2] << 16) | (buf[3] << 8) | buf[4];
            size_t pos = 5;
            uint8_t dcil = buf[pos];
            uint8_t scil = buf[pos + 1];

            std::cout << "[QUIC] Версия: 0x" << std::hex << version << std::dec
                      << ", DCIL=" << (int)dcil << ", SCIL=" << (int)scil << std::endl;

            if (dcil == 0 || scil == 0 || pos + 2 + dcil + scil > (size_t)n) {
                std::cout << "[PACKET] Некорректные CID" << std::endl;
                continue;
            }

            uint8_t* dcid = (uint8_t*)&buf[pos + 2];
            uint8_t* scid = (uint8_t*)&buf[pos + 2 + dcil];

            // Ключ: клиент + первые 8 байт SCID
            ClientKey key;
            key.addr = client_addr.sin_addr.s_addr;
            key.port = client_addr.sin_port;
            memset(key.cid, 0, 8);
            memcpy(key.cid, scid, std::min((size_t)scil, (size_t)8));

            auto it = session_map.find(key);
            std::vector<uint8_t> local_cid;
            if (it == session_map.end()) {
                local_cid = generate_local_cid();
                session_map[key] = local_cid;
                reverse_map[local_cid] = key;
                std::cout << "[SESSION] Новая сессия: "
                          << client_ip << ":" << client_port << " → LocalCID:";
                for (int i = 0; i < 8; ++i) printf("%02x", local_cid[i]);
                std::cout << std::endl;
            } else {
                local_cid = it->second;
                std::cout << "[SESSION] Reuse LocalCID:";
                for (int i = 0; i < 8; ++i) printf("%02x", local_cid[i]);
                std::cout << std::endl;
            }

            // === МОДИФИКАЦИЯ ПАКЕТА ===
            buf[pos + 1] = 8;  // Устанавливаем SCIL = 8
            memcpy(scid, local_cid.data(), 8);
            ssize_t new_len = n - (scil - 8);  // Обрезаем лишнее

            ssize_t sent = sendto(wg_fd, buf, new_len, 0,
                                  (struct sockaddr*)&backend_addr, sizeof(backend_addr));
            if (sent < 0) {
                std::cerr << "sendto backend failed: " << strerror(errno) << std::endl;
            } else {
                std::cout << "[FORWARD] Переслано " << sent << " байт в РФ" << std::endl;
            }
        }

        // === НАПРАВЛЕНИЕ: СЕРВЕР → КЛИЕНТ ===
        if (FD_ISSET(wg_fd, &read_fds)) {
            ssize_t n = recvfrom(wg_fd, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&backend_addr, &backend_len);

            if (n < 0 || n >= MAX_PACKET_SIZE) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                    std::cerr << "recvfrom backend failed: " << strerror(errno) << std::endl;
                continue;
            }

            std::cout << "\n=== [SERVER → CLIENT] ===" << std::endl;
            std::cout << "[REPLY] Получено " << n << " байт от сервера" << std::endl;
            print_hex((uint8_t*)buf, std::min(n, 32L), "REPLY_HEADER");

            if (n < 6) continue;

            uint8_t packet_type = buf[0];
            if ((packet_type & 0xC0) != 0xC0) {
                std::cout << "[REPLY] Short Header — пропускаем" << std::endl;
                continue;
            }

            size_t pos = 5;
            uint8_t dcil = buf[pos];
            uint8_t scil = buf[pos + 1];

            if (dcil == 0 || scil == 0 || pos + 2 + dcil + scil > (size_t)n) {
                std::cout << "[REPLY] Некорректные CID" << std::endl;
                continue;
            }

            uint8_t* dcid = (uint8_t*)&buf[pos + 2];  // Это LocalCID

            // Поиск оригинального ключа по LocalCID
            std::vector<uint8_t> local_cid_vec(dcid, dcid + 8);
            auto rev_it = reverse_map.find(local_cid_vec);
            if (rev_it == reverse_map.end()) {
                std::cout << "[REPLY] Неизвестный LocalCID — пакет потерялся" << std::endl;
                continue;
            }

            ClientKey orig_key = rev_it->second;
            uint8_t* orig_scid = orig_key.cid;

            // Увеличиваем DCIL до оригинальной длины (берём из ключа — но у нас только 8 байт)
            // Предполагаем, что клиент ожидает SCID такой же длины, как он отправил
            // В простом случае — можно использовать SCIL=8, если клиент не требует больше
            buf[pos] = 8;     // DCIL = 8
            buf[pos + 1] = orig_key.cid[7] ? 8 : 0;  // Упрощённо: ставим 8
            memcpy(dcid, orig_scid, 8);

            // Формируем адрес клиента
            struct sockaddr_in client_dest;
            memset(&client_dest, 0, sizeof(client_dest));
            client_dest.sin_family = AF_INET;
            client_dest.sin_addr.s_addr = orig_key.addr;
            client_dest.sin_port = orig_key.port;

            ssize_t sent = sendto(udp_fd, buf, n, 0,
                                  (struct sockaddr*)&client_dest, sizeof(client_dest));
            if (sent < 0) {
                std::cerr << "sendto client failed: " << strerror(errno) << std::endl;
            } else {
                std::cout << "[REPLY] Отправлено " << sent << " байт клиенту "
                          << inet_ntoa(client_dest.sin_addr) << ":" << ntohs(client_dest.sin_port) << std::endl;
            }
        }
    }

    std::cout << "[PROXY] Остановлен." << std::endl;
    if (udp_fd != -1) close(udp_fd);
    if (wg_fd != -1) close(wg_fd);
    return 0;
}