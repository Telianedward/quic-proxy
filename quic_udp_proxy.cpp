// quic_udp_proxy.cpp
//
// Минимальный UDP-прокси для HTTP/3.
// Только логирует входящие пакеты — НЕ ПЕРЕСЫЛАЕТ.
// Используется для диагностики и проверки, что трафик доходит.
//
// Компиляция: g++ -O2 -o quic_proxy quic_udp_proxy.cpp
// Запуск: sudo ./quic_proxy

#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <csignal>
#include <cerrno>
#include <string>

// Настройки
const int LISTEN_PORT = 443;                 // Порт для клиентов
const size_t MAX_PACKET_SIZE = 1500;         // Максимальный размер UDP-пакета

// Глобальный флаг для graceful shutdown
volatile bool running = true;

// Обработчик сигналов
void signal_handler(int sig) {
    std::cout << "\n[PROXY] Получен сигнал " << sig << ". Остановка...\n";
    running = false;
}

// Установка неблокирующего режима
int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
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
    int udp_fd = -1;
    struct sockaddr_in client_addr, listen_addr;
    socklen_t client_len;

    // Обработчик Ctrl+C
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    // --- Создание UDP-сокета ---
    udp_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (udp_fd < 0) {
        perror("socket failed");
        return 1;
    }

    // Reuse address and port
    int opt = 1;
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(udp_fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    if (set_nonblocking(udp_fd) == -1) {
        perror("set_nonblocking failed");
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
        perror("bind failed");
        close(udp_fd);
        return 1;
    }

    std::cout << "[PROXY] Запущен на порту " << LISTEN_PORT
              << ", слушает IP: " << (external_ip.empty() ? "0.0.0.0" : external_ip)
              << std::endl;

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
            std::cerr << "recvfrom error: " << strerror(errno) << std::endl;
            continue;
        }

        // === ЛОГИРУЕМ ПАКЕТ ===
        std::cout << "[PACKET] "
                  << n << " байт от "
                  << inet_ntoa(client_addr.sin_addr) << ":"
                  << ntohs(client_addr.sin_port)
                  << " → ";
        for (int i = 0; i < std::min(n, 16L); ++i) {
            printf("%02x ", (uint8_t)buf[i]);
        }
        std::cout << (n > 16 ? "... " : "") << std::endl;
    }

    std::cout << "[PROXY] Остановлен." << std::endl;
    if (udp_fd != -1) close(udp_fd);
    return 0;
}