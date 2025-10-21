// #include <iostream>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <unistd.h>
// #include <fcntl.h>
// #include <arpa/inet.h>

// int main() {
//     int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
//     if (fd < 0) {
//         std::cerr << "socket failed\n";
//         return 1;
//     }

//     struct sockaddr_in addr{};
//     addr.sin_family = AF_INET;
//     addr.sin_addr.s_addr = INADDR_ANY; // можно заменить на 5.129.238.35
//     addr.sin_port = htons(443);

//     int opt = 1;
//     setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
//     setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

//     if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
//         std::cerr << "bind failed\n";
//         close(fd);
//         return 1;
//     }

//     std::cout << "[TEST] Слушаю UDP на порту 443...\n";

//     char buf[1500];
//     while (true) {
//         socklen_t client_len = sizeof(struct sockaddr_in);
//         ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, nullptr, &client_len);
//         if (n > 0) {
//             std::cout << "[TEST] Получено " << n << " байт!\n";
//         } else if (n < 0 && errno != EAGAIN) {
//             std::cerr << "recvfrom error: " << errno << "\n";
//         }
//         usleep(1000);
//     }

//     close(fd);
//     return 0;
// }