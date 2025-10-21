// include/quic_udp_proxy.hpp
/**
 * @file quic_udp_proxy.hpp
 * @brief Заголовочный файл для QUIC-UDP прокси.
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
#pragma once
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <cstdint>
#include <random>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <csignal>
#include <cerrno>
#include <sys/select.h>
#include <thread>
#include "../logger/logger.h"
#include "client_key.hpp"
#include "quic_udp_deduplicator.hpp"

/**
 * @brief Класс QUIC-UDP прокси.
 *
 * Слушает входящие QUIC-пакеты на порту 443 и перенаправляет их на сервер в России (через WireGuard).
 */
// === Хэш-функции и равенство для std::vector<uint8_t> ===
struct VectorHash {
    size_t operator()(const std::vector<uint8_t> &v) const noexcept {
        size_t result = 0;
        for (uint8_t b : v) {
            result ^= static_cast<size_t>(b);
            result *= 2654435761U; // FNV prime
        }
        return result;
    }
};

struct VectorEqual {
    bool operator()(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) const noexcept {
        if (a.size() != b.size())
            return false;
        return std::equal(a.begin(), a.end(), b.begin());
    }
};

/**
 * @brief Класс QUIC-UDP прокси.
 *
 * Слушает входящие QUIC-пакеты на порту 443 и перенаправляет их на сервер в России (через WireGuard).
 */
class QuicUdpProxy {
public:
    /**
     * @brief Конструктор.
     * @param listen_port Порт, на котором слушает прокси (обычно 443).
     * @param backend_ip IP-адрес сервера в России.
     * @param backend_port Порт сервера в России.
     */
    QuicUdpProxy(int listen_port, const std::string& backend_ip, int backend_port);

    /**
     * @brief Запускает QUIC-UDP прокси.
     * @return true при успешном завершении, false при ошибке.
     */
    bool run();

    /**
     * @brief Останавливает QUIC-UDP прокси.
     */
    void stop();

private:
    int udp_fd_;              ///< Сокет для прослушивания входящих пакетов от клиентов
    int wg_fd_;               ///< Сокет для отправки пакетов на сервер в России
    int listen_port_;         ///< Порт, на котором слушает прокси
    int backend_port_;        ///< Порт сервера в России
    std::string backend_ip_;  ///< IP сервера в России
    volatile sig_atomic_t running_{true}; ///< Флаг работы прокси

    // Map: ClientKey -> ClientKey (для хранения токена)
    std::unordered_map<ClientKey, ClientKey, ClientKeyHash, ClientKeyEqual> session_map_;
    // Reverse map: DCID -> ClientKey (для поиска клиента по DCID)
    std::unordered_map<std::vector<uint8_t>, ClientKey, VectorHash, VectorEqual> reverse_map_;
    Deduplicator deduplicator_; // Экземпляр дедупликатора

    /**
     * @brief Устанавливает неблокирующий режим сокета.
     * @param fd Дескриптор сокета.
     * @return 0 при успехе, -1 при ошибке.
     */
    [[nodiscard]] int set_nonblocking(int fd) noexcept;

    /**
     * @brief Генерирует случайный 8-байтовый CID.
     * @return Вектор из 8 случайных байт.
     */
    [[nodiscard]] std::vector<uint8_t> generate_local_cid() noexcept;

    /**
     * @brief Определяет внешний IP-адрес системы.
     * @param ip_out Строка для сохранения IP.
     * @return true, если удалось определить.
     */
    [[nodiscard]] bool get_external_ip(std::string &ip_out) noexcept;

    /**
     * @brief Выводит байты в hex-формате.
     * @param data Указатель на данные.
     * @param len Длина данных.
     * @param label Метка для вывода.
     */
    void print_hex(const uint8_t *data, size_t len, const std::string &label) noexcept;

    /**
     * @brief Обработчик сигналов завершения.
     * @param sig Номер сигнала.
     */
    static void signal_handler(int sig);

    /**
     * @brief Обрабатывает пакет от клиента.
     * @param buf Буфер с данными пакета.
     * @param n Размер пакета.
     * @param client_addr Адрес клиента.
     * @param client_len Размер структуры адреса.
     */
    void handle_client_packet(char *buf, ssize_t n, const sockaddr_in &client_addr, socklen_t client_len) noexcept;

    /**
     * @brief Обрабатывает пакет от сервера в России.
     * @param buf Буфер с данными пакета.
     * @param n Размер пакета.
     * @param backend_addr Адрес сервера.
     * @param backend_len Размер структуры адреса.
     */
    void handle_backend_packet(char *buf, ssize_t n, const sockaddr_in &backend_addr, socklen_t backend_len) noexcept;
};