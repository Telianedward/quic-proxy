// quic_udp_proxy.hpp
//
// Заголовочный файл для UDP-прокси QUIC через WireGuard.
// Содержит объявления всех типов, функций и констант.
//
// Версия: 1.2 (исправлено)
#pragma once

#include <iostream>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <string>
#include <cstdint>  // ✅ Добавлено: для uint8_t, uint16_t, uint32_t

/**
 * @brief Хеш-функция для std::vector<uint8_t>
 */
struct VectorHash
{
    size_t operator()(const std::vector<uint8_t> &v) const noexcept;
};

/**
 * @brief Оператор сравнения для векторов байтов
 */
struct VectorEqual
{
    bool operator()(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b) const noexcept;
};

/**
 * @brief Ключ клиента: IP, порт и первые 8 байт SCID
 */
struct ClientKey
{
    uint32_t addr;          ///< IPv4-адрес клиента
    uint16_t port;          ///< Порт клиента
    uint8_t cid[8];         ///< Первые 8 байт исходного SCID

    bool operator==(const ClientKey &other) const noexcept;
};

/**
 * @brief Хеш для структуры ClientKey
 */
struct ClientKeyHash
{
    size_t operator()(const ClientKey &k) const noexcept;
};

// === Глобальные константы ===
constexpr char BACKEND_IP[] = "10.8.0.11";   ///< IP сервера в РФ через WireGuard
constexpr int BACKEND_PORT = 8585;           ///< Порт H3-сервера в РФ
constexpr int LISTEN_PORT = 443;             ///< Порт, на котором слушает прокси (HTTPS)
constexpr size_t MAX_PACKET_SIZE = 1500;     ///< Максимальный размер UDP-пакета

// === Глобальные переменные ===
extern std::unordered_map<ClientKey, std::vector<uint8_t>, ClientKeyHash> session_map;
extern std::unordered_map<std::vector<uint8_t>, ClientKey, VectorHash, VectorEqual> reverse_map;

// === Функции ===

/**
 * @brief Устанавливает неблокирующий режим сокета
 * @param fd Дескриптор сокета
 * @return 0 при успехе, -1 при ошибке
 */
int set_nonblocking(int fd) noexcept;

/**
 * @brief Генерирует случайный 8-байтовый CID
 * @return Вектор из 8 случайных байт
 */
std::vector<uint8_t> generate_local_cid() noexcept;

/**
 * @brief Определяет внешний IP-адрес системы через подключение к 8.8.8.8:53
 * @param ip_out Строка для сохранения IP
 * @return true, если удалось определить
 * @warning Может вернуть неверный IP при нескольких интерфейсах
 */
bool get_external_ip(std::string &ip_out) noexcept;

/**
 * @brief Выводит байты в hex-формате (первые 32 байта)
 * @param data Указатель на данные
 * @param len Длина данных
 * @param label Метка для вывода (например, "HEADER")
 */
void print_hex(const uint8_t *data, size_t len, const std::string &label) noexcept;

/**
 * @brief Обработчик сигналов завершения (SIGINT, SIGTERM)
 * @param sig Номер сигнала
 */
void signal_handler(int sig);