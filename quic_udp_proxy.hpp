/**
 * @file quic_udp_proxy.hpp
 * @brief Краткое описание назначения заголовочного файла.
 *
 * Более подробное описание того, какие классы, функции, структуры объявляет файл.
 * Может содержать информацию о зависимости от других модулей или ограничениях использования.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-09-29
 * @version 1.0
 * @license MIT
 *
 * @note Этот файл требует стандарта C++23 (ISO/IEC 14882:2024).
 * Используются: std::vector, std::unordered_map, std::random_device, std::mt19937.
 *
 * @note Внешние зависимости:
 * - Стандартная библиотека C++23.
 * - Системные заголовки: <sys/socket.h>, <netinet/in.h>, <unistd.h>.
 * - Не требует сторонних библиотек.
 */

#pragma once

#include <iostream>
#include <cstring>
#include <unordered_map>
#include <vector>
#include <string>
#include <cstdint>   // Для uint8_t, uint16_t, uint32_t
#include <algorithm> // Для std::min, std::max
#include <cstdlib>   // Для std::srand, std::rand
#include "server/logger.h"



// === Глобальные константы ===
constexpr char BACKEND_IP[] = "10.8.0.11";   ///< IP сервера в РФ через WireGuard
constexpr int BACKEND_PORT = 8585;           ///< Порт H3-сервера в РФ
constexpr int LISTEN_PORT = 443;             ///< Порт, на котором слушает прокси (HTTPS)
constexpr size_t MAX_PACKET_SIZE = 1500;     ///< Максимальный размер UDP-пакета

static_assert(MAX_PACKET_SIZE <= 65536, "MAX_PACKET_SIZE должен быть <= 65536");

// === Глобальные переменные ===

/**
 * @brief Маппинг ключа клиента → локальный CID.
 *
 * Используется для восстановления оригинального SCID при ответе от сервера.
 */
extern std::unordered_map<ClientKey, ClientKey, ClientKeyHash> session_map;

/**
 * @brief Обратный маппинг: локальный CID → ключ клиента.
 *
 * Используется для поиска клиента по CID при получении ответа от сервера.
 */
extern std::unordered_map<std::vector<uint8_t>, ClientKey, VectorHash, VectorEqual> reverse_map;

// === Функции ===

/**
 * @brief Устанавливает неблокирующий режим сокета
 * @param fd Дескриптор сокета
 * @return 0 при успехе, -1 при ошибке
 * @throws Никаких исключений — функция не выбрасывает.
 */
[[nodiscard]] int set_nonblocking(int fd) noexcept;

/**
 * @brief Генерирует случайный 8-байтовый CID
 * @return Вектор из 8 случайных байт
 * @throws Никаких исключений — функция не выбрасывает.
 */
[[nodiscard]] std::vector<uint8_t> generate_local_cid() noexcept;

/**
 * @brief Определяет внешний IP-адрес системы через подключение к 8.8.8.8:53
 * @param ip_out Строка для сохранения IP
 * @return true, если удалось определить
 * @throws Никаких исключений — функция не выбрасывает.
 * @warning Может вернуть неверный IP при нескольких интерфейсах
 */
[[nodiscard]] bool get_external_ip(std::string &ip_out) noexcept;

/**
 * @brief Выводит байты в hex-формате (первые 32 байта)
 * @param data Указатель на данные
 * @param len Длина данных
 * @param label Метка для вывода (например, "HEADER")
 * @throws Никаких исключений — функция не выбрасывает.
 */
void print_hex(const uint8_t *data, size_t len, const std::string &label) noexcept;

/**
 * @brief Обработчик сигналов завершения (SIGINT, SIGTERM)
 * @param sig Номер сигнала
 * @throws Никаких исключений — функция не выбрасывает.
 */
void signal_handler(int sig);