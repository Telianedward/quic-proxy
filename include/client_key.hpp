// include/client_key.hpp
/**
 * @file client_key.hpp
 * @brief Краткое описание назначения заголовочного файла.
 *
 * Более подробное описание того, какие классы, функции, структуры объявляет файл.
 * Может содержать информацию о зависимости от других модулей или ограничениях использования.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-21
 * @version 1.0
 * @license MIT
 */
#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <unordered_map>

/**
 * @brief Структура для хранения ключа клиента.
 *
 * Используется как ключ в session_map и Deduplicator.
 */
struct ClientKey {
    uint32_t addr;          ///< IPv4-адрес клиента
    uint16_t port;          ///< Порт клиента
    uint8_t cid[8];         ///< Первые 8 байт SCID
    std::vector<uint8_t> token; ///< Токен из Retry-пакета

    bool operator==(const ClientKey &other) const noexcept;
};

/**
 * @brief Хеш-функция для ClientKey.
 */
struct ClientKeyHash {
    size_t operator()(const ClientKey &k) const noexcept;
};

/**
 * @brief Оператор сравнения для ClientKey.
 */
struct ClientKeyEqual {
    bool operator()(const ClientKey &a, const ClientKey &b) const noexcept;
};