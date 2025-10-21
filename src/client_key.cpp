/**
 * @file client_key.cpp
 * @brief Реализация методов, объявленных в соответствующем .h файле.
 *
 * Здесь реализуются методы, утилитные функции, бизнес-логика.
 * Файл работает с PostgreSQL через libpqxx и соответствует стандартам C++23.
 *
 * @author Telian Edward <telianedward@icloud.com>
 * @assisted-by AI-Assistant
 * @date 2025-10-21
 * @version 1.0
 * @license MIT
 */

// src/client_key.cpp
#include "../include/client_key.hpp"

size_t ClientKeyHash::operator()(const ClientKey &k) const noexcept
{
    std::hash<uint32_t> hasher;
    size_t result = hasher(k.addr) ^
                    (std::hash<uint16_t>()(k.port) << 1) ^
                    std::hash<uint64_t>()(*reinterpret_cast<const uint64_t *>(k.cid));
    return result;
}

bool ClientKeyEqual::operator()(const ClientKey &a, const ClientKey &b) const noexcept
{
    return a.addr == b.addr && a.port == b.port &&
           std::memcmp(a.cid, b.cid, 8) == 0 &&
           a.token == b.token; // Добавлено сравнение токена
}

bool ClientKey::operator==(const ClientKey &other) const noexcept
{
    return addr == other.addr && port == other.port &&
           std::memcmp(cid, other.cid, 8) == 0 &&
           token == other.token; // Добавлено сравнение токена
}