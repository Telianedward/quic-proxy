/**
 * @file quic_udp_deduplicator.cpp
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
// src/quic_udp_deduplicator.cpp
#include "../include/quic_udp_deduplicator.hpp"
#include "../include/client_key.hpp"
#include <cstring>

size_t Deduplicator::PacketKeyHash::operator()(const PacketKey &key) const noexcept
{
    size_t result = 0;
    // Хэшируем ClientKey
    result ^= std::hash<uint32_t>()(key.client_key.addr);
    result ^= std::hash<uint16_t>()(key.client_key.port);
    for (uint8_t b : key.client_key.cid)
    {
        result ^= std::hash<uint8_t>()(b) + 2654435761U + (result << 6) + (result >> 2);
    }
    // Хэшируем SCID
    for (uint8_t b : key.scid)
    {
        result ^= std::hash<uint8_t>()(b) + 2654435761U + (result << 6) + (result >> 2);
    }
    // Хэшируем DCID
    for (uint8_t b : key.dcid)
    {
        result ^= std::hash<uint8_t>()(b) + 2654435761U + (result << 6) + (result >> 2);
    }
    // Хэшируем Packet Number
    result ^= std::hash<uint64_t>()(key.packet_number);
    return result;
}

bool Deduplicator::PacketKeyEqual::operator()(const PacketKey &a, const PacketKey &b) const noexcept
{
    return a.client_key == b.client_key &&
           a.scid == b.scid &&
           a.dcid == b.dcid &&
           a.packet_number == b.packet_number;
}

void Deduplicator::add_packet(const ClientKey &key, const PacketInfo &info)
{
    PacketKey packet_key{};
    packet_key.client_key = key;
    packet_key.scid = info.scid;
    packet_key.dcid = {}; // DCID пока неизвестен, можно установить позже
    packet_key.packet_number = info.packet_number;

    seen_packets_[packet_key] = true;
}

bool Deduplicator::is_duplicate(const ClientKey &key, const std::vector<uint8_t> &scid, const std::vector<uint8_t> &dcid, uint64_t packet_number) const
{
    PacketKey packet_key{};
    packet_key.client_key = key;
    packet_key.scid = scid;
    packet_key.dcid = dcid;
    packet_key.packet_number = packet_number;

    auto it = seen_packets_.find(packet_key);
    if (it != seen_packets_.end())
    {
        return true; // Это дубликат
    }

    return false; // Это первый пакет
}

void Deduplicator::remove_connection(const ClientKey &key)
{
    packet_map_.erase(key);
}