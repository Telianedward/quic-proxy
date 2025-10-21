// src/quic_udp_deduplicator.cpp
#include "../include/quic_udp_deduplicator.hpp"
#include "../include/client_key.hpp"
#include <cstring>

// Реализация функций для структур, которые находятся в global scope, а не внутри Deduplicator

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

void Deduplicator::add_packet(const ClientKey &key, const PacketInfo &info)
{
    packet_map_[key] = info;
}

bool Deduplicator::is_duplicate(const ClientKey &key, const std::vector<uint8_t> &scid, const std::vector<uint8_t> &token) const
{
    auto it = packet_map_.find(key);
    if (it == packet_map_.end())
    {
        return false; // Нет информации о первом пакете — это первый пакет
    }

    // Проверяем, совпадают ли SCID и токен с теми, что в первом пакете
    if (it->second.scid == scid && it->second.token == token)
    {
        return true; // Это повторный пакет
    }

    return false; // Это новый пакет
}

void Deduplicator::remove_connection(const ClientKey &key)
{
    packet_map_.erase(key);
}