// src/quic_udp_deduplicator.cpp
#include "../include/quic_udp_deduplicator.hpp"
#include "../include/client_key.hpp"
#include <cstring>

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