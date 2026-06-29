#include "internal.hpp"

#include <algorithm>
#include <cstring>

#ifdef SEDS_HAS_ZSTD
#include <zstd.h>
#endif

namespace seds {
namespace {

size_t endpoint_bitmap_bytes() { return static_cast<size_t>((kEndpointCount + 7u) / 8u); }

constexpr size_t kV4EndpointBitmapBytes = 32;
constexpr uint8_t kV4FlagCompressedPayload = 0x01;
constexpr uint8_t kV4FlagEndpointBitmapPresent = 0x20;
constexpr uint8_t kV4FlagCompactReliableHeader = 0x40;
constexpr uint8_t kV4ReliableFlagAckOnly = 0x01;
constexpr uint8_t kV4ReliableFlagUnsequenced = 0x80;
constexpr uint8_t kV4ReliableWireSeqPresent = 0x04;
constexpr uint8_t kV4ReliableWireAckPresent = 0x08;

bool is_v4_frame_flags(uint8_t flags) {
  return (flags & (0x04u | 0x08u | 0x10u | kV4FlagEndpointBitmapPresent | kV4FlagCompactReliableHeader)) != 0u ||
         (flags & ~(kV4FlagCompressedPayload | 0x04u | 0x08u | 0x10u | kV4FlagEndpointBitmapPresent |
                    kV4FlagCompactReliableHeader)) != 0u;
}

bool is_reliable_control_type(uint32_t local) {
  if (!valid_type(local)) {
    return false;
  }
  const std::string_view name(kTypeInfo[local].name);
  return name == "RELIABLE_ACK" || name == "RELIABLE_PACKET_REQUEST" || name == "RELIABLE_PARTIAL_ACK";
}

bool has_v4_reliable_header(uint32_t local) {
  return valid_type(local) && kTypeInfo[local].reliable() && !is_reliable_control_type(local);
}

uint32_t v4_type_id(uint32_t local) {
  if (!valid_type(local)) {
    return local;
  }
  const std::string_view name(kTypeInfo[local].name);
  if (name == "TELEMETRY_ERROR") return 0;
  if (name == "RELIABLE_ACK") return 1;
  if (name == "RELIABLE_PACKET_REQUEST") return 2;
  if (name == "RELIABLE_PARTIAL_ACK") return 3;
  if (name == "TIME_SYNC_ANNOUNCE") return 4;
  if (name == "TIME_SYNC_REQUEST") return 5;
  if (name == "TIME_SYNC_RESPONSE") return 6;
  if (name == "DISCOVERY_ANNOUNCE") return 7;
  if (name == "DISCOVERY_TIMESYNC_SOURCES") return 8;
  if (name == "DISCOVERY_TOPOLOGY") return 9;
  if (name == "SEDSNET_DISCOVERY_SCHEMA") return 10;
  if (name == "SEDSNET_DISCOVERY_TOPOLOGY_REQUEST") return 11;
  if (name == "SEDSNET_DISCOVERY_SCHEMA_REQUEST") return 12;
  if (name == "SEDSNET_MANAGED_VARIABLE_REQUEST") return 13;
  if (name == "SEDSNET_MANAGED_VARIABLE_VALUE") return 14;
  if (name == "SEDSNET_DISCOVERY_LEAVE") return 15;
  if (name == "SEDSNET_DISCOVERY_LINK_CAPABILITIES") return 16;
  if (name == "SEDSNET_DISCOVERY_ADDRESS") return 17;
  if (name == "SEDSNET_P2P_MESSAGE") return 18;
  if (local >= 100u) {
    return local;
  }
  return 100u + local;
}

std::optional<uint32_t> local_type_id(uint32_t wire) {
  auto by_name = [](std::string_view name) -> std::optional<uint32_t> {
    for (uint32_t i = 0; i < kTypeInfo.size(); ++i) {
      if (name == kTypeInfo[i].name) {
        return i;
      }
    }
    return std::nullopt;
  };
  switch (wire) {
    case 0: return by_name("TELEMETRY_ERROR");
    case 1: return by_name("RELIABLE_ACK");
    case 2: return by_name("RELIABLE_PACKET_REQUEST");
    case 3: return by_name("RELIABLE_PARTIAL_ACK");
    case 4: return by_name("TIME_SYNC_ANNOUNCE");
    case 5: return by_name("TIME_SYNC_REQUEST");
    case 6: return by_name("TIME_SYNC_RESPONSE");
    case 7: return by_name("DISCOVERY_ANNOUNCE");
    case 8: return by_name("DISCOVERY_TIMESYNC_SOURCES");
    case 9: return by_name("DISCOVERY_TOPOLOGY");
    case 10: return by_name("SEDSNET_DISCOVERY_SCHEMA");
    case 11: return by_name("SEDSNET_DISCOVERY_TOPOLOGY_REQUEST");
    case 12: return by_name("SEDSNET_DISCOVERY_SCHEMA_REQUEST");
    case 13: return by_name("SEDSNET_MANAGED_VARIABLE_REQUEST");
    case 14: return by_name("SEDSNET_MANAGED_VARIABLE_VALUE");
    case 15: return by_name("SEDSNET_DISCOVERY_LEAVE");
    case 16: return by_name("SEDSNET_DISCOVERY_LINK_CAPABILITIES");
    case 17: return by_name("SEDSNET_DISCOVERY_ADDRESS");
    case 18: return by_name("SEDSNET_P2P_MESSAGE");
    default:
      if (wire >= 100) {
        if (valid_type(wire)) {
          return wire;
        }
        const uint32_t local = wire - 100u;
        if (valid_type(local)) {
          return local;
        }
      }
      return std::nullopt;
  }
}

uint32_t v4_endpoint_id(uint32_t local) {
  if (!valid_endpoint(local)) {
    return local;
  }
  if (local >= 100u) {
    return local;
  }
  const std::string_view name(kEndpointNames[local]);
  if (name == "TIME_SYNC") return 200;
  if (name == "DISCOVERY") return 201;
  if (name == "TELEMETRY_ERROR") return 202;
  return 100u + local;
}

std::optional<uint32_t> local_endpoint_id(uint32_t wire) {
  auto by_name = [](std::string_view name) -> std::optional<uint32_t> {
    for (uint32_t i = 0; i < kEndpointNames.size(); ++i) {
      if (name == kEndpointNames[i]) {
        return i;
      }
    }
    return std::nullopt;
  };
  switch (wire) {
    case 200:
    case 201:
    case 202:
      if (valid_endpoint(wire)) {
        return wire;
      }
      if (wire == 200) return by_name("TIME_SYNC");
      if (wire == 201) return by_name("DISCOVERY");
      return by_name("TELEMETRY_ERROR");
    default:
      if (wire >= 100) {
        if (valid_endpoint(wire)) {
          return wire;
        }
        const uint32_t local = wire - 100u;
        if (valid_endpoint(local)) {
          return local;
        }
      }
      return std::nullopt;
  }
}

std::vector<uint8_t> v4_endpoint_bitmap(const std::vector<uint32_t> &endpoints) {
  std::vector<uint8_t> bitmap(kV4EndpointBitmapBytes, 0);
  for (const uint32_t ep : endpoints) {
    const uint32_t wire = v4_endpoint_id(ep);
    if (wire < kV4EndpointBitmapBytes * 8u) {
      bitmap[wire / 8u] |= static_cast<uint8_t>(1u << (wire % 8u));
    }
  }
  return bitmap;
}

std::vector<uint32_t> parse_v4_bitmap(const uint8_t *bitmap, size_t len) {
  std::vector<uint32_t> out;
  for (size_t i = 0; i < len * 8u; ++i) {
    if ((bitmap[i / 8] & (1u << (i % 8))) != 0u) {
      if (auto local = local_endpoint_id(static_cast<uint32_t>(i)); local.has_value()) {
        out.push_back(*local);
      }
    }
  }
  return out;
}

}  // namespace

uint32_t wire_type_id(uint32_t local) {
  return v4_type_id(local);
}

std::optional<uint32_t> local_type_from_wire_id(uint32_t wire) {
  return local_type_id(wire);
}

namespace {

uint32_t sender_address_u32(std::string_view sender) {
  uint64_t h = 0xA6D38C214B7F19E5ull;
  h = hash_bytes_u64(h, reinterpret_cast<const uint8_t *>(sender.data()), sender.size());
  const auto raw = static_cast<uint32_t>(h);
  return raw == 0 ? 1u : raw;
}

bool should_compact_reliable_header(ReliableHeaderLite header) {
  return (header.flags & kV4ReliableFlagAckOnly) != 0u || header.seq == 0 || header.ack == 0;
}

void write_v4_reliable_header(ReliableHeaderLite header, bool compact, std::vector<uint8_t> &out) {
  if (!compact) {
    out.push_back(header.flags);
    append_le<uint32_t>(header.seq, out);
    append_le<uint32_t>(header.ack, out);
    return;
  }
  uint8_t flags = header.flags;
  const bool seq_present = (header.flags & kV4ReliableFlagAckOnly) == 0 || header.seq != 0;
  const bool ack_present = header.ack != 0 || (header.flags & kV4ReliableFlagAckOnly) != 0;
  if (seq_present) flags |= kV4ReliableWireSeqPresent;
  if (ack_present) flags |= kV4ReliableWireAckPresent;
  out.push_back(flags);
  if (seq_present) write_uleb128(header.seq, out);
  if (ack_present) write_uleb128(header.ack, out);
}

std::optional<ReliableHeaderLite> read_v4_reliable_header(const uint8_t *&cur, const uint8_t *end, bool compact) {
  if (cur >= end) {
    return std::nullopt;
  }
  ReliableHeaderLite header{};
  header.flags = *cur++;
  if (!compact) {
    if (static_cast<size_t>(end - cur) < 8) {
      return std::nullopt;
    }
    std::memcpy(&header.seq, cur, 4);
    std::memcpy(&header.ack, cur + 4, 4);
    cur += 8;
    return header;
  }
  if ((header.flags & kV4ReliableWireSeqPresent) != 0u) {
    uint64_t seq = 0;
    if (!read_uleb128(cur, end, seq) || seq > UINT32_MAX) return std::nullopt;
    header.seq = static_cast<uint32_t>(seq);
  }
  if ((header.flags & kV4ReliableWireAckPresent) != 0u) {
    uint64_t ack = 0;
    if (!read_uleb128(cur, end, ack) || ack > UINT32_MAX) return std::nullopt;
    header.ack = static_cast<uint32_t>(ack);
  }
  header.flags &= ~(kV4ReliableWireSeqPresent | kV4ReliableWireAckPresent);
  return header;
}

} // namespace

void write_uleb128(uint64_t value, std::vector<uint8_t> &out) {
  do {
    auto byte = static_cast<uint8_t>(value & 0x7F);
    value >>= 7u;
    if (value != 0) {
      byte |= 0x80u;
    }
    out.push_back(byte);
  } while (value != 0);
}

bool read_uleb128(const uint8_t *&cur, const uint8_t *end, uint64_t &out) {
  out = 0;
  int shift = 0;
  for (int i = 0; i < 10; ++i) {
    if (cur >= end) {
      return false;
    }
    const uint8_t byte = *cur++;
    out |= static_cast<uint64_t>(byte & 0x7F) << shift;
    if ((byte & 0x80u) == 0) {
      return true;
    }
    shift += 7;
  }
  return false;
}

std::vector<uint8_t> endpoint_bitmap(const std::vector<uint32_t> &endpoints) {
  std::vector<uint8_t> bitmap(endpoint_bitmap_bytes(), 0);
  for (const uint32_t ep : endpoints) {
    if (valid_endpoint(ep)) {
      bitmap[ep / 8u] |= static_cast<uint8_t>(1u << (ep % 8u));
    }
  }
  return bitmap;
}

std::vector<uint32_t> parse_bitmap(const uint8_t *bitmap, size_t len) {
  std::vector<uint32_t> out;
  const size_t max_bits = std::min<size_t>(len * 8u, kEndpointCount);
  for (size_t i = 0; i < max_bits; ++i) {
    if ((bitmap[i / 8] & (1u << (i % 8))) != 0u) {
      out.push_back(static_cast<uint32_t>(i));
    }
  }
  return out;
}

std::vector<uint8_t> maybe_compress(const uint8_t *data, size_t len, bool &compressed) {
  compressed = false;
#ifdef SEDS_HAS_ZSTD
  if (len >= runtime_payload_compress_threshold()) {
    std::vector<uint8_t> out(ZSTD_compressBound(len));
    const size_t got = ZSTD_compress(out.data(), out.size(), data, len, 1);
    if (!ZSTD_isError(got) && got < len) {
      out.resize(got);
      compressed = true;
      return out;
    }
  }
#endif
  return {data, data + len};
}

std::vector<uint8_t> maybe_decompress(const uint8_t *data, size_t wire_len, size_t logical_len, bool compressed) {
  if (!compressed) {
    return {data, data + wire_len};
  }
#ifdef SEDS_HAS_ZSTD
  std::vector<uint8_t> out(logical_len);
  const size_t got = ZSTD_decompress(out.data(), out.size(), data, wire_len);
  if (ZSTD_isError(got) || got != logical_len) {
    return {};
  }
  return out;
#else
  (void)logical_len;
  return {};
#endif
}

std::optional<PacketData> deserialize_packet(const uint8_t *bytes, size_t len) {
  if (bytes == nullptr || len < 2 + kCrcBytes) {
    return std::nullopt;
  }
  const uint32_t got_crc = crc32_bytes(bytes, len - kCrcBytes);
  uint32_t exp_crc = 0;
  std::memcpy(&exp_crc, bytes + len - kCrcBytes, kCrcBytes);
  if (got_crc != exp_crc) {
    return std::nullopt;
  }

  const uint8_t v4_flags = bytes[0];
  if (is_v4_frame_flags(v4_flags)) {
    const uint8_t *cur_v4 = bytes;
    const uint8_t *end_v4 = bytes + len - kCrcBytes;
    const uint8_t flags = *cur_v4++;
    const bool payload_compressed = (flags & kV4FlagCompressedPayload) != 0u;
    const bool endpoint_bitmap_present = (flags & kV4FlagEndpointBitmapPresent) != 0u;
    const bool compact_reliable = (flags & kV4FlagCompactReliableHeader) != 0u;
    const uint8_t nep = *cur_v4++;
    uint64_t wire_ty = 0;
    uint64_t logical_size = 0;
    uint64_t timestamp = 0;
    uint64_t source_address = 0;
    if (!read_uleb128(cur_v4, end_v4, wire_ty) || !read_uleb128(cur_v4, end_v4, logical_size) ||
        !read_uleb128(cur_v4, end_v4, timestamp)) {
      return std::nullopt;
    }
    if ((flags & 0x08u) != 0u) {
      uint64_t nonce = 0;
      if (!read_uleb128(cur_v4, end_v4, nonce)) {
        return std::nullopt;
      }
    }
    if (!read_uleb128(cur_v4, end_v4, source_address)) {
      return std::nullopt;
    }
    const auto local_ty = local_type_id(static_cast<uint32_t>(wire_ty));
    if (!local_ty || !valid_type(*local_ty)) {
      return std::nullopt;
    }
    std::vector<uint32_t> endpoints;
    if (endpoint_bitmap_present) {
      if (static_cast<size_t>(end_v4 - cur_v4) < kV4EndpointBitmapBytes) {
        return std::nullopt;
      }
      endpoints = parse_v4_bitmap(cur_v4, kV4EndpointBitmapBytes);
      cur_v4 += kV4EndpointBitmapBytes;
    } else {
      endpoints = kTypeInfo[*local_ty].endpoints;
    }
    if (endpoints.size() != nep) {
      return std::nullopt;
    }
    if ((flags & 0x04u) != 0u) {
      uint64_t contract_len = 0;
      if (!read_uleb128(cur_v4, end_v4, contract_len) ||
          static_cast<uint64_t>(end_v4 - cur_v4) < contract_len) {
        return std::nullopt;
      }
      cur_v4 += contract_len;
    }
    if (has_v4_reliable_header(*local_ty)) {
      auto reliable = read_v4_reliable_header(cur_v4, end_v4, compact_reliable);
      if (!reliable || (reliable->flags & kV4ReliableFlagAckOnly) != 0u) {
        return std::nullopt;
      }
    }
    const size_t payload_wire_len = static_cast<size_t>(end_v4 - cur_v4);
    auto payload = maybe_decompress(cur_v4, payload_wire_len, static_cast<size_t>(logical_size), payload_compressed);
    if (payload.size() != logical_size) {
      return std::nullopt;
    }
    PacketData pkt;
    pkt.ty = *local_ty;
    pkt.sender = "@addr:" + std::to_string(source_address);
    pkt.endpoints = std::move(endpoints);
    pkt.timestamp = timestamp;
    pkt.payload = std::move(payload);
    return pkt;
  }

  const uint8_t *cur = bytes;
  const uint8_t *end = bytes + len - kCrcBytes;
  const uint8_t flags = *cur++;
  const uint8_t nep = *cur++;
  uint64_t ty = 0;
  uint64_t logical_size = 0;
  uint64_t timestamp = 0;
  uint64_t sender_len = 0;
  uint64_t sender_wire_len = 0;
  if (!read_uleb128(cur, end, ty) || !read_uleb128(cur, end, logical_size) || !read_uleb128(cur, end, timestamp) ||
      !read_uleb128(cur, end, sender_len)) {
    return std::nullopt;
  }
  if ((flags & kFlagCompressedSender) != 0u) {
    if (!read_uleb128(cur, end, sender_wire_len)) {
      return std::nullopt;
    }
  } else {
    sender_wire_len = sender_len;
  }
  if (!valid_type(static_cast<uint32_t>(ty))) {
    return std::nullopt;
  }
  const size_t bitmap_len = endpoint_bitmap_bytes();
  if (static_cast<size_t>(end - cur) < bitmap_len + sender_wire_len) {
    return std::nullopt;
  }
  std::vector<uint32_t> endpoints = parse_bitmap(cur, bitmap_len);
  cur += bitmap_len;
  if (endpoints.size() != nep) {
    return std::nullopt;
  }

  const auto sender_bytes = maybe_decompress(cur, static_cast<size_t>(sender_wire_len), static_cast<size_t>(sender_len),
                                             (flags & kFlagCompressedSender) != 0u);
  if (sender_bytes.size() != sender_len) {
    return std::nullopt;
  }
  cur += sender_wire_len;
  if (kTypeInfo[ty].reliable()) {
    if (static_cast<size_t>(end - cur) < kReliableHeaderBytes) {
      return std::nullopt;
    }
    if ((cur[0] & 0x01u) != 0u) {
      return std::nullopt;
    }
    cur += kReliableHeaderBytes;
  }

  const auto payload_wire_len = static_cast<size_t>(end - cur);
  auto payload = maybe_decompress(cur, payload_wire_len, static_cast<size_t>(logical_size),
                                  (flags & kFlagCompressedPayload) != 0u);
  if (payload.size() != logical_size) {
    return std::nullopt;
  }

  PacketData pkt;
  pkt.ty = static_cast<uint32_t>(ty);
  pkt.sender.assign(reinterpret_cast<const char *>(sender_bytes.data()), sender_bytes.size());
  pkt.endpoints = std::move(endpoints);
  pkt.timestamp = timestamp;
  pkt.payload = std::move(payload);
  return pkt;
}

std::vector<uint8_t> serialize_packet(const PacketData &pkt) {
  if (pkt.ty == static_cast<uint32_t>(SEDS_DT_RELIABLE_ACK) && pkt.payload.size() == sizeof(uint32_t) * 2u &&
      pkt.sender.rfind("E2EACK:", 0) != 0) {
    uint32_t acked_ty = 0;
    uint32_t ack = 0;
    std::memcpy(&acked_ty, pkt.payload.data(), sizeof(acked_ty));
    std::memcpy(&ack, pkt.payload.data() + sizeof(acked_ty), sizeof(ack));
    if (const auto local_ty = local_type_from_wire_id(acked_ty); local_ty.has_value()) {
      acked_ty = *local_ty;
    }
    return serialize_reliable_ack(pkt.sender, acked_ty, pkt.timestamp, ack);
  }
  if (has_v4_reliable_header(pkt.ty)) {
    return serialize_packet_with_reliable(pkt, ReliableHeaderLite{kV4ReliableFlagUnsequenced, 0u, 0u});
  }
  std::vector<uint8_t> out;
  bool payload_compressed = false;
  auto payload_wire = maybe_compress(pkt.payload.data(), pkt.payload.size(), payload_compressed);
  uint8_t flags = 0;
  if (payload_compressed)
    flags |= kV4FlagCompressedPayload;
  flags |= kV4FlagEndpointBitmapPresent;
  out.push_back(flags);
  out.push_back(static_cast<uint8_t>(pkt.endpoints.size()));
  write_uleb128(v4_type_id(pkt.ty), out);
  write_uleb128(pkt.payload.size(), out);
  write_uleb128(pkt.timestamp, out);
  write_uleb128(sender_address_u32(pkt.sender), out);
  const auto bitmap = v4_endpoint_bitmap(pkt.endpoints);
  out.insert(out.end(), bitmap.begin(), bitmap.end());
  out.insert(out.end(), payload_wire.begin(), payload_wire.end());
  append_le<uint32_t>(crc32_bytes(out.data(), out.size()), out);
  return out;
}

std::vector<uint8_t> serialize_packet_with_reliable(const PacketData &pkt, ReliableHeaderLite header) {
  std::vector<uint8_t> out;
  bool payload_compressed = false;
  auto payload_wire = maybe_compress(pkt.payload.data(), pkt.payload.size(), payload_compressed);
  const bool compact_reliable = should_compact_reliable_header(header);
  uint8_t flags = 0;
  if (payload_compressed)
    flags |= kV4FlagCompressedPayload;
  flags |= kV4FlagEndpointBitmapPresent;
  if (compact_reliable)
    flags |= kV4FlagCompactReliableHeader;
  out.push_back(flags);
  out.push_back(static_cast<uint8_t>(pkt.endpoints.size()));
  write_uleb128(v4_type_id(pkt.ty), out);
  write_uleb128(pkt.payload.size(), out);
  write_uleb128(pkt.timestamp, out);
  write_uleb128(sender_address_u32(pkt.sender), out);
  const auto bitmap = v4_endpoint_bitmap(pkt.endpoints);
  out.insert(out.end(), bitmap.begin(), bitmap.end());
  if (has_v4_reliable_header(pkt.ty)) {
    write_v4_reliable_header(header, compact_reliable, out);
  }
  out.insert(out.end(), payload_wire.begin(), payload_wire.end());
  append_le<uint32_t>(crc32_bytes(out.data(), out.size()), out);
  return out;
}

std::vector<uint8_t> serialize_reliable_ack(std::string_view sender, uint32_t ty, uint64_t timestamp_ms, uint32_t ack) {
  std::vector<uint8_t> out;
  out.push_back(static_cast<uint8_t>(kV4FlagEndpointBitmapPresent | kV4FlagCompactReliableHeader));
  out.push_back(0u);
  write_uleb128(v4_type_id(ty), out);
  write_uleb128(0u, out);
  write_uleb128(timestamp_ms, out);
  write_uleb128(sender_address_u32(sender), out);
  out.insert(out.end(), kV4EndpointBitmapBytes, 0u);
  write_v4_reliable_header(ReliableHeaderLite{kV4ReliableFlagAckOnly, 0u, ack}, true, out);
  append_le<uint32_t>(crc32_bytes(out.data(), out.size()), out);
  return out;
}

std::optional<FrameInfoLite> peek_frame_info(const uint8_t *bytes, size_t len, bool verify_crc) {
  if (bytes == nullptr || len < 2 + kCrcBytes) {
    return std::nullopt;
  }
  if (verify_crc) {
    const uint32_t got_crc = crc32_bytes(bytes, len - kCrcBytes);
    uint32_t exp_crc = 0;
    std::memcpy(&exp_crc, bytes + len - kCrcBytes, kCrcBytes);
    if (got_crc != exp_crc) {
      return std::nullopt;
    }
  }
  const uint8_t v4_flags = bytes[0];
  if (is_v4_frame_flags(v4_flags)) {
    const uint8_t *cur_v4 = bytes;
    const uint8_t *end_v4 = bytes + len - kCrcBytes;
    const uint8_t flags = *cur_v4++;
    const bool endpoint_bitmap_present = (flags & kV4FlagEndpointBitmapPresent) != 0u;
    const bool compact_reliable = (flags & kV4FlagCompactReliableHeader) != 0u;
    const uint8_t nep = *cur_v4++;
    uint64_t wire_ty = 0, dsz = 0, ts = 0, source_address = 0;
    if (!read_uleb128(cur_v4, end_v4, wire_ty) || !read_uleb128(cur_v4, end_v4, dsz) ||
        !read_uleb128(cur_v4, end_v4, ts)) {
      return std::nullopt;
    }
    if ((flags & 0x08u) != 0u) {
      uint64_t nonce = 0;
      if (!read_uleb128(cur_v4, end_v4, nonce)) return std::nullopt;
    }
    if (!read_uleb128(cur_v4, end_v4, source_address)) {
      return std::nullopt;
    }
    const auto local_ty = local_type_id(static_cast<uint32_t>(wire_ty));
    if (!local_ty || !valid_type(*local_ty)) {
      return std::nullopt;
    }
    std::vector<uint32_t> endpoints;
    if (endpoint_bitmap_present) {
      if (static_cast<size_t>(end_v4 - cur_v4) < kV4EndpointBitmapBytes) {
        return std::nullopt;
      }
      endpoints = parse_v4_bitmap(cur_v4, kV4EndpointBitmapBytes);
      cur_v4 += kV4EndpointBitmapBytes;
    } else {
      endpoints = kTypeInfo[*local_ty].endpoints;
    }
    if (endpoints.size() != nep) {
      return std::nullopt;
    }
    if ((flags & 0x04u) != 0u) {
      uint64_t contract_len = 0;
      if (!read_uleb128(cur_v4, end_v4, contract_len) ||
          static_cast<uint64_t>(end_v4 - cur_v4) < contract_len) {
        return std::nullopt;
      }
      cur_v4 += contract_len;
    }
    std::optional<ReliableHeaderLite> reliable;
    if (has_v4_reliable_header(*local_ty)) {
      reliable = read_v4_reliable_header(cur_v4, end_v4, compact_reliable);
      if (!reliable) {
        return std::nullopt;
      }
    }
    return FrameInfoLite{
        TelemetryEnvelopeLite{*local_ty, std::move(endpoints), "@addr:" + std::to_string(source_address), ts},
        reliable};
  }
  const uint8_t *cur = bytes;
  const uint8_t *end = bytes + len - kCrcBytes;
  const uint8_t flags = *cur++;
  const bool sender_compressed = (flags & kFlagCompressedSender) != 0u;
  const uint8_t nep = *cur++;
  uint64_t ty = 0, dsz = 0, ts = 0, sender_len = 0, sender_wire_len = 0;
  if (!read_uleb128(cur, end, ty) || !read_uleb128(cur, end, dsz) || !read_uleb128(cur, end, ts) ||
      !read_uleb128(cur, end, sender_len)) {
    return std::nullopt;
  }
  if (sender_compressed) {
    if (!read_uleb128(cur, end, sender_wire_len)) {
      return std::nullopt;
    }
  } else {
    sender_wire_len = sender_len;
  }
  const size_t bitmap_len = endpoint_bitmap_bytes();
  if (!valid_type(static_cast<uint32_t>(ty)) || static_cast<size_t>(end - cur) < bitmap_len + sender_wire_len) {
    return std::nullopt;
  }
  auto endpoints = parse_bitmap(cur, bitmap_len);
  cur += bitmap_len;
  if (endpoints.size() != nep) {
    return std::nullopt;
  }
  const auto sender_bytes =
      maybe_decompress(cur, static_cast<size_t>(sender_wire_len), static_cast<size_t>(sender_len), sender_compressed);
  if (sender_bytes.size() != sender_len) {
    return std::nullopt;
  }
  cur += sender_wire_len;
  std::optional<ReliableHeaderLite> reliable;
  if (kTypeInfo[ty].reliable()) {
    if (static_cast<size_t>(end - cur) < kReliableHeaderBytes) {
      return std::nullopt;
    }
    ReliableHeaderLite hdr{};
    hdr.flags = cur[0];
    std::memcpy(&hdr.seq, cur + 1, 4);
    std::memcpy(&hdr.ack, cur + 5, 4);
    reliable = hdr;
  }
  return FrameInfoLite{
      TelemetryEnvelopeLite{static_cast<uint32_t>(ty), std::move(endpoints),
                            std::string(reinterpret_cast<const char *>(sender_bytes.data()), sender_bytes.size()), ts},
      reliable};
}

std::optional<size_t> reliable_header_offset(const uint8_t *bytes, size_t len) {
  if (bytes == nullptr || len < 2 + kCrcBytes) {
    return std::nullopt;
  }
  const uint8_t v4_flags = bytes[0];
  if (is_v4_frame_flags(v4_flags)) {
    const uint8_t *cur_v4 = bytes;
    const uint8_t *end_v4 = bytes + len - kCrcBytes;
    const uint8_t flags = *cur_v4++;
    const bool endpoint_bitmap_present = (flags & kV4FlagEndpointBitmapPresent) != 0u;
    cur_v4++;
    uint64_t wire_ty = 0, dsz = 0, ts = 0, source_address = 0;
    if (!read_uleb128(cur_v4, end_v4, wire_ty) || !read_uleb128(cur_v4, end_v4, dsz) ||
        !read_uleb128(cur_v4, end_v4, ts)) {
      return std::nullopt;
    }
    if ((flags & 0x08u) != 0u) {
      uint64_t nonce = 0;
      if (!read_uleb128(cur_v4, end_v4, nonce)) return std::nullopt;
    }
    if (!read_uleb128(cur_v4, end_v4, source_address)) {
      return std::nullopt;
    }
    const auto local_ty = local_type_id(static_cast<uint32_t>(wire_ty));
    if (!local_ty || !has_v4_reliable_header(*local_ty)) {
      return std::nullopt;
    }
    if (endpoint_bitmap_present) {
      if (static_cast<size_t>(end_v4 - cur_v4) < kV4EndpointBitmapBytes) return std::nullopt;
      cur_v4 += kV4EndpointBitmapBytes;
    }
    if ((flags & 0x04u) != 0u) {
      uint64_t contract_len = 0;
      if (!read_uleb128(cur_v4, end_v4, contract_len) ||
          static_cast<uint64_t>(end_v4 - cur_v4) < contract_len) {
        return std::nullopt;
      }
      cur_v4 += contract_len;
    }
    return static_cast<size_t>(cur_v4 - bytes);
  }
  const uint8_t *cur = bytes;
  const uint8_t *end = bytes + len - kCrcBytes;
  const uint8_t flags = *cur++;
  const bool sender_compressed = (flags & kFlagCompressedSender) != 0u;
  cur++;
  uint64_t ty = 0, dsz = 0, ts = 0, sender_len = 0, sender_wire_len = 0;
  if (!read_uleb128(cur, end, ty) || !read_uleb128(cur, end, dsz) || !read_uleb128(cur, end, ts) ||
      !read_uleb128(cur, end, sender_len)) {
    return std::nullopt;
  }
  if (sender_compressed) {
    if (!read_uleb128(cur, end, sender_wire_len)) {
      return std::nullopt;
    }
  } else {
    sender_wire_len = sender_len;
  }
  const size_t bitmap_len = endpoint_bitmap_bytes();
  if (!valid_type(static_cast<uint32_t>(ty)) || static_cast<size_t>(end - cur) < bitmap_len + sender_wire_len) {
    return std::nullopt;
  }
  cur += bitmap_len + sender_wire_len;
  if (!kTypeInfo[ty].reliable()) {
    return std::nullopt;
  }
  return static_cast<size_t>(cur - bytes);
}

bool rewrite_reliable_header(uint8_t *bytes, size_t len, uint8_t flags, uint32_t seq, uint32_t ack) {
  const auto off = reliable_header_offset(bytes, len);
  if (!off || len < *off + kReliableHeaderBytes + kCrcBytes) {
    return false;
  }
  bytes[*off] = flags;
  std::memcpy(bytes + *off + 1, &seq, 4);
  std::memcpy(bytes + *off + 5, &ack, 4);
  const uint32_t crc = crc32_bytes(bytes, len - kCrcBytes);
  std::memcpy(bytes + len - kCrcBytes, &crc, 4);
  return true;
}

std::optional<uint64_t> packet_id_from_wire(const uint8_t *bytes, size_t len) {
  const auto pkt = deserialize_packet(bytes, len);
  if (!pkt) {
    return std::nullopt;
  }
  return packet_id(*pkt);
}

} // namespace seds
