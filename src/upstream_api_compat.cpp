#include "internal.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace {

std::map<uint32_t, std::string> g_runtime_endpoint_names;
std::map<uint32_t, std::string> g_runtime_type_names;
std::map<uint32_t, std::string> g_runtime_endpoint_descriptions;
std::map<uint32_t, std::string> g_runtime_type_descriptions;
std::map<uint32_t, bool> g_runtime_endpoint_link_local;
std::map<uint32_t, uint8_t> g_runtime_type_priorities;
std::map<uint32_t, uint8_t> g_runtime_type_e2e_policies;
std::once_flag g_runtime_schema_once;
std::mutex g_runtime_tuning_mu;
SedsRuntimeTuningConfig g_runtime_tuning_config{
  seds::kCompressionThreshold,
  seds::kStaticStringLength,
  seds::kStaticHexLength,
  seds::kStringPrecision,
  seds::kMaxHandlerRetries,
  static_cast<uint32_t>(seds::kReliableRetransmitMs),
  seds::kReliableMaxRetries,
  seds::kReliableMaxPending,
  seds::kReliableMaxReturnRoutes,
  seds::kReliableMaxEndToEndPending,
  seds::kReliableMaxEndToEndAckCache,
};
std::string g_runtime_device_identifier{"CPP"};
SedsCryptoSealFn g_crypto_seal = nullptr;
SedsCryptoOpenFn g_crypto_open = nullptr;
void * g_crypto_user = nullptr;
std::unordered_map<uint32_t, std::array<uint8_t, 32>> g_software_keys;

constexpr uint8_t kP2pStreamMagic[4] = {'S', 'D', 'S', 'P'};
constexpr uint8_t kP2pStreamVersion = 1;
constexpr uint8_t kP2pStreamSyn = 0x01;
constexpr uint8_t kP2pStreamAck = 0x02;
constexpr uint8_t kP2pStreamFin = 0x04;
constexpr uint8_t kP2pStreamRst = 0x08;
constexpr uint8_t kP2pStreamData = 0x10;
constexpr size_t kSoftwareKeyMinLen = 16;
constexpr size_t kSoftwareTagLen = 16;
constexpr size_t kManagedCredentialLen = 80;
constexpr size_t kManagedCredentialBodyLen = 48;
constexpr uint8_t kManagedCredentialMagic[8] = {'S', 'E', 'D', 'S', 'C', 'R', '1', 0};

template<typename T>
void append_le(std::vector<uint8_t> & out, T value)
{
  for (size_t i = 0; i < sizeof(T); ++i)
  {
    out.push_back(static_cast<uint8_t>((static_cast<uint64_t>(value) >> (8u * i)) & 0xffu));
  }
}

uint16_t read_u16_le(const uint8_t * ptr)
{
  return static_cast<uint16_t>(ptr[0]) | (static_cast<uint16_t>(ptr[1]) << 8u);
}

uint32_t read_u32_le(const uint8_t * ptr)
{
  return static_cast<uint32_t>(ptr[0]) | (static_cast<uint32_t>(ptr[1]) << 8u) |
         (static_cast<uint32_t>(ptr[2]) << 16u) | (static_cast<uint32_t>(ptr[3]) << 24u);
}

uint64_t read_u64_le(const uint8_t * ptr)
{
  uint64_t out = 0;
  for (size_t i = 0; i < 8; ++i)
  {
    out |= static_cast<uint64_t>(ptr[i]) << (8u * i);
  }
  return out;
}

template<typename T>
void write_le(uint8_t * out, T value)
{
  for (size_t i = 0; i < sizeof(T); ++i)
  {
    out[i] = static_cast<uint8_t>((static_cast<uint64_t>(value) >> (8u * i)) & 0xffu);
  }
}

uint32_t address_for_sender(std::string_view sender)
{
  const auto raw = static_cast<uint32_t>(seds::sender_hash(sender));
  return raw == 0 ? 1u : raw;
}

uint32_t local_p2p_address(SedsRouter & r)
{
  if (r.p2p_address == 0)
  {
    r.p2p_address = address_for_sender(r.sender);
    r.p2p_address_book[r.sender] = r.p2p_address;
    r.p2p_host_by_address[r.p2p_address] = r.sender;
  }
  return r.p2p_address;
}

bool valid_runtime_tuning_config(const SedsRuntimeTuningConfig & cfg)
{
  return cfg.static_string_length != 0 && cfg.static_hex_length != 0 && cfg.max_handler_retries != 0 &&
         cfg.reliable_retransmit_ms != 0 && cfg.reliable_max_retries != 0 && cfg.reliable_max_pending != 0 &&
         cfg.reliable_max_return_routes != 0 && cfg.reliable_max_end_to_end_pending != 0 &&
         cfg.reliable_max_end_to_end_ack_cache != 0;
}

uint32_t p2p_type_id()
{
  return seds::local_type_from_wire_id(18).value_or(1018u);
}

uint32_t c_api_type_id(uint32_t ty)
{
  const auto raw_valid = [](uint32_t id)
  {
    return id < seds::kTypeInfo.size() && seds::kTypeInfo[id].name != nullptr && seds::kTypeInfo[id].name[0] != '\0';
  };
  if (raw_valid(ty))
  {
    return ty;
  }
  const auto by_name = [&](std::string_view name) -> std::optional<uint32_t>
  {
    for (uint32_t i = 0; i < seds::kTypeInfo.size(); ++i)
    {
      if (seds::kTypeInfo[i].name != nullptr && name == seds::kTypeInfo[i].name)
      {
        return i;
      }
    }
    return std::nullopt;
  };
  switch (ty)
  {
    case 0: return by_name("TELEMETRY_ERROR").value_or(ty);
    case 1: return by_name("RELIABLE_ACK").value_or(ty);
    case 2: return by_name("RELIABLE_PACKET_REQUEST").value_or(ty);
    case 3: return by_name("RELIABLE_PARTIAL_ACK").value_or(ty);
    case 4: return by_name("TIME_SYNC_ANNOUNCE").value_or(ty);
    case 5: return by_name("TIME_SYNC_REQUEST").value_or(ty);
    case 6: return by_name("TIME_SYNC_RESPONSE").value_or(ty);
    case 7: return by_name("DISCOVERY_ANNOUNCE").value_or(ty);
    case 8: return by_name("DISCOVERY_TIMESYNC_SOURCES").value_or(ty);
    case 9: return by_name("DISCOVERY_TOPOLOGY").value_or(ty);
    case 10: return by_name("SEDSNET_DISCOVERY_SCHEMA").value_or(ty);
    case 11: return by_name("SEDSNET_DISCOVERY_TOPOLOGY_REQUEST").value_or(ty);
    case 12: return by_name("SEDSNET_DISCOVERY_SCHEMA_REQUEST").value_or(ty);
    case 13: return by_name("SEDSNET_MANAGED_VARIABLE_REQUEST").value_or(ty);
    case 14: return by_name("SEDSNET_MANAGED_VARIABLE_VALUE").value_or(ty);
    case 15: return by_name("SEDSNET_DISCOVERY_LEAVE").value_or(ty);
    case 16: return by_name("SEDSNET_DISCOVERY_LINK_CAPABILITIES").value_or(ty);
    case 17: return by_name("SEDSNET_DISCOVERY_ADDRESS").value_or(ty);
    case 18: return by_name("SEDSNET_P2P_MESSAGE").value_or(ty);
    default:
      return ty;
  }
}

bool is_internal_endpoint_id(uint32_t endpoint)
{
  return endpoint == SEDS_EP_TIME_SYNC || endpoint == SEDS_EP_DISCOVERY || endpoint == SEDS_EP_TELEMETRY_ERROR;
}

bool is_internal_type_id(uint32_t ty)
{
  ty = c_api_type_id(ty);
  if (!seds::valid_type(ty))
  {
    return false;
  }
  const std::string_view name(seds::kTypeInfo[ty].name);
  return name == "TELEMETRY_ERROR" || name == "RELIABLE_ACK" || name == "RELIABLE_PACKET_REQUEST" ||
         name == "RELIABLE_PARTIAL_ACK" || name == "TIME_SYNC_ANNOUNCE" || name == "TIME_SYNC_REQUEST" ||
         name == "TIME_SYNC_RESPONSE" || name == "DISCOVERY_ANNOUNCE" || name == "DISCOVERY_TIMESYNC_SOURCES" ||
         name == "DISCOVERY_TOPOLOGY" || name == "SEDSNET_DISCOVERY_SCHEMA" ||
         name == "SEDSNET_DISCOVERY_TOPOLOGY_REQUEST" || name == "SEDSNET_DISCOVERY_SCHEMA_REQUEST" ||
         name == "SEDSNET_MANAGED_VARIABLE_REQUEST" || name == "SEDSNET_MANAGED_VARIABLE_VALUE" ||
         name == "SEDSNET_DISCOVERY_LEAVE" || name == "SEDSNET_DISCOVERY_LINK_CAPABILITIES" ||
         name == "SEDSNET_DISCOVERY_ADDRESS" || name == "SEDSNET_P2P_MESSAGE";
}

std::string_view endpoint_description(uint32_t endpoint)
{
  const auto it = g_runtime_endpoint_descriptions.find(endpoint);
  return it == g_runtime_endpoint_descriptions.end() ? std::string_view{} : std::string_view(it->second);
}

std::string_view type_description(uint32_t ty)
{
  const auto it = g_runtime_type_descriptions.find(ty);
  return it == g_runtime_type_descriptions.end() ? std::string_view{} : std::string_view(it->second);
}

bool endpoint_link_local(uint32_t endpoint)
{
  const auto it = g_runtime_endpoint_link_local.find(endpoint);
  return it == g_runtime_endpoint_link_local.end() ? false : it->second;
}

uint8_t type_priority(uint32_t ty)
{
  const auto it = g_runtime_type_priorities.find(ty);
  return it == g_runtime_type_priorities.end() ? 0u : it->second;
}

uint8_t type_e2e_policy(uint32_t ty)
{
  const auto it = g_runtime_type_e2e_policies.find(ty);
  return it == g_runtime_type_e2e_policies.end() ? SEDS_E2E_PREFER_OFF : it->second;
}

const char * route_mode_name(SedsRouteSelectionMode mode)
{
  switch (mode)
  {
    case Seds_RSM_Weighted: return "Weighted";
    case Seds_RSM_Failover: return "Failover";
    case Seds_RSM_Fanout:
    default: return "Fanout";
  }
}

const char * side_transport_profile_name(SedsSideTransportProfile profile)
{
  switch (profile)
  {
    case SEDS_SIDE_TRANSPORT_PROFILE_TEMPLATE: return "template";
    case SEDS_SIDE_TRANSPORT_PROFILE_IPV6_LIKE: return "ipv6_like";
    case SEDS_SIDE_TRANSPORT_PROFILE_IPV4_LIKE: return "ipv4_like";
    case SEDS_SIDE_TRANSPORT_PROFILE_CANONICAL:
    default: return "canonical";
  }
}

void apply_side_transport_profile(seds::Side & side, SedsSideTransportProfile profile, size_t max_frame_bytes,
                                  size_t compact_header_target_bytes, size_t max_side_transport_templates)
{
  side.side_transport_profile = profile;
  side.max_frame_bytes = max_frame_bytes;
  side.max_side_transport_templates = max_side_transport_templates;
  side.header_template_enabled = false;
  side.compact_header_target_bytes = compact_header_target_bytes;
  switch (profile)
  {
    case SEDS_SIDE_TRANSPORT_PROFILE_TEMPLATE:
      side.header_template_enabled = true;
      break;
    case SEDS_SIDE_TRANSPORT_PROFILE_IPV6_LIKE:
      side.header_template_enabled = true;
      side.compact_header_target_bytes = compact_header_target_bytes == 0 ? 40u : compact_header_target_bytes;
      break;
    case SEDS_SIDE_TRANSPORT_PROFILE_IPV4_LIKE:
      side.header_template_enabled = true;
      side.compact_header_target_bytes = compact_header_target_bytes == 0 ? 20u : compact_header_target_bytes;
      break;
    case SEDS_SIDE_TRANSPORT_PROFILE_CANONICAL:
    default:
      break;
  }
}

class Sha256
{
public:
  void update(std::span<const uint8_t> input)
  {
    len_bits_ += static_cast<uint64_t>(input.size()) * 8u;
    if (buffer_len_ > 0)
    {
      const size_t take = std::min<size_t>(64u - buffer_len_, input.size());
      std::copy_n(input.data(), take, buffer_.data() + buffer_len_);
      buffer_len_ += take;
      input = input.subspan(take);
      if (buffer_len_ == 64u)
      {
        compress(buffer_);
        buffer_len_ = 0;
      }
    }
    while (input.size() >= 64u)
    {
      std::array<uint8_t, 64> block{};
      std::copy_n(input.data(), 64, block.data());
      compress(block);
      input = input.subspan(64);
    }
    if (!input.empty())
    {
      std::copy(input.begin(), input.end(), buffer_.begin());
      buffer_len_ = input.size();
    }
  }

  [[nodiscard]] std::array<uint8_t, 32> finalize()
  {
    buffer_[buffer_len_++] = 0x80u;
    if (buffer_len_ > 56u)
    {
      std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_len_), buffer_.end(), 0);
      compress(buffer_);
      buffer_len_ = 0;
    }
    std::fill(buffer_.begin() + static_cast<std::ptrdiff_t>(buffer_len_), buffer_.begin() + 56, 0);
    for (size_t i = 0; i < 8; ++i)
    {
      buffer_[56 + i] = static_cast<uint8_t>((len_bits_ >> (56u - i * 8u)) & 0xffu);
    }
    compress(buffer_);
    std::array<uint8_t, 32> out{};
    for (size_t i = 0; i < state_.size(); ++i)
    {
      out[i * 4] = static_cast<uint8_t>(state_[i] >> 24u);
      out[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16u);
      out[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8u);
      out[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
    }
    return out;
  }

  static std::array<uint8_t, 32> digest(std::span<const uint8_t> input)
  {
    Sha256 h;
    h.update(input);
    return h.finalize();
  }

private:
  void compress(const std::array<uint8_t, 64> & block)
  {
    static constexpr uint32_t k[64] = {
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
      0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
      0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
      0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
      0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
      0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
      0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
      0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
      0xc67178f2};
    uint32_t w[64]{};
    for (size_t i = 0; i < 16; ++i)
    {
      w[i] = (static_cast<uint32_t>(block[i * 4]) << 24u) |
             (static_cast<uint32_t>(block[i * 4 + 1]) << 16u) |
             (static_cast<uint32_t>(block[i * 4 + 2]) << 8u) |
             static_cast<uint32_t>(block[i * 4 + 3]);
    }
    for (size_t i = 16; i < 64; ++i)
    {
      const uint32_t s0 = std::rotr(w[i - 15], 7) ^ std::rotr(w[i - 15], 18) ^ (w[i - 15] >> 3u);
      const uint32_t s1 = std::rotr(w[i - 2], 17) ^ std::rotr(w[i - 2], 19) ^ (w[i - 2] >> 10u);
      w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    auto [a, b, c, d, e, f, g, h] = state_;
    for (size_t i = 0; i < 64; ++i)
    {
      const uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      const uint32_t ch = (e & f) ^ (~e & g);
      const uint32_t temp1 = h + s1 + ch + k[i] + w[i];
      const uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      const uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      const uint32_t temp2 = s0 + maj;
      h = g; g = f; f = e; e = d + temp1; d = c; c = b; b = a; a = temp1 + temp2;
    }
    state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
  }

  std::array<uint32_t, 8> state_{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                                 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  std::array<uint8_t, 64> buffer_{};
  size_t buffer_len_{};
  uint64_t len_bits_{};
};

std::array<uint8_t, 32> normalize_software_key(const uint8_t * key, size_t len)
{
  if (len == 32u)
  {
    std::array<uint8_t, 32> out{};
    std::copy_n(key, 32, out.data());
    return out;
  }
  return Sha256::digest(std::span<const uint8_t>(key, len));
}

std::array<uint8_t, 32> hmac_sha256(const std::array<uint8_t, 32> & key,
                                    std::initializer_list<std::span<const uint8_t>> chunks)
{
  std::array<uint8_t, 64> ipad{};
  std::array<uint8_t, 64> opad{};
  ipad.fill(0x36u);
  opad.fill(0x5cu);
  for (size_t i = 0; i < key.size(); ++i)
  {
    ipad[i] ^= key[i];
    opad[i] ^= key[i];
  }
  Sha256 inner;
  inner.update(ipad);
  for (const auto chunk: chunks)
  {
    inner.update(chunk);
  }
  const auto inner_hash = inner.finalize();
  Sha256 outer;
  outer.update(opad);
  outer.update(inner_hash);
  return outer.finalize();
}

bool constant_time_eq(std::span<const uint8_t> a, std::span<const uint8_t> b)
{
  if (a.size() != b.size())
  {
    return false;
  }
  uint8_t diff = 0;
  for (size_t i = 0; i < a.size(); ++i)
  {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}

std::array<uint8_t, 32> software_tag(const std::array<uint8_t, 32> & key, uint32_t key_id,
                                     std::span<const uint8_t> nonce, std::span<const uint8_t> aad,
                                     std::span<const uint8_t> ciphertext)
{
  const auto key_id_bytes = std::array<uint8_t, 4>{static_cast<uint8_t>(key_id),
                                                   static_cast<uint8_t>(key_id >> 8u),
                                                   static_cast<uint8_t>(key_id >> 16u),
                                                   static_cast<uint8_t>(key_id >> 24u)};
  return hmac_sha256(key, {std::span<const uint8_t>(reinterpret_cast<const uint8_t *>("SEDS-HMAC-TAG"), 13),
                           key_id_bytes, nonce, aad, ciphertext});
}

std::array<uint8_t, 32> managed_credential_tag(const std::array<uint8_t, 32> & key,
                                               std::span<const uint8_t> body)
{
  return hmac_sha256(key, {std::span<const uint8_t>(
                             reinterpret_cast<const uint8_t *>("SEDS-MASTER-CREDENTIAL"), 22),
                           body});
}

void apply_hmac_stream(const std::array<uint8_t, 32> & key, uint32_t key_id, std::span<const uint8_t> nonce,
                       std::span<const uint8_t> aad, std::span<const uint8_t> input, uint8_t * output)
{
  const auto key_id_bytes = std::array<uint8_t, 4>{static_cast<uint8_t>(key_id),
                                                   static_cast<uint8_t>(key_id >> 8u),
                                                   static_cast<uint8_t>(key_id >> 16u),
                                                   static_cast<uint8_t>(key_id >> 24u)};
  size_t offset = 0;
  uint64_t counter = 0;
  while (offset < input.size())
  {
    const auto counter_bytes = std::array<uint8_t, 8>{static_cast<uint8_t>(counter),
      static_cast<uint8_t>(counter >> 8u), static_cast<uint8_t>(counter >> 16u),
      static_cast<uint8_t>(counter >> 24u), static_cast<uint8_t>(counter >> 32u),
      static_cast<uint8_t>(counter >> 40u), static_cast<uint8_t>(counter >> 48u),
      static_cast<uint8_t>(counter >> 56u)};
    const auto block = hmac_sha256(key, {std::span<const uint8_t>(reinterpret_cast<const uint8_t *>("SEDS-HMAC-STREAM"), 16),
                                         key_id_bytes, nonce, aad, counter_bytes});
    const size_t take = std::min(block.size(), input.size() - offset);
    for (size_t i = 0; i < take; ++i)
    {
      output[offset + i] = input[offset + i] ^ block[i];
    }
    offset += take;
    ++counter;
  }
}

struct P2pDatagram
{
  std::string source_hostname;
  uint32_t source_address{};
  uint16_t source_port{};
  uint16_t destination_port{};
  std::span<const uint8_t> payload;
};

struct P2pStreamFrame
{
  uint8_t flags{};
  uint32_t source_stream_id{};
  uint32_t destination_stream_id{};
  uint32_t sequence{};
  std::span<const uint8_t> payload;
};

std::vector<uint8_t> encode_p2p_payload(std::string_view source_hostname, uint32_t source_address,
                                        uint16_t src_port, uint16_t dst_port,
                                        const uint8_t * payload, size_t payload_len)
{
  std::vector<uint8_t> out;
  out.reserve(15u + source_hostname.size() + payload_len);
  out.push_back(1);
  append_le<uint16_t>(out, dst_port);
  append_le<uint16_t>(out, src_port);
  append_le<uint32_t>(out, source_address);
  append_le<uint16_t>(out, static_cast<uint16_t>(source_hostname.size()));
  append_le<uint32_t>(out, static_cast<uint32_t>(payload_len));
  out.insert(out.end(), source_hostname.begin(), source_hostname.end());
  if (payload_len != 0)
  {
    out.insert(out.end(), payload, payload + payload_len);
  }
  return out;
}

std::optional<P2pDatagram> decode_p2p_payload(const std::vector<uint8_t> & payload)
{
  if (payload.size() < 15u || payload[0] != 1u)
  {
    return std::nullopt;
  }
  const uint16_t dst_port = read_u16_le(payload.data() + 1);
  const uint16_t src_port = read_u16_le(payload.data() + 3);
  const uint32_t src_address = read_u32_le(payload.data() + 5);
  const size_t host_len = read_u16_le(payload.data() + 9);
  const size_t body_len = read_u32_le(payload.data() + 11);
  const size_t host_start = 15u;
  const size_t host_end = host_start + host_len;
  const size_t body_end = host_end + body_len;
  if (host_end > payload.size() || body_end != payload.size())
  {
    return std::nullopt;
  }
  P2pDatagram out;
  out.destination_port = dst_port;
  out.source_port = src_port;
  out.source_address = src_address;
  out.source_hostname.assign(reinterpret_cast<const char *>(payload.data() + host_start), host_len);
  out.payload = std::span<const uint8_t>(payload.data() + host_end, body_len);
  return out;
}

std::vector<uint8_t> encode_p2p_stream_payload(uint8_t flags, uint32_t source_stream_id,
                                               uint32_t destination_stream_id, uint32_t sequence,
                                               const uint8_t * payload, size_t payload_len)
{
  std::vector<uint8_t> out;
  out.reserve(22u + payload_len);
  out.insert(out.end(), std::begin(kP2pStreamMagic), std::end(kP2pStreamMagic));
  out.push_back(kP2pStreamVersion);
  out.push_back(flags);
  append_le<uint32_t>(out, source_stream_id);
  append_le<uint32_t>(out, destination_stream_id);
  append_le<uint32_t>(out, sequence);
  append_le<uint32_t>(out, static_cast<uint32_t>(payload_len));
  if (payload_len != 0)
  {
    out.insert(out.end(), payload, payload + payload_len);
  }
  return out;
}

std::optional<P2pStreamFrame> decode_p2p_stream_payload(std::span<const uint8_t> payload)
{
  if (payload.size() < sizeof(kP2pStreamMagic) ||
      !std::equal(std::begin(kP2pStreamMagic), std::end(kP2pStreamMagic), payload.begin()))
  {
    return std::nullopt;
  }
  if (payload.size() < 22u || payload[4] != kP2pStreamVersion)
  {
    return P2pStreamFrame{};
  }
  const size_t body_len = read_u32_le(payload.data() + 18);
  if (22u + body_len != payload.size())
  {
    return P2pStreamFrame{};
  }
  return P2pStreamFrame{payload[5], read_u32_le(payload.data() + 6), read_u32_le(payload.data() + 10),
                        read_u32_le(payload.data() + 14),
                        std::span<const uint8_t>(payload.data() + 22, body_len)};
}

uint8_t message_data_type_code(const seds::ElementDataType type)
{
  return static_cast<uint8_t>(type);
}

uint8_t message_class_code(const seds::MessageClass klass)
{
  return static_cast<uint8_t>(klass);
}

uint8_t reliable_code(const seds::ReliableMode mode)
{
  return static_cast<uint8_t>(mode);
}

SedsResult copy_json(std::string_view json, char * buf, size_t buf_len)
{
  return static_cast<SedsResult>(seds::copy_text(json, buf, buf_len));
}

void json_push_escaped(std::string & out, std::string_view value)
{
  out.push_back('"');
  for (const unsigned char ch: value)
  {
    switch (ch)
    {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (ch < 0x20u)
        {
          std::ostringstream os;
          os << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(ch);
          out += os.str();
        }
        else
        {
          out.push_back(static_cast<char>(ch));
        }
    }
  }
  out.push_back('"');
}

template<typename T>
void json_push_number_array(std::string & out, const std::vector<T> & vals)
{
  out.push_back('[');
  for (size_t i = 0; i < vals.size(); ++i)
  {
    if (i != 0)
    {
      out.push_back(',');
    }
    out += std::to_string(vals[i]);
  }
  out.push_back(']');
}

void json_push_string_array(std::string & out, const std::vector<std::string> & vals)
{
  out.push_back('[');
  for (size_t i = 0; i < vals.size(); ++i)
  {
    if (i != 0)
    {
      out.push_back(',');
    }
    json_push_escaped(out, vals[i]);
  }
  out.push_back(']');
}

bool is_stats_control_endpoint(uint32_t endpoint)
{
  return endpoint == SEDS_EP_DISCOVERY || endpoint == SEDS_EP_TIME_SYNC || endpoint == SEDS_EP_TELEMETRY_ERROR;
}

std::string endpoint_stats_name(uint32_t endpoint)
{
  if (endpoint < seds::kEndpointNames.size() && seds::kEndpointNames[endpoint] != nullptr)
  {
    return seds::kEndpointNames[endpoint];
  }
  return "endpoint_" + std::to_string(endpoint);
}

template<typename OwnerT>
std::string client_stats_json(OwnerT & owner, std::string_view sender)
{
  const uint64_t now = owner.now_ms();
  std::vector<size_t> side_ids;
  std::vector<std::string> side_names;
  std::vector<uint32_t> endpoints;
  std::vector<std::string> endpoint_names;
  std::vector<std::string> timesync_sources;
  std::optional<uint64_t> last_seen_ms;
  {
    std::scoped_lock lock(owner.mu);
    for (const auto & [side_id, route]: owner.discovery_routes)
    {
      const auto sender_it = route.announcers.find(std::string(sender));
      if (sender_it == route.announcers.end())
      {
        continue;
      }
      side_ids.push_back(static_cast<size_t>(side_id));
      if (side_id >= 0 && static_cast<size_t>(side_id) < owner.sides.size())
      {
        side_names.push_back(owner.sides[side_id].name);
      }
      last_seen_ms = std::max<uint64_t>(last_seen_ms.value_or(0), sender_it->second.last_seen_ms);
      endpoints.insert(endpoints.end(), sender_it->second.endpoints.begin(), sender_it->second.endpoints.end());
      timesync_sources.insert(timesync_sources.end(), sender_it->second.timesync_sources.begin(),
                              sender_it->second.timesync_sources.end());
    }
  }
  if (side_ids.empty())
  {
    return "null";
  }
  endpoints.erase(std::remove_if(endpoints.begin(), endpoints.end(), is_stats_control_endpoint), endpoints.end());
  std::ranges::sort(side_ids);
  side_ids.erase(std::ranges::unique(side_ids).begin(), side_ids.end());
  seds::sort_dedup_strings(side_names);
  std::ranges::sort(endpoints);
  endpoints.erase(std::ranges::unique(endpoints).begin(), endpoints.end());
  for (const uint32_t endpoint: endpoints)
  {
    endpoint_names.push_back(endpoint_stats_name(endpoint));
  }
  seds::sort_dedup_strings(timesync_sources);
  const uint64_t age_ms = last_seen_ms ? now - *last_seen_ms : 0;

  std::string out;
  out.reserve(256);
  out += "{\"sender_id\":";
  json_push_escaped(out, sender);
  out += ",\"connected\":";
  out += age_ms <= seds::kDiscoveryTtlMs ? "true" : "false";
  out += ",\"side_ids\":";
  json_push_number_array(out, side_ids);
  out += ",\"side_names\":";
  json_push_string_array(out, side_names);
  out += ",\"last_seen_ms\":";
  out += last_seen_ms ? std::to_string(*last_seen_ms) : "null";
  out += ",\"age_ms\":";
  out += last_seen_ms ? std::to_string(age_ms) : "null";
  out += ",\"reachable_endpoints\":";
  json_push_string_array(out, endpoint_names);
  out += ",\"reachable_endpoint_ids\":";
  json_push_number_array(out, endpoints);
  out += ",\"reachable_timesync_sources\":";
  json_push_string_array(out, timesync_sources);
  out += ",\"packets_sent\":0,\"packets_received\":0,\"bytes_sent\":0,\"bytes_received\":0}";
  return out;
}

template<typename OwnerT>
std::string runtime_stats_json(OwnerT & owner)
{
  std::scoped_lock lock(owner.mu);
  std::string out;
  out.push_back('{');
  out += "\"sides\":[";
  for (size_t i = 0; i < owner.sides.size(); ++i)
  {
    const auto & side = owner.sides[i];
    if (i != 0)
    {
      out.push_back(',');
    }
    out += "{\"side_id\":";
    out += std::to_string(i);
    out += ",\"side_name\":";
    json_push_escaped(out, side.name);
    out += ",\"reliable_enabled\":";
    out += side.reliable_enabled ? "true" : "false";
    out += ",\"link_local_enabled\":";
    out += side.link_local_enabled ? "true" : "false";
    out += ",\"header_template_enabled\":";
    out += side.header_template_enabled ? "true" : "false";
    out += ",\"max_frame_bytes\":";
    out += std::to_string(side.max_frame_bytes);
    out += ",\"compact_header_target_bytes\":";
    out += std::to_string(side.compact_header_target_bytes);
    out += ",\"max_side_transport_templates\":";
    out += std::to_string(side.max_side_transport_templates);
    out += ",\"side_transport_profile\":";
    json_push_escaped(out, side_transport_profile_name(side.side_transport_profile));
    out += ",\"ingress_enabled\":";
    out += side.ingress_enabled ? "true" : "false";
    out += ",\"egress_enabled\":";
    out += side.egress_enabled ? "true" : "false";
    out += ",\"tx_packets\":0,\"tx_bytes\":0,\"rx_packets\":0,\"rx_bytes\":0";
    out += ",\"relayed_tx_packets\":0,\"relayed_tx_bytes\":0,\"relayed_rx_packets\":0,\"relayed_rx_bytes\":0";
    out += ",\"local_delivery_packets\":0,\"tx_retries\":0,\"tx_handler_failures\":0,\"local_handler_failures\":0";
    out += ",\"total_handler_retries\":0,\"side_transport_full_frames\":0,\"side_transport_compact_frames\":0";
    out += ",\"side_transport_compact_delta_frames\":0,\"side_transport_compact_omitted_timestamp_frames\":0";
    out += ",\"side_transport_chunk_frames\":0,\"side_transport_raw_bytes\":0,\"side_transport_wire_bytes\":0";
    out += ",\"side_transport_bytes_saved\":0,\"side_transport_compact_target_misses\":0";
    out += ",\"side_transport_template_evictions\":0,\"side_transport_tx_template_count\":0";
    out += ",\"side_transport_rx_template_count\":0,\"side_transport_min_compact_overhead_bytes\":null";
    out += ",\"side_transport_max_compact_overhead_bytes\":null";
    out += ",\"adaptive\":{\"auto_balancing_enabled\":false,\"estimated_capacity_bps\":0,\"peak_capacity_bps\":0";
    out += ",\"current_usage_bps\":0,\"peak_usage_bps\":0,\"available_headroom_bps\":0,\"effective_weight\":1";
    out += ",\"last_observed_ms\":0,\"sample_count\":0},\"data_types\":[]}";
  }
  out += "],\"route_modes\":[";
  bool first = true;
  const auto push_route_mode = [&](std::optional<int32_t> src_side, const seds::RoutePolicy & policy)
  {
    if (!first)
    {
      out.push_back(',');
    }
    first = false;
    out += "{\"src_side_id\":";
    out += src_side ? std::to_string(*src_side) : "null";
    out += ",\"selection_mode\":";
    json_push_escaped(out, route_mode_name(policy.mode));
    out += ",\"cursor\":";
    out += std::to_string(policy.rr_counter);
    out.push_back('}');
  };
  if (owner.local_policy.mode != Seds_RSM_Fanout || !owner.local_policy.weights.empty() ||
      !owner.local_policy.priorities.empty())
  {
    push_route_mode(std::nullopt, owner.local_policy);
  }
  for (const auto & [src_side, policy]: owner.source_policy)
  {
    push_route_mode(src_side, policy);
  }
  out += "],\"route_overrides\":[";
  first = true;
  for (const auto & [key, enabled]: owner.route_overrides)
  {
    if (!first)
    {
      out.push_back(',');
    }
    first = false;
    out += "{\"src_side_id\":";
    out += key.src_side >= 0 ? std::to_string(key.src_side) : "null";
    out += ",\"dst_side_id\":";
    out += std::to_string(key.dst_side);
    out += ",\"enabled\":";
    out += enabled ? "true" : "false";
    out.push_back('}');
  }
  out += "],\"typed_route_overrides\":[";
  first = true;
  for (const auto & [key, enabled]: owner.typed_route_overrides)
  {
    if (!first)
    {
      out.push_back(',');
    }
    first = false;
    out += "{\"src_side_id\":";
    out += key.src_side >= 0 ? std::to_string(key.src_side) : "null";
    out += ",\"data_type\":";
    out += std::to_string(seds::wire_type_id(key.ty));
    out += ",\"dst_side_id\":";
    out += std::to_string(key.dst_side);
    out += ",\"enabled\":";
    out += enabled ? "true" : "false";
    out.push_back('}');
  }
  const auto push_route_policy_values = [&](std::string_view field_name, bool priorities)
  {
    out += ",\"";
    out += field_name;
    out += "\":[";
    bool first_value = true;
    const auto push_one_policy = [&](std::optional<int32_t> src_side, const seds::RoutePolicy & policy)
    {
      const auto & values = priorities ? policy.priorities : policy.weights;
      for (const auto & [dst_side, value]: values)
      {
        if (!first_value)
        {
          out.push_back(',');
        }
        first_value = false;
        out += "{\"src_side_id\":";
        out += src_side ? std::to_string(*src_side) : "null";
        out += ",\"dst_side_id\":";
        out += std::to_string(dst_side);
        out += priorities ? ",\"priority\":" : ",\"weight\":";
        out += std::to_string(value);
        out.push_back('}');
      }
    };
    push_one_policy(std::nullopt, owner.local_policy);
    for (const auto & [src_side, policy]: owner.source_policy)
    {
      push_one_policy(src_side, policy);
    }
    out.push_back(']');
  };
  push_route_policy_values("route_weights", false);
  push_route_policy_values("route_priorities", true);
  out += ",\"queues\":{\"rx_len\":";
  out += std::to_string(owner.rx_queue.size());
  out += ",\"rx_bytes\":";
  out += std::to_string(owner.rx_queue_bytes);
  out += ",\"tx_len\":";
  out += std::to_string(owner.tx_queue.size());
  out += ",\"tx_bytes\":";
  out += std::to_string(owner.tx_queue_bytes);
  out += ",\"replay_len\":";
  out += std::to_string(owner.reliable_released_rx.size());
  out += ",\"replay_bytes\":0,\"recent_rx_len\":";
  out += std::to_string(owner.recent_ids.size());
  out += ",\"recent_rx_bytes\":";
  out += std::to_string(owner.recent_ids.size() * sizeof(uint64_t));
  out += ",\"reliable_rx_buffered_len\":0,\"reliable_rx_buffered_bytes\":0,\"shared_queue_bytes_used\":";
  out += std::to_string(owner.rx_queue_bytes + owner.tx_queue_bytes);
  out += "},\"reliable\":{\"reliable_return_route_count\":";
  out += std::to_string(owner.reliable_return_routes.size());
  out += ",\"end_to_end_pending_count\":0,\"end_to_end_pending_destination_count\":0,\"end_to_end_acked_cache_count\":0}";
  out += ",\"discovery\":{\"route_count\":";
  out += std::to_string(owner.discovery_routes.size());
  size_t announcer_count = 0;
  for (const auto & [_, route]: owner.discovery_routes)
  {
    announcer_count += route.announcers.size();
  }
  out += ",\"announcer_count\":";
  out += std::to_string(announcer_count);
  out += ",\"current_announce_interval_ms\":";
  out += std::to_string(owner.discovery_interval_ms);
  out += ",\"next_announce_ms\":";
  out += std::to_string(owner.discovery_next_ms);
  out += "},\"total_handler_failures\":0,\"total_handler_retries\":0}";
  return out;
}

template<typename OwnerT>
std::string memory_layout_json(OwnerT & owner, std::string_view kind)
{
  std::scoped_lock lock(owner.mu);
  std::string out;
  out += "{\"kind\":";
  json_push_escaped(out, kind);
  out += ",\"side_count\":";
  out += std::to_string(owner.sides.size());
  out += ",\"shared_queue_bytes_allocated\":";
  out += std::to_string(owner.memory.max_queue_budget);
  out += ",\"shared_queue_bytes_used\":";
  out += std::to_string(owner.rx_queue_bytes + owner.tx_queue_bytes);
  out += ",\"rx_queue_len\":";
  out += std::to_string(owner.rx_queue.size());
  out += ",\"rx_queue_bytes_used\":";
  out += std::to_string(owner.rx_queue_bytes);
  out += ",\"rx_queue_bytes_allocated\":";
  out += std::to_string(owner.memory.max_queue_budget);
  out += ",\"tx_queue_len\":";
  out += std::to_string(owner.tx_queue.size());
  out += ",\"tx_queue_bytes_used\":";
  out += std::to_string(owner.tx_queue_bytes);
  out += ",\"tx_queue_bytes_allocated\":";
  out += std::to_string(owner.memory.max_queue_budget);
  out += ",\"replay_queue_len\":";
  out += std::to_string(owner.reliable_released_rx.size());
  out += ",\"replay_queue_bytes_used\":0,\"replay_queue_bytes_allocated\":";
  out += std::to_string(owner.memory.max_queue_budget);
  out += ",\"recent_rx_len\":";
  out += std::to_string(owner.recent_ids.size());
  out += ",\"recent_rx_bytes_used\":";
  out += std::to_string(owner.recent_ids.size() * sizeof(uint64_t));
  out += ",\"recent_rx_bytes_allocated\":";
  out += std::to_string(seds::recent_rx_queue_bytes(owner.memory));
  out += ",\"reliable_return_route_count\":";
  out += std::to_string(owner.reliable_return_routes.size());
  out += ",\"network_variable_cache_bytes_used\":0}";
  return out;
}

std::string_view sv_from(const char * ptr, size_t len)
{
  return ptr == nullptr ? std::string_view{} : std::string_view(ptr, len);
}

seds::ElementDataType element_type_from_code(uint8_t code)
{
  if (code <= static_cast<uint8_t>(seds::ElementDataType::Binary))
  {
    return static_cast<seds::ElementDataType>(code);
  }
  return seds::ElementDataType::UInt8;
}

seds::MessageClass message_class_from_code(uint8_t code)
{
  if (code <= static_cast<uint8_t>(seds::MessageClass::Warning))
  {
    return static_cast<seds::MessageClass>(code);
  }
  return seds::MessageClass::Data;
}

seds::ReliableMode reliable_from_code(uint8_t code)
{
  if (code <= static_cast<uint8_t>(seds::ReliableMode::Unordered))
  {
    return static_cast<seds::ReliableMode>(code);
  }
  return seds::ReliableMode::None;
}

size_t elem_size_from_type(seds::ElementDataType type)
{
  switch (type)
  {
    case seds::ElementDataType::Bool:
    case seds::ElementDataType::UInt8:
    case seds::ElementDataType::Int8:
    case seds::ElementDataType::String:
    case seds::ElementDataType::Binary:
      return 1;
    case seds::ElementDataType::UInt16:
    case seds::ElementDataType::Int16:
      return 2;
    case seds::ElementDataType::UInt32:
    case seds::ElementDataType::Int32:
    case seds::ElementDataType::Float32:
      return 4;
    case seds::ElementDataType::UInt64:
    case seds::ElementDataType::Int64:
    case seds::ElementDataType::Float64:
      return 8;
    case seds::ElementDataType::UInt128:
    case seds::ElementDataType::Int128:
      return 16;
    case seds::ElementDataType::NoData:
    default:
      return 0;
  }
}

std::string unescape_json_string(std::string_view value)
{
  std::string out;
  out.reserve(value.size());
  for (size_t i = 0; i < value.size(); ++i)
  {
    if (value[i] == '\\' && i + 1 < value.size())
    {
      ++i;
      switch (value[i])
      {
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        default: out.push_back(value[i]); break;
      }
    }
    else
    {
      out.push_back(value[i]);
    }
  }
  return out;
}

std::optional<std::string> json_string_value(std::string_view obj, std::string_view key)
{
  const std::string needle = "\"" + std::string(key) + "\"";
  size_t pos = obj.find(needle);
  if (pos == std::string_view::npos)
  {
    return std::nullopt;
  }
  pos = obj.find(':', pos + needle.size());
  if (pos == std::string_view::npos)
  {
    return std::nullopt;
  }
  pos = obj.find('"', pos + 1);
  if (pos == std::string_view::npos)
  {
    return std::nullopt;
  }
  const size_t start = pos + 1;
  bool escaped = false;
  for (size_t i = start; i < obj.size(); ++i)
  {
    if (escaped)
    {
      escaped = false;
      continue;
    }
    if (obj[i] == '\\')
    {
      escaped = true;
      continue;
    }
    if (obj[i] == '"')
    {
      return unescape_json_string(obj.substr(start, i - start));
    }
  }
  return std::nullopt;
}

std::optional<size_t> json_size_value(std::string_view obj, std::string_view key)
{
  const std::string needle = "\"" + std::string(key) + "\"";
  size_t pos = obj.find(needle);
  if (pos == std::string_view::npos)
  {
    return std::nullopt;
  }
  pos = obj.find(':', pos + needle.size());
  if (pos == std::string_view::npos)
  {
    return std::nullopt;
  }
  ++pos;
  while (pos < obj.size() && std::isspace(static_cast<unsigned char>(obj[pos])))
  {
    ++pos;
  }
  size_t end = pos;
  while (end < obj.size() && std::isdigit(static_cast<unsigned char>(obj[end])))
  {
    ++end;
  }
  if (end == pos)
  {
    return std::nullopt;
  }
  return static_cast<size_t>(std::stoull(std::string(obj.substr(pos, end - pos))));
}

std::optional<bool> json_bool_value(std::string_view obj, std::string_view key)
{
  const std::string needle = "\"" + std::string(key) + "\"";
  size_t pos = obj.find(needle);
  if (pos == std::string_view::npos)
  {
    return std::nullopt;
  }
  pos = obj.find(':', pos + needle.size());
  if (pos == std::string_view::npos)
  {
    return std::nullopt;
  }
  ++pos;
  while (pos < obj.size() && std::isspace(static_cast<unsigned char>(obj[pos])))
  {
    ++pos;
  }
  if (obj.substr(pos, 4) == "true")
  {
    return true;
  }
  if (obj.substr(pos, 5) == "false")
  {
    return false;
  }
  return std::nullopt;
}

std::optional<std::string_view> json_array_value(std::string_view obj, std::string_view key)
{
  const std::string needle = "\"" + std::string(key) + "\"";
  size_t pos = obj.find(needle);
  if (pos == std::string_view::npos)
  {
    return std::nullopt;
  }
  pos = obj.find('[', pos + needle.size());
  if (pos == std::string_view::npos)
  {
    return std::nullopt;
  }
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  for (size_t i = pos; i < obj.size(); ++i)
  {
    const char ch = obj[i];
    if (in_string)
    {
      if (escaped)
      {
        escaped = false;
      }
      else if (ch == '\\')
      {
        escaped = true;
      }
      else if (ch == '"')
      {
        in_string = false;
      }
      continue;
    }
    if (ch == '"')
    {
      in_string = true;
    }
    else if (ch == '[')
    {
      ++depth;
    }
    else if (ch == ']')
    {
      --depth;
      if (depth == 0)
      {
        return obj.substr(pos + 1, i - pos - 1);
      }
    }
  }
  return std::nullopt;
}

std::vector<std::string_view> split_top_level_objects(std::string_view array)
{
  std::vector<std::string_view> out;
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  size_t start = std::string_view::npos;
  for (size_t i = 0; i < array.size(); ++i)
  {
    const char ch = array[i];
    if (in_string)
    {
      if (escaped)
        escaped = false;
      else if (ch == '\\')
        escaped = true;
      else if (ch == '"')
        in_string = false;
      continue;
    }
    if (ch == '"')
      in_string = true;
    else if (ch == '{')
    {
      if (depth == 0)
        start = i;
      ++depth;
    }
    else if (ch == '}')
    {
      --depth;
      if (depth == 0 && start != std::string_view::npos)
      {
        out.push_back(array.substr(start, i - start + 1));
        start = std::string_view::npos;
      }
    }
  }
  return out;
}

std::vector<std::string> split_string_array(std::string_view array)
{
  std::vector<std::string> out;
  size_t pos = 0;
  while ((pos = array.find('"', pos)) != std::string_view::npos)
  {
    const size_t start = pos + 1;
    bool escaped = false;
    for (size_t i = start; i < array.size(); ++i)
    {
      if (escaped)
      {
        escaped = false;
        continue;
      }
      if (array[i] == '\\')
      {
        escaped = true;
        continue;
      }
      if (array[i] == '"')
      {
        out.push_back(unescape_json_string(array.substr(start, i - start)));
        pos = i + 1;
        break;
      }
    }
  }
  return out;
}

uint8_t element_code_from_name(const std::string & name)
{
  if (name == "NoData") return static_cast<uint8_t>(seds::ElementDataType::NoData);
  if (name == "Bool") return static_cast<uint8_t>(seds::ElementDataType::Bool);
  if (name == "UInt8") return static_cast<uint8_t>(seds::ElementDataType::UInt8);
  if (name == "UInt16") return static_cast<uint8_t>(seds::ElementDataType::UInt16);
  if (name == "UInt32") return static_cast<uint8_t>(seds::ElementDataType::UInt32);
  if (name == "UInt64") return static_cast<uint8_t>(seds::ElementDataType::UInt64);
  if (name == "Int8") return static_cast<uint8_t>(seds::ElementDataType::Int8);
  if (name == "Int16") return static_cast<uint8_t>(seds::ElementDataType::Int16);
  if (name == "Int32") return static_cast<uint8_t>(seds::ElementDataType::Int32);
  if (name == "Int64") return static_cast<uint8_t>(seds::ElementDataType::Int64);
  if (name == "Float32") return static_cast<uint8_t>(seds::ElementDataType::Float32);
  if (name == "Float64") return static_cast<uint8_t>(seds::ElementDataType::Float64);
  if (name == "String") return static_cast<uint8_t>(seds::ElementDataType::String);
  if (name == "Binary") return static_cast<uint8_t>(seds::ElementDataType::Binary);
  return static_cast<uint8_t>(seds::ElementDataType::UInt8);
}

uint8_t reliable_code_from_name(const std::string & name)
{
  if (name == "Ordered") return static_cast<uint8_t>(seds::ReliableMode::Ordered);
  if (name == "Unordered") return static_cast<uint8_t>(seds::ReliableMode::Unordered);
  return static_cast<uint8_t>(seds::ReliableMode::None);
}

uint8_t message_class_code_from_name(const std::string & name)
{
  if (name == "Error") return static_cast<uint8_t>(seds::MessageClass::Error);
  if (name == "Warning") return static_cast<uint8_t>(seds::MessageClass::Warning);
  return static_cast<uint8_t>(seds::MessageClass::Data);
}

SedsResult register_schema_json_text(std::string_view json)
{
  const auto endpoint_array = json_array_value(json, "endpoints");
  const auto type_array = json_array_value(json, "types");
  if (!endpoint_array || !type_array)
  {
    return SEDS_DESERIALIZE;
  }
  std::map<std::string, uint32_t> endpoint_ids;
  uint32_t next_endpoint = 100;
  while (next_endpoint < seds::kEndpointNames.size() && seds::kEndpointNames[next_endpoint] != nullptr)
  {
    ++next_endpoint;
  }
  for (const auto ep_obj: split_top_level_objects(*endpoint_array))
  {
    const auto rust = json_string_value(ep_obj, "rust");
    const auto name = json_string_value(ep_obj, "name");
    if (!rust || !name)
    {
      return SEDS_DESERIALIZE;
    }
    auto description = json_string_value(ep_obj, "description");
    if (!description)
    {
      description = json_string_value(ep_obj, "doc");
    }
    const std::string description_value = description.value_or("");
    const bool link_local_only = json_bool_value(ep_obj, "link_local_only").value_or(false) ||
                                 json_string_value(ep_obj, "broadcast_mode").value_or("") == "Never";
    const uint32_t id = next_endpoint++;
    while (next_endpoint < seds::kEndpointNames.size() && seds::kEndpointNames[next_endpoint] != nullptr)
    {
      ++next_endpoint;
    }
    const auto rc = seds_endpoint_register_ex(id, name->c_str(), name->size(), description_value.c_str(),
                                              description_value.size(), link_local_only);
    if (rc != SEDS_OK)
    {
      return rc;
    }
    endpoint_ids[*rust] = id;
  }

  uint32_t next_type = 100;
  while (next_type < seds::kTypeInfo.size() && seds::kTypeInfo[next_type].name != nullptr &&
         seds::kTypeInfo[next_type].name[0] != '\0')
  {
    ++next_type;
  }
  for (const auto ty_obj: split_top_level_objects(*type_array))
  {
    const auto name = json_string_value(ty_obj, "name");
    if (!name)
    {
      return SEDS_DESERIALIZE;
    }
    const auto kind = json_string_value(ty_obj, "kind").value_or("Static");
    const auto data_type = json_string_value(ty_obj, "data_type").value_or("UInt8");
    const auto reliable = json_string_value(ty_obj, "reliable_mode").value_or("None");
    auto description = json_string_value(ty_obj, "description");
    if (!description)
    {
      description = json_string_value(ty_obj, "doc");
    }
    const std::string description_value = description.value_or("");
    const uint8_t reliable_code = json_bool_value(ty_obj, "reliable").value_or(false)
                                      ? static_cast<uint8_t>(seds::ReliableMode::Ordered)
                                      : reliable_code_from_name(reliable);
    const uint8_t priority = static_cast<uint8_t>(json_size_value(ty_obj, "priority").value_or(0) & 0xffu);
    const uint8_t klass = message_class_code_from_name(json_string_value(ty_obj, "class").value_or("Data"));
    const auto endpoint_names_array = json_array_value(ty_obj, "endpoints");
    if (!endpoint_names_array)
    {
      return SEDS_DESERIALIZE;
    }
    std::vector<uint32_t> endpoints;
    for (const auto & endpoint_name: split_string_array(*endpoint_names_array))
    {
      const auto it = endpoint_ids.find(endpoint_name);
      if (it != endpoint_ids.end())
      {
        endpoints.push_back(it->second);
      }
    }
    if (endpoints.empty())
    {
      return SEDS_BAD_ARG;
    }
    const bool is_static = kind != "Dynamic";
    const size_t count = is_static ? json_size_value(ty_obj, "count").value_or(0) : 0;
    const uint32_t id = next_type++;
    while (next_type < seds::kTypeInfo.size() && seds::kTypeInfo[next_type].name != nullptr &&
           seds::kTypeInfo[next_type].name[0] != '\0')
    {
      ++next_type;
    }
    const auto rc = seds_dtype_register_ex(id, name->c_str(), name->size(), description_value.c_str(),
                                           description_value.size(), is_static, count,
                                           element_code_from_name(data_type), klass, reliable_code, priority,
                                           endpoints.data(), endpoints.size());
    if (rc != SEDS_OK)
    {
      return rc;
    }
  }
  return SEDS_OK;
}

std::optional<seds::PacketData> unpack_managed_packet(const uint8_t * bytes, size_t len)
{
  if (bytes == nullptr && len != 0)
  {
    return std::nullopt;
  }
  return seds::deserialize_packet(bytes, len);
}

SedsResult remember_managed_packet(SedsRouter & r, seds::PacketData pkt, bool invoke_callback)
{
  if (!seds::valid_type(pkt.ty))
  {
    return SEDS_INVALID_TYPE;
  }
  auto & policy = r.managed_variable_policy[pkt.ty];
  policy.enabled = true;
  auto packed = seds::serialize_packet(pkt);
  const uint64_t now = r.now_ms();
  auto view_pkt = pkt;
  r.managed_variable_latest[pkt.ty] =
      seds::ManagedVariableEntry{std::move(pkt), std::move(packed), now};
  if (invoke_callback)
  {
    if (const auto cb_it = r.managed_variable_callbacks.find(view_pkt.ty);
        cb_it != r.managed_variable_callbacks.end() && cb_it->second.cb != nullptr)
    {
      SedsPacketView view{};
      seds::fill_view(view_pkt, view);
      (void)cb_it->second.cb(&view, cb_it->second.user);
    }
  }
  return SEDS_OK;
}

SedsResult queue_managed_request(SedsRouter & r, uint32_t ty)
{
  if (!seds::valid_type(ty))
  {
    return SEDS_INVALID_TYPE;
  }
  std::vector<uint8_t> payload;
  const uint32_t wire_ty = seds::wire_type_id(ty);
  payload.insert(payload.end(), reinterpret_cast<const uint8_t *>(&wire_ty),
                 reinterpret_cast<const uint8_t *>(&wire_ty) + sizeof(wire_ty));
  const uint32_t request_ty = seds::local_type_from_wire_id(13).value_or(1013u);
  auto pkt = seds::make_internal_packet(request_ty, r.current_network_ms(), std::move(payload));
  pkt.sender = r.sender;
  seds::enqueue_tx(r.tx_queue, r.tx_queue_bytes, {std::move(pkt), std::nullopt, std::nullopt, false},
                   r.memory.max_queue_budget);
  return SEDS_OK;
}

int32_t copy_managed_entry(const seds::ManagedVariableEntry & entry, uint8_t * out, size_t out_len)
{
  if (out == nullptr)
  {
    return static_cast<int32_t>(entry.packed.size());
  }
  if (out_len < entry.packed.size())
  {
    return SEDS_SIZE_MISMATCH;
  }
  std::memcpy(out, entry.packed.data(), entry.packed.size());
  return static_cast<int32_t>(entry.packed.size());
}

SedsResult enqueue_p2p_packet(SedsRouter & r, uint16_t dst_port, uint16_t src_port,
                              const uint8_t * payload, size_t payload_len)
{
  if (dst_port == 0)
  {
    return SEDS_BAD_ARG;
  }
  const auto p2p_payload = encode_p2p_payload(r.sender, local_p2p_address(r), src_port, dst_port, payload, payload_len);
  auto pkt = seds::make_internal_packet(p2p_type_id(), r.current_network_ms(), p2p_payload);
  pkt.sender = r.sender;
  seds::enqueue_tx(r.tx_queue, r.tx_queue_bytes, {std::move(pkt), std::nullopt, std::nullopt, false},
                   r.memory.max_queue_budget);
  return SEDS_OK;
}

std::optional<std::pair<std::string, uint32_t>> resolve_p2p_host(SedsRouter & r, std::string_view hostname)
{
  if (hostname == r.sender)
  {
    return std::make_pair(r.sender, local_p2p_address(r));
  }
  const auto it = r.p2p_address_book.find(std::string(hostname));
  if (it == r.p2p_address_book.end())
  {
    return std::nullopt;
  }
  return std::make_pair(it->first, it->second);
}

std::optional<std::pair<std::string, uint32_t>> resolve_p2p_address(SedsRouter & r, uint32_t address)
{
  if (address == local_p2p_address(r))
  {
    return std::make_pair(r.sender, address);
  }
  const auto it = r.p2p_host_by_address.find(address);
  if (it == r.p2p_host_by_address.end())
  {
    return std::nullopt;
  }
  return std::make_pair(it->second, address);
}

uint32_t allocate_p2p_stream_id(SedsRouter & r)
{
  for (uint32_t tries = 0; tries < UINT32_MAX; ++tries)
  {
    const uint32_t id = std::max<uint32_t>(1u, r.p2p_next_stream_id);
    r.p2p_next_stream_id = std::max<uint32_t>(1u, r.p2p_next_stream_id + 1u);
    if (!r.p2p_stream_sessions.contains(id))
    {
      return id;
    }
  }
  return 0;
}

SedsResult send_p2p_stream_control(SedsRouter & r, uint32_t stream_id, uint8_t flags,
                                   const uint8_t * payload, size_t payload_len);

SedsResult dispatch_p2p_stream(SedsRouter & r, const P2pDatagram & msg, const P2pStreamFrame & frame)
{
  if (frame.flags == 0)
  {
    return SEDS_DESERIALIZE;
  }
  if ((frame.flags & kP2pStreamSyn) != 0u && (frame.flags & kP2pStreamAck) == 0u)
  {
    uint32_t local_id = 0;
    for (const auto & [id, session]: r.p2p_stream_sessions)
    {
      if (session.peer_stream_id == frame.source_stream_id && session.local_port == msg.destination_port &&
          session.peer_port == msg.source_port && session.peer_address == msg.source_address &&
          session.peer_hostname == msg.source_hostname)
      {
        local_id = id;
        break;
      }
    }
    if (local_id == 0)
    {
      local_id = allocate_p2p_stream_id(r);
      if (local_id == 0)
      {
        return SEDS_IO;
      }
      r.p2p_stream_sessions[local_id] =
          seds::P2pStreamSession{msg.source_hostname, msg.source_address, msg.destination_port,
                                 msg.source_port, frame.source_stream_id, 1, true};
      const auto handlers = r.p2p_stream_handlers[msg.destination_port];
      for (const auto & handler: handlers)
      {
        if (handler.cb != nullptr)
        {
          const SedsP2pStreamEventView view{1, local_id, frame.source_stream_id, frame.sequence,
                                            msg.source_hostname.c_str(), msg.source_hostname.size(),
                                            msg.source_address, msg.destination_port, msg.source_port,
                                            frame.payload.data(), frame.payload.size()};
          if (handler.cb(&view, handler.user) != SEDS_OK)
          {
            return SEDS_HANDLER_ERROR;
          }
        }
      }
    }
    const auto reply = encode_p2p_stream_payload(kP2pStreamSyn | kP2pStreamAck, local_id,
                                                 frame.source_stream_id, 0, nullptr, 0);
    return enqueue_p2p_packet(r, msg.source_port, msg.destination_port, reply.data(), reply.size());
  }
  if ((frame.flags & kP2pStreamSyn) != 0u && (frame.flags & kP2pStreamAck) != 0u)
  {
    auto it = r.p2p_stream_sessions.find(frame.destination_stream_id);
    if (it == r.p2p_stream_sessions.end())
    {
      return SEDS_OK;
    }
    it->second.peer_stream_id = frame.source_stream_id;
    it->second.connected = true;
    const auto handlers = r.p2p_stream_handlers[it->second.local_port];
    for (const auto & handler: handlers)
    {
      if (handler.cb != nullptr)
      {
        const SedsP2pStreamEventView view{2, frame.destination_stream_id, frame.source_stream_id, frame.sequence,
                                          it->second.peer_hostname.c_str(), it->second.peer_hostname.size(),
                                          it->second.peer_address, it->second.local_port, it->second.peer_port,
                                          frame.payload.data(), frame.payload.size()};
        if (handler.cb(&view, handler.user) != SEDS_OK)
        {
          return SEDS_HANDLER_ERROR;
        }
      }
    }
    return SEDS_OK;
  }
  const uint8_t kind = (frame.flags & kP2pStreamRst) != 0u ? 5u :
                       (frame.flags & kP2pStreamFin) != 0u ? 4u : 3u;
  uint32_t session_id = frame.destination_stream_id;
  if (session_id == 0)
  {
    for (const auto & [id, session]: r.p2p_stream_sessions)
    {
      if (session.peer_stream_id == frame.source_stream_id && session.local_port == msg.destination_port &&
          session.peer_port == msg.source_port && session.peer_address == msg.source_address &&
          session.peer_hostname == msg.source_hostname)
      {
        session_id = id;
        break;
      }
    }
  }
  auto it = r.p2p_stream_sessions.find(session_id);
  if (it == r.p2p_stream_sessions.end())
  {
    return SEDS_OK;
  }
  const auto session = it->second;
  const auto handlers = r.p2p_stream_handlers[session.local_port];
  for (const auto & handler: handlers)
  {
    if (handler.cb != nullptr)
    {
      const SedsP2pStreamEventView view{kind, session_id, frame.source_stream_id, frame.sequence,
                                        session.peer_hostname.c_str(), session.peer_hostname.size(),
                                        session.peer_address, session.local_port, session.peer_port,
                                        frame.payload.data(), frame.payload.size()};
      if (handler.cb(&view, handler.user) != SEDS_OK)
      {
        return SEDS_HANDLER_ERROR;
      }
    }
  }
  if (kind == 4u || kind == 5u)
  {
    r.p2p_stream_sessions.erase(session_id);
  }
  return SEDS_OK;
}

SedsResult dispatch_p2p_packet(SedsRouter & r, const seds::PacketData & pkt)
{
  if (pkt.ty != p2p_type_id())
  {
    return SEDS_OK;
  }
  const auto decoded = decode_p2p_payload(pkt.payload);
  if (!decoded)
  {
    return SEDS_DESERIALIZE;
  }
  if (!decoded->source_hostname.empty())
  {
    r.p2p_address_book[decoded->source_hostname] = decoded->source_address;
    r.p2p_host_by_address[decoded->source_address] = decoded->source_hostname;
  }
  if (const auto stream = decode_p2p_stream_payload(decoded->payload); stream.has_value())
  {
    return dispatch_p2p_stream(r, *decoded, *stream);
  }
  const auto handlers = r.p2p_handlers[decoded->destination_port];
  for (const auto & handler: handlers)
  {
    if (handler.cb != nullptr)
    {
      const SedsP2pMessageView view{decoded->source_hostname.c_str(), decoded->source_hostname.size(),
                                    decoded->source_address, decoded->source_port, decoded->destination_port,
                                    decoded->payload.data(), decoded->payload.size()};
      if (handler.cb(&view, handler.user) != SEDS_OK)
      {
        return SEDS_HANDLER_ERROR;
      }
    }
  }
  return SEDS_OK;
}

SedsResult send_p2p_stream_control(SedsRouter & r, uint32_t stream_id, uint8_t flags,
                                   const uint8_t * payload, size_t payload_len)
{
  auto it = r.p2p_stream_sessions.find(stream_id);
  if (it == r.p2p_stream_sessions.end())
  {
    return SEDS_BAD_ARG;
  }
  auto & session = it->second;
  const uint32_t seq = session.next_sequence++;
  if (session.next_sequence == 0)
  {
    session.next_sequence = 1;
  }
  const auto stream_payload = encode_p2p_stream_payload(flags, stream_id, session.peer_stream_id,
                                                        seq, payload, payload_len);
  const auto rc = enqueue_p2p_packet(r, session.peer_port, session.local_port,
                                     stream_payload.data(), stream_payload.size());
  if (rc == SEDS_OK && (flags & (kP2pStreamFin | kP2pStreamRst)) != 0u)
  {
    r.p2p_stream_sessions.erase(stream_id);
  }
  return rc;
}

} // namespace

namespace seds
{
  SedsRuntimeTuningConfig runtime_tuning_config()
  {
    std::scoped_lock lock(g_runtime_tuning_mu);
    return g_runtime_tuning_config;
  }

  std::string runtime_device_identifier()
  {
    std::scoped_lock lock(g_runtime_tuning_mu);
    return g_runtime_device_identifier;
  }

  size_t runtime_payload_compress_threshold() { return runtime_tuning_config().payload_compress_threshold; }

  size_t runtime_static_string_length() { return runtime_tuning_config().static_string_length; }

  size_t runtime_static_hex_length() { return runtime_tuning_config().static_hex_length; }

  size_t runtime_string_precision() { return runtime_tuning_config().string_precision; }

  size_t runtime_max_handler_retries() { return runtime_tuning_config().max_handler_retries; }

  uint32_t runtime_reliable_retransmit_ms() { return runtime_tuning_config().reliable_retransmit_ms; }

  uint32_t runtime_reliable_max_retries() { return runtime_tuning_config().reliable_max_retries; }

  size_t runtime_reliable_max_pending() { return runtime_tuning_config().reliable_max_pending; }

  size_t runtime_reliable_max_return_routes() { return runtime_tuning_config().reliable_max_return_routes; }

  size_t runtime_reliable_max_end_to_end_pending() { return runtime_tuning_config().reliable_max_end_to_end_pending; }

  size_t runtime_reliable_max_end_to_end_ack_cache()
  {
    return runtime_tuning_config().reliable_max_end_to_end_ack_cache;
  }

  void ensure_runtime_schema_loaded()
  {
    std::call_once(g_runtime_schema_once, [] {
      const auto load_path = [](const char * primary, const char * legacy) {
        const char * path = std::getenv(primary);
        if ((path == nullptr || path[0] == '\0') && legacy != nullptr)
        {
          path = std::getenv(legacy);
        }
        if (path == nullptr || path[0] == '\0')
        {
          return;
        }
        std::ifstream in(path);
        if (!in)
        {
          return;
        }
        std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        (void)register_schema_json_text(text);
      };
      load_path("SEDSNET_STATIC_SCHEMA_PATH", "SEDSPRINTF_RS_SCHEMA_PATH");
      load_path("SEDSNET_STATIC_IPC_SCHEMA_PATH", "SEDSPRINTF_RS_IPC_SCHEMA_PATH");
    });
  }
}

SedsResult seds_router_dispatch_p2p_packet(SedsRouter & r, const seds::PacketData & pkt)
{
  return dispatch_p2p_packet(r, pkt);
}

extern "C" {

SedsResult seds_runtime_device_identifier(char * buf, size_t buf_len)
{
  return static_cast<SedsResult>(seds::copy_text(seds::runtime_device_identifier(), buf, buf_len));
}

SedsResult seds_set_runtime_device_identifier(const char * sender, size_t sender_len)
{
  if (sender == nullptr || sender_len == 0)
  {
    return SEDS_BAD_ARG;
  }
  std::scoped_lock lock(g_runtime_tuning_mu);
  g_runtime_device_identifier.assign(sender, sender_len);
  return SEDS_OK;
}

SedsResult seds_get_runtime_tuning_config(SedsRuntimeTuningConfig * out)
{
  if (out == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  std::scoped_lock lock(g_runtime_tuning_mu);
  *out = g_runtime_tuning_config;
  return SEDS_OK;
}

SedsResult seds_set_runtime_tuning_config(const SedsRuntimeTuningConfig * cfg)
{
  if (cfg == nullptr || !valid_runtime_tuning_config(*cfg))
  {
    return SEDS_BAD_ARG;
  }
  std::scoped_lock lock(g_runtime_tuning_mu);
  g_runtime_tuning_config = *cfg;
  return SEDS_OK;
}

SedsRouter * seds_router_new_ex(SedsRouterMode mode, SedsNowMsFn now_ms_cb, void * user,
                                const SedsLocalEndpointDesc * handlers, size_t n_handlers,
                                uint8_t e2e_mode, uint32_t e2e_key_id)
{
  return seds_router_new_with_memory(mode, now_ms_cb, user, handlers, n_handlers, e2e_mode, e2e_key_id, nullptr);
}

SedsResult seds_router_set_sender_id(SedsRouter * r, const char * sender, size_t sender_len)
{
  const auto rc = seds_router_set_sender(r, sender, sender_len);
  if (rc == SEDS_OK && r != nullptr)
  {
    r->p2p_address = address_for_sender(r->sender);
    r->p2p_address_book[r->sender] = r->p2p_address;
    r->p2p_host_by_address[r->p2p_address] = r->sender;
  }
  return rc;
}

SedsResult seds_relay_set_sender_id(SedsRelay * r, const char * sender, size_t sender_len)
{
  if (r == nullptr || (sender == nullptr && sender_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  return SEDS_OK;
}

SedsResult seds_router_current_address(SedsRouter * r, uint32_t * out_address)
{
  if (r == nullptr || out_address == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  *out_address = local_p2p_address(*r);
  return SEDS_OK;
}

SedsResult seds_router_configure_address(SedsRouter * r, uint8_t address_mode, uint32_t requested_address)
{
  if (r == nullptr || address_mode > 2u)
  {
    return SEDS_BAD_ARG;
  }
  std::scoped_lock lock(r->mu);
  if (address_mode == 0u)
  {
    r->p2p_address = address_for_sender(r->sender);
  }
  else
  {
    r->p2p_address = requested_address == 0u ? 1u : requested_address;
  }
  r->p2p_address_book[r->sender] = r->p2p_address;
  r->p2p_host_by_address[r->p2p_address] = r->sender;
  return SEDS_OK;
}

SedsResult seds_router_resolve_hostname_address(SedsRouter * r, const char * hostname, size_t hostname_len,
                                                uint32_t * out_address)
{
  if (r == nullptr || out_address == nullptr || (hostname == nullptr && hostname_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  const auto found = resolve_p2p_host(*r, sv_from(hostname, hostname_len));
  if (!found)
  {
    return SEDS_BAD_ARG;
  }
  *out_address = found->second;
  return SEDS_OK;
}

SedsResult seds_router_bind_p2p_port(SedsRouter * r, uint16_t port, SedsP2pHandlerFn cb, void * user)
{
  if (r == nullptr || cb == nullptr || port == 0)
  {
    return SEDS_BAD_ARG;
  }
  r->p2p_handlers[port].push_back(seds::P2pPortHandler{cb, user});
  return SEDS_OK;
}

SedsResult seds_router_clear_p2p_port(SedsRouter * r, uint16_t port)
{
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  r->p2p_handlers.erase(port);
  return SEDS_OK;
}

SedsResult seds_router_send_p2p_to_hostname(SedsRouter * r, const char * hostname, size_t hostname_len,
                                            uint16_t dst_port, uint16_t src_port,
                                            const uint8_t * payload, size_t payload_len)
{
  if (r == nullptr || (hostname == nullptr && hostname_len != 0) || (payload == nullptr && payload_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  const auto found = resolve_p2p_host(*r, sv_from(hostname, hostname_len));
  if (!found)
  {
    return SEDS_BAD_ARG;
  }
  (void)found;
  return enqueue_p2p_packet(*r, dst_port, src_port, payload, payload_len);
}

SedsResult seds_router_send_p2p_to_address(SedsRouter * r, uint32_t address, uint16_t dst_port, uint16_t src_port,
                                           const uint8_t * payload, size_t payload_len)
{
  if (r == nullptr || (payload == nullptr && payload_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  const auto found = resolve_p2p_address(*r, address);
  if (!found)
  {
    return SEDS_BAD_ARG;
  }
  return enqueue_p2p_packet(*r, dst_port, src_port, payload, payload_len);
}

SedsResult seds_router_bind_p2p_stream_port(SedsRouter * r, uint16_t port, SedsP2pStreamHandlerFn cb, void * user)
{
  if (r == nullptr || cb == nullptr || port == 0)
  {
    return SEDS_BAD_ARG;
  }
  r->p2p_stream_handlers[port].push_back(seds::P2pStreamHandler{cb, user});
  return SEDS_OK;
}

SedsResult seds_router_clear_p2p_stream_port(SedsRouter * r, uint16_t port)
{
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  r->p2p_stream_handlers.erase(port);
  return SEDS_OK;
}

SedsResult seds_router_open_p2p_stream_to_hostname(SedsRouter * r, const char * hostname, size_t hostname_len,
                                                   uint16_t dst_port, uint16_t src_port, uint32_t * out_stream_id)
{
  if (out_stream_id)
  {
    *out_stream_id = 0;
  }
  if (r == nullptr || out_stream_id == nullptr || (hostname == nullptr && hostname_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  const auto found = resolve_p2p_host(*r, sv_from(hostname, hostname_len));
  if (!found || dst_port == 0 || src_port == 0)
  {
    return SEDS_BAD_ARG;
  }
  const uint32_t stream_id = allocate_p2p_stream_id(*r);
  if (stream_id == 0)
  {
    return SEDS_IO;
  }
  r->p2p_stream_sessions[stream_id] =
      seds::P2pStreamSession{found->first, found->second, src_port, dst_port, 0, 1, false};
  *out_stream_id = stream_id;
  const auto payload = encode_p2p_stream_payload(kP2pStreamSyn, stream_id, 0, 0, nullptr, 0);
  return enqueue_p2p_packet(*r, dst_port, src_port, payload.data(), payload.size());
}

SedsResult seds_router_open_p2p_stream_to_address(SedsRouter * r, uint32_t address,
                                                  uint16_t dst_port, uint16_t src_port,
                                                  uint32_t * out_stream_id)
{
  if (out_stream_id)
  {
    *out_stream_id = 0;
  }
  if (r == nullptr || out_stream_id == nullptr || dst_port == 0 || src_port == 0)
  {
    return SEDS_BAD_ARG;
  }
  const auto found = resolve_p2p_address(*r, address);
  if (!found)
  {
    return SEDS_BAD_ARG;
  }
  const uint32_t stream_id = allocate_p2p_stream_id(*r);
  if (stream_id == 0)
  {
    return SEDS_IO;
  }
  r->p2p_stream_sessions[stream_id] =
      seds::P2pStreamSession{found->first, found->second, src_port, dst_port, 0, 1, false};
  *out_stream_id = stream_id;
  const auto payload = encode_p2p_stream_payload(kP2pStreamSyn, stream_id, 0, 0, nullptr, 0);
  return enqueue_p2p_packet(*r, dst_port, src_port, payload.data(), payload.size());
}

SedsResult seds_router_send_p2p_stream(SedsRouter * r, uint32_t stream_id, const uint8_t * payload, size_t payload_len)
{
  if (r == nullptr || (payload == nullptr && payload_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  return send_p2p_stream_control(*r, stream_id, kP2pStreamData, payload, payload_len);
}

SedsResult seds_router_close_p2p_stream(SedsRouter * r, uint32_t stream_id)
{
  return r == nullptr ? SEDS_BAD_ARG : send_p2p_stream_control(*r, stream_id, kP2pStreamFin, nullptr, 0);
}

SedsResult seds_router_reset_p2p_stream(SedsRouter * r, uint32_t stream_id)
{
  return r == nullptr ? SEDS_BAD_ARG : send_p2p_stream_control(*r, stream_id, kP2pStreamRst, nullptr, 0);
}

SedsResult seds_router_announce_leave(SedsRouter * r)
{
  return r == nullptr ? SEDS_BAD_ARG : SEDS_OK;
}

SedsResult seds_relay_announce_leave(SedsRelay * r)
{
  return r == nullptr ? SEDS_BAD_ARG : SEDS_OK;
}

SedsResult seds_router_enable_managed_variable(SedsRouter * r, SedsDataType ty)
{
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  if (!seds::valid_type(static_cast<uint32_t>(ty)))
  {
    return SEDS_INVALID_TYPE;
  }
  std::scoped_lock lock(r->mu);
  r->managed_variable_policy[static_cast<uint32_t>(ty)] = seds::ManagedVariablePolicy{true, true, true};
  return SEDS_OK;
}

SedsResult seds_router_enable_network_variable(SedsRouter * r, SedsDataType ty, bool can_read, bool can_write)
{
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  if (!seds::valid_type(static_cast<uint32_t>(ty)))
  {
    return SEDS_INVALID_TYPE;
  }
  std::scoped_lock lock(r->mu);
  r->managed_variable_policy[static_cast<uint32_t>(ty)] = seds::ManagedVariablePolicy{true, can_read, can_write};
  return SEDS_OK;
}

SedsResult seds_router_on_network_variable_update(SedsRouter * r, SedsDataType ty, SedsEndpointHandlerFn cb,
                                                  void * user)
{
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  if (!seds::valid_type(static_cast<uint32_t>(ty)))
  {
    return SEDS_INVALID_TYPE;
  }
  std::scoped_lock lock(r->mu);
  r->managed_variable_callbacks[static_cast<uint32_t>(ty)] = seds::ManagedVariableCallback{cb, user};
  return SEDS_OK;
}

void seds_router_disable_managed_variable(SedsRouter * r, SedsDataType ty)
{
  if (r == nullptr)
  {
    return;
  }
  std::scoped_lock lock(r->mu);
  const uint32_t id = static_cast<uint32_t>(ty);
  r->managed_variable_policy.erase(id);
  r->managed_variable_latest.erase(id);
  r->managed_variable_callbacks.erase(id);
}

SedsResult seds_router_request_managed_variable(SedsRouter * r, SedsDataType ty)
{
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  const uint32_t id = static_cast<uint32_t>(ty);
  if (!seds::valid_type(id))
  {
    return SEDS_INVALID_TYPE;
  }
  std::scoped_lock lock(r->mu);
  auto & policy = r->managed_variable_policy[id];
  policy.enabled = true;
  if (!policy.can_read)
  {
    return SEDS_PERMISSION_DENIED;
  }
  return queue_managed_request(*r, id);
}

SedsResult seds_router_set_network_variable_packed(SedsRouter * r, const uint8_t * bytes, size_t len)
{
  if (r == nullptr || (bytes == nullptr && len != 0))
  {
    return SEDS_BAD_ARG;
  }
  auto pkt = unpack_managed_packet(bytes, len);
  if (!pkt)
  {
    return SEDS_DESERIALIZE;
  }
  std::scoped_lock lock(r->mu);
  auto & policy = r->managed_variable_policy[pkt->ty];
  policy.enabled = true;
  if (!policy.can_write)
  {
    return SEDS_PERMISSION_DENIED;
  }
  const auto rc = remember_managed_packet(*r, *pkt, true);
  if (rc != SEDS_OK)
  {
    return rc;
  }
  seds::enqueue_tx(r->tx_queue, r->tx_queue_bytes, {std::move(*pkt), std::nullopt, std::nullopt, false},
                   r->memory.max_queue_budget);
  return SEDS_OK;
}

SedsResult seds_router_seed_managed_variable_packed(SedsRouter * r, const uint8_t * bytes, size_t len)
{
  if (r == nullptr || (bytes == nullptr && len != 0))
  {
    return SEDS_BAD_ARG;
  }
  auto pkt = unpack_managed_packet(bytes, len);
  if (!pkt)
  {
    return SEDS_DESERIALIZE;
  }
  std::scoped_lock lock(r->mu);
  return remember_managed_packet(*r, std::move(*pkt), true);
}

int32_t seds_router_cached_managed_variable_packed_len(SedsRouter * r, SedsDataType ty)
{
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  std::scoped_lock lock(r->mu);
  const auto it = r->managed_variable_latest.find(static_cast<uint32_t>(ty));
  return it == r->managed_variable_latest.end() ? 0 : static_cast<int32_t>(it->second.packed.size());
}

int32_t seds_router_get_network_variable_packed_len(SedsRouter * r, SedsDataType ty, uint32_t stale_after_ms)
{
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  std::scoped_lock lock(r->mu);
  const uint32_t id = static_cast<uint32_t>(ty);
  const auto policy = r->managed_variable_policy.find(id);
  if (policy != r->managed_variable_policy.end() && !policy->second.can_read)
  {
    return SEDS_PERMISSION_DENIED;
  }
  const auto it = r->managed_variable_latest.find(id);
  if (it == r->managed_variable_latest.end())
  {
    (void)queue_managed_request(*r, id);
    return 0;
  }
  if (stale_after_ms != 0 && static_cast<uint64_t>(r->now_ms() - it->second.updated_ms) > stale_after_ms)
  {
    (void)queue_managed_request(*r, id);
  }
  return static_cast<int32_t>(it->second.packed.size());
}

int32_t seds_router_cached_managed_variable_packed(SedsRouter * r, SedsDataType ty, uint8_t * out, size_t out_len)
{
  if (r == nullptr || (out == nullptr && out_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  std::scoped_lock lock(r->mu);
  const auto it = r->managed_variable_latest.find(static_cast<uint32_t>(ty));
  return it == r->managed_variable_latest.end() ? 0 : copy_managed_entry(it->second, out, out_len);
}

int32_t seds_router_get_network_variable_packed(SedsRouter * r, SedsDataType ty, uint32_t stale_after_ms,
                                                uint8_t * out, size_t out_len)
{
  if (r == nullptr || (out == nullptr && out_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  std::scoped_lock lock(r->mu);
  const uint32_t id = static_cast<uint32_t>(ty);
  const auto policy = r->managed_variable_policy.find(id);
  if (policy != r->managed_variable_policy.end() && !policy->second.can_read)
  {
    return SEDS_PERMISSION_DENIED;
  }
  const auto it = r->managed_variable_latest.find(id);
  if (it == r->managed_variable_latest.end())
  {
    (void)queue_managed_request(*r, id);
    return 0;
  }
  if (stale_after_ms != 0 && static_cast<uint64_t>(r->now_ms() - it->second.updated_ms) > stale_after_ms)
  {
    (void)queue_managed_request(*r, id);
  }
  return copy_managed_entry(it->second, out, out_len);
}

SedsResult seds_crypto_register_provider(SedsCryptoSealFn seal, SedsCryptoOpenFn open, void * user)
{
  if (seal == nullptr || open == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  g_crypto_seal = seal;
  g_crypto_open = open;
  g_crypto_user = user;
  return SEDS_OK;
}

void seds_crypto_clear_provider(void)
{
  g_crypto_seal = nullptr;
  g_crypto_open = nullptr;
  g_crypto_user = nullptr;
}

SedsResult seds_crypto_register_software_key(uint32_t key_id, const uint8_t * key, size_t key_len)
{
  if (key == nullptr || key_len < kSoftwareKeyMinLen)
  {
    return SEDS_BAD_ARG;
  }
  g_software_keys[key_id] = normalize_software_key(key, key_len);
  return SEDS_OK;
}

void seds_crypto_clear_software_keys(void)
{
  g_software_keys.clear();
}

SedsResult seds_crypto_issue_managed_credential(const uint8_t * root_key, size_t root_key_len,
                                                uint64_t subject_id, uint32_t key_id, uint64_t epoch,
                                                uint64_t not_before_ms, uint64_t not_after_ms,
                                                uint32_t permissions, uint8_t * out, size_t out_cap,
                                                size_t * out_len)
{
  if (root_key == nullptr || root_key_len < kSoftwareKeyMinLen || out == nullptr || out_len == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  *out_len = 0;
  if (out_cap < kManagedCredentialLen)
  {
    return SEDS_SIZE_MISMATCH;
  }
  std::memcpy(out, kManagedCredentialMagic, sizeof(kManagedCredentialMagic));
  write_le<uint64_t>(out + 8, subject_id);
  write_le<uint32_t>(out + 16, key_id);
  write_le<uint64_t>(out + 20, epoch);
  write_le<uint64_t>(out + 28, not_before_ms);
  write_le<uint64_t>(out + 36, not_after_ms);
  write_le<uint32_t>(out + 44, permissions);
  const auto key = normalize_software_key(root_key, root_key_len);
  const auto tag = managed_credential_tag(key, std::span<const uint8_t>(out, kManagedCredentialBodyLen));
  std::copy_n(tag.data(), 32, out + kManagedCredentialBodyLen);
  *out_len = kManagedCredentialLen;
  return SEDS_OK;
}

SedsResult seds_crypto_verify_managed_credential(const uint8_t * root_key, size_t root_key_len,
                                                 const uint8_t * credential, size_t credential_len,
                                                 uint64_t now_ms, SedsManagedCredentialInfo * out_info)
{
  if (root_key == nullptr || root_key_len < kSoftwareKeyMinLen || credential == nullptr || out_info == nullptr ||
      credential_len != kManagedCredentialLen)
  {
    return SEDS_BAD_ARG;
  }
  *out_info = {};
  if (!std::equal(std::begin(kManagedCredentialMagic), std::end(kManagedCredentialMagic), credential))
  {
    return SEDS_BAD_ARG;
  }
  const auto key = normalize_software_key(root_key, root_key_len);
  const auto tag = managed_credential_tag(key, std::span<const uint8_t>(credential, kManagedCredentialBodyLen));
  if (!constant_time_eq(std::span<const uint8_t>(tag.data(), 32),
                        std::span<const uint8_t>(credential + kManagedCredentialBodyLen, 32)))
  {
    return SEDS_HANDLER_ERROR;
  }
  const uint64_t not_before_ms = read_u64_le(credential + 28);
  const uint64_t not_after_ms = read_u64_le(credential + 36);
  if (now_ms < not_before_ms || now_ms > not_after_ms)
  {
    return SEDS_HANDLER_ERROR;
  }
  out_info->subject_id = read_u64_le(credential + 8);
  out_info->key_id = read_u32_le(credential + 16);
  out_info->epoch = read_u64_le(credential + 20);
  out_info->not_before_ms = not_before_ms;
  out_info->not_after_ms = not_after_ms;
  out_info->permissions = read_u32_le(credential + 44);
  return SEDS_OK;
}

SedsResult seds_crypto_seal(uint32_t key_id, const uint8_t * nonce, size_t nonce_len, const uint8_t * aad,
                            size_t aad_len, const uint8_t * plaintext, size_t plaintext_len,
                            uint8_t * ciphertext_out, size_t ciphertext_cap, size_t * ciphertext_len_out,
                            uint8_t * tag_out, size_t tag_cap, size_t * tag_len_out)
{
  if ((nonce == nullptr && nonce_len != 0) || (aad == nullptr && aad_len != 0) ||
      (plaintext == nullptr && plaintext_len != 0) || (ciphertext_out == nullptr && ciphertext_cap != 0) ||
      (tag_out == nullptr && tag_cap != 0) || ciphertext_len_out == nullptr || tag_len_out == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  if (g_crypto_seal != nullptr)
  {
    return g_crypto_seal(key_id, nonce, nonce_len, aad, aad_len, plaintext, plaintext_len, ciphertext_out,
                         ciphertext_cap, ciphertext_len_out, tag_out, tag_cap, tag_len_out, g_crypto_user);
  }
  const auto key = g_software_keys.find(key_id);
  if (key == g_software_keys.end())
  {
    return SEDS_BAD_ARG;
  }
  *ciphertext_len_out = 0;
  *tag_len_out = 0;
  if (ciphertext_out == nullptr || tag_out == nullptr || ciphertext_cap < plaintext_len || tag_cap < kSoftwareTagLen)
  {
    return SEDS_SIZE_MISMATCH;
  }
  apply_hmac_stream(key->second, key_id, std::span<const uint8_t>(nonce, nonce_len),
                    std::span<const uint8_t>(aad, aad_len),
                    std::span<const uint8_t>(plaintext, plaintext_len), ciphertext_out);
  const auto tag = software_tag(key->second, key_id, std::span<const uint8_t>(nonce, nonce_len),
                                std::span<const uint8_t>(aad, aad_len),
                                std::span<const uint8_t>(ciphertext_out, plaintext_len));
  std::copy_n(tag.data(), kSoftwareTagLen, tag_out);
  *ciphertext_len_out = plaintext_len;
  *tag_len_out = kSoftwareTagLen;
  return SEDS_OK;
}

SedsResult seds_crypto_open(uint32_t key_id, const uint8_t * nonce, size_t nonce_len, const uint8_t * aad,
                            size_t aad_len, const uint8_t * ciphertext, size_t ciphertext_len,
                            const uint8_t * tag, size_t tag_len, uint8_t * plaintext_out,
                            size_t plaintext_cap, size_t * plaintext_len_out)
{
  if ((nonce == nullptr && nonce_len != 0) || (aad == nullptr && aad_len != 0) ||
      (ciphertext == nullptr && ciphertext_len != 0) || (tag == nullptr && tag_len != 0) ||
      (plaintext_out == nullptr && plaintext_cap != 0) || plaintext_len_out == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  if (g_crypto_open != nullptr)
  {
    return g_crypto_open(key_id, nonce, nonce_len, aad, aad_len, ciphertext, ciphertext_len, tag, tag_len,
                         plaintext_out, plaintext_cap, plaintext_len_out, g_crypto_user);
  }
  const auto key = g_software_keys.find(key_id);
  if (key == g_software_keys.end() || tag_len != kSoftwareTagLen)
  {
    return SEDS_BAD_ARG;
  }
  *plaintext_len_out = 0;
  if (plaintext_out == nullptr || plaintext_cap < ciphertext_len)
  {
    return SEDS_SIZE_MISMATCH;
  }
  const auto expected = software_tag(key->second, key_id, std::span<const uint8_t>(nonce, nonce_len),
                                     std::span<const uint8_t>(aad, aad_len),
                                     std::span<const uint8_t>(ciphertext, ciphertext_len));
  if (!constant_time_eq(std::span<const uint8_t>(expected.data(), kSoftwareTagLen),
                        std::span<const uint8_t>(tag, tag_len)))
  {
    return SEDS_HANDLER_ERROR;
  }
  apply_hmac_stream(key->second, key_id, std::span<const uint8_t>(nonce, nonce_len),
                    std::span<const uint8_t>(aad, aad_len),
                    std::span<const uint8_t>(ciphertext, ciphertext_len), plaintext_out);
  *plaintext_len_out = ciphertext_len;
  return SEDS_OK;
}

bool seds_endpoint_exists(uint32_t endpoint)
{
  seds::ensure_runtime_schema_loaded();
  return seds::valid_endpoint(endpoint);
}

bool seds_dtype_exists(uint32_t ty)
{
  seds::ensure_runtime_schema_loaded();
  ty = c_api_type_id(ty);
  return seds::valid_type(ty);
}

SedsResult seds_endpoint_get_info(uint32_t endpoint, SedsEndpointInfo * out)
{
  if (out == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  seds::ensure_runtime_schema_loaded();
  *out = {};
  out->id = endpoint;
  out->exists = seds::valid_endpoint(endpoint);
  if (!out->exists)
  {
    return SEDS_OK;
  }
  out->name = seds::kEndpointNames[endpoint];
  out->name_len = std::strlen(out->name);
  out->link_local_only = endpoint_link_local(endpoint) || seds::endpoint_link_local_only(endpoint);
  const auto desc = endpoint_description(endpoint);
  out->description = desc.data();
  out->description_len = desc.size();
  return SEDS_OK;
}

SedsResult seds_endpoint_get_info_by_name(const char * name, size_t name_len, SedsEndpointInfo * out)
{
  if (out == nullptr || (name == nullptr && name_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  seds::ensure_runtime_schema_loaded();
  const std::string_view wanted = sv_from(name, name_len);
  for (uint32_t i = 100; i < seds::kEndpointNames.size(); ++i)
  {
    if (seds::kEndpointNames[i] != nullptr && wanted == seds::kEndpointNames[i])
    {
      return seds_endpoint_get_info(i, out);
    }
  }
  for (uint32_t i = 0; i < seds::kEndpointNames.size(); ++i)
  {
    if (seds::kEndpointNames[i] != nullptr && wanted == seds::kEndpointNames[i])
    {
      return seds_endpoint_get_info(i, out);
    }
  }
  *out = {};
  out->exists = false;
  return SEDS_OK;
}

SedsResult seds_dtype_get_info(uint32_t ty, uint32_t * endpoints_out, size_t endpoints_cap, SedsDataTypeInfo * out)
{
  if (out == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  seds::ensure_runtime_schema_loaded();
  ty = c_api_type_id(ty);
  *out = {};
  out->id = ty;
  out->exists = seds::valid_type(ty);
  if (!out->exists)
  {
    return SEDS_OK;
  }
  const auto & info = seds::kTypeInfo[ty];
  out->is_static = !info.dynamic;
  out->element_count = info.dynamic ? 0 : info.static_count;
  out->message_data_type = message_data_type_code(info.data_type);
  out->message_class = message_class_code(info.message_class);
  out->reliable = reliable_code(info.reliable_mode);
  out->priority = type_priority(ty);
  out->e2e_encryption = type_e2e_policy(ty);
  out->fixed_size = info.dynamic ? 0 : info.elem_size * info.static_count;
  out->endpoints = info.endpoints.data();
  out->num_endpoints = info.endpoints.size();
  out->name = info.name;
  out->name_len = std::strlen(info.name);
  const auto desc = type_description(ty);
  out->description = desc.data();
  out->description_len = desc.size();
  if (endpoints_out != nullptr)
  {
    const size_t n = std::min(endpoints_cap, info.endpoints.size());
    std::copy_n(info.endpoints.data(), n, endpoints_out);
  }
  return SEDS_OK;
}

SedsResult seds_dtype_get_info_by_name(const char * name, size_t name_len, uint32_t * endpoints_out,
                                       size_t endpoints_cap, SedsDataTypeInfo * out)
{
  if (out == nullptr || (name == nullptr && name_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  seds::ensure_runtime_schema_loaded();
  const std::string_view wanted = sv_from(name, name_len);
  for (uint32_t i = 100; i < seds::kTypeInfo.size(); ++i)
  {
    if (seds::kTypeInfo[i].name != nullptr && seds::kTypeInfo[i].name[0] != '\0' && wanted == seds::kTypeInfo[i].name)
    {
      return seds_dtype_get_info(i, endpoints_out, endpoints_cap, out);
    }
  }
  for (uint32_t i = 0; i < seds::kTypeInfo.size(); ++i)
  {
    if (seds::kTypeInfo[i].name != nullptr && seds::kTypeInfo[i].name[0] != '\0' && wanted == seds::kTypeInfo[i].name)
    {
      return seds_dtype_get_info(i, endpoints_out, endpoints_cap, out);
    }
  }
  *out = {};
  out->exists = false;
  return SEDS_OK;
}

SedsResult seds_endpoint_register(uint32_t endpoint, const char * name, size_t name_len, bool link_local_only)
{
  return seds_endpoint_register_ex(endpoint, name, name_len, nullptr, 0, link_local_only);
}

SedsResult seds_endpoint_register_ex(uint32_t endpoint, const char * name, size_t name_len,
                                     const char * description, size_t description_len, bool link_local_only)
{
  if ((name == nullptr && name_len != 0) || (description == nullptr && description_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  const std::string_view new_name = sv_from(name, name_len);
  const std::string_view new_desc = sv_from(description, description_len);
  if (endpoint < seds::kEndpointNames.size() && seds::kEndpointNames[endpoint] != nullptr)
  {
    if (new_name == seds::kEndpointNames[endpoint] && new_desc == endpoint_description(endpoint) &&
        link_local_only == endpoint_link_local(endpoint))
    {
      return SEDS_OK;
    }
    return SEDS_BAD_ARG;
  }
  for (uint32_t i = 0; i < seds::kEndpointNames.size(); ++i)
  {
    if (i != endpoint && seds::kEndpointNames[i] != nullptr && new_name == seds::kEndpointNames[i])
    {
      return SEDS_BAD_ARG;
    }
  }
  if (endpoint >= seds::kEndpointNames.size())
  {
    seds::kEndpointNames.resize(endpoint + 1u, nullptr);
  }
  auto & stored_name = g_runtime_endpoint_names[endpoint];
  stored_name = std::string(new_name);
  g_runtime_endpoint_descriptions[endpoint] = std::string(new_desc);
  g_runtime_endpoint_link_local[endpoint] = link_local_only;
  seds::kEndpointNames[endpoint] = stored_name.c_str();
  seds::kEndpointCount = static_cast<uint32_t>(seds::kEndpointNames.size());
  return SEDS_OK;
}

SedsResult seds_dtype_register(uint32_t ty, const char * name, size_t name_len, bool is_static,
                               size_t element_count, uint8_t message_data_type, uint8_t message_class,
                               uint8_t reliable, uint8_t priority, const uint32_t * endpoints,
                               size_t num_endpoints)
{
  if ((name == nullptr && name_len != 0) || (endpoints == nullptr && num_endpoints != 0))
  {
    return SEDS_BAD_ARG;
  }
  ty = c_api_type_id(ty);
  const std::string_view new_name = sv_from(name, name_len);
  const auto elem_type = element_type_from_code(message_data_type);
  std::vector<uint32_t> endpoint_vec(endpoints, endpoints + num_endpoints);
  for (const auto endpoint: endpoint_vec)
  {
    if (endpoint >= seds::kEndpointNames.size() || seds::kEndpointNames[endpoint] == nullptr)
    {
      return SEDS_BAD_ARG;
    }
  }
  if (ty < seds::kTypeInfo.size() && seds::kTypeInfo[ty].name != nullptr && seds::kTypeInfo[ty].name[0] != '\0')
  {
    const auto & existing = seds::kTypeInfo[ty];
    if (new_name == existing.name && existing.dynamic == !is_static &&
        existing.static_count == (is_static ? element_count : 0) && existing.data_type == elem_type &&
        existing.message_class == message_class_from_code(message_class) &&
        existing.reliable_mode == reliable_from_code(reliable) && existing.endpoints == endpoint_vec &&
        type_priority(ty) == priority && type_description(ty).empty())
    {
      return SEDS_OK;
    }
    return SEDS_BAD_ARG;
  }
  for (uint32_t i = 0; i < seds::kTypeInfo.size(); ++i)
  {
    if (i != ty && seds::kTypeInfo[i].name != nullptr && seds::kTypeInfo[i].name[0] != '\0' &&
        new_name == seds::kTypeInfo[i].name)
    {
      return SEDS_BAD_ARG;
    }
  }
  if (ty >= seds::kTypeInfo.size())
  {
    seds::kTypeInfo.resize(ty + 1u, seds::TypeInfo{"", 0, 0, false, seds::ReliableMode::None,
                                                   seds::ElementDataType::NoData,
                                                   seds::MessageClass::Data, false, {}});
  }
  auto & stored_name = g_runtime_type_names[ty];
  stored_name = std::string(new_name);
  auto & info = seds::kTypeInfo[ty];
  info.name = stored_name.c_str();
  info.elem_size = elem_size_from_type(elem_type);
  info.static_count = is_static ? element_count : 0;
  info.dynamic = !is_static;
  info.reliable_mode = reliable_from_code(reliable);
  info.data_type = elem_type;
  info.message_class = message_class_from_code(message_class);
  info.link_local_only = false;
  info.endpoints = std::move(endpoint_vec);
  g_runtime_type_descriptions[ty] = {};
  g_runtime_type_priorities[ty] = priority;
  g_runtime_type_e2e_policies[ty] = SEDS_E2E_PREFER_OFF;
  return SEDS_OK;
}

SedsResult seds_dtype_register_ex(uint32_t ty, const char * name, size_t name_len,
                                  const char * description, size_t description_len, bool is_static,
                                  size_t element_count, uint8_t message_data_type, uint8_t message_class,
                                  uint8_t reliable, uint8_t priority, const uint32_t * endpoints,
                                  size_t num_endpoints)
{
  if (description == nullptr && description_len != 0)
  {
    return SEDS_BAD_ARG;
  }
  const uint32_t local_ty = c_api_type_id(ty);
  const bool existed = local_ty < seds::kTypeInfo.size() && seds::kTypeInfo[local_ty].name != nullptr &&
                       seds::kTypeInfo[local_ty].name[0] != '\0';
  const std::string_view new_desc = sv_from(description, description_len);
  const auto rc = seds_dtype_register(ty, name, name_len, is_static, element_count, message_data_type, message_class,
                                      reliable, priority, endpoints, num_endpoints);
  if (rc != SEDS_OK)
  {
    return rc;
  }
  if (existed)
  {
    return type_description(local_ty) == new_desc ? SEDS_OK : SEDS_BAD_ARG;
  }
  g_runtime_type_descriptions[local_ty] = std::string(new_desc);
  return SEDS_OK;
}

SedsResult seds_dtype_set_e2e_encryption_policy(uint32_t ty, uint8_t policy)
{
  ty = c_api_type_id(ty);
  if (!seds::valid_type(ty))
  {
    return SEDS_INVALID_TYPE;
  }
  g_runtime_type_e2e_policies[ty] = policy;
  return SEDS_OK;
}

SedsResult seds_schema_register_json_bytes(const uint8_t * json, size_t json_len)
{
  if (json == nullptr && json_len != 0)
  {
    return SEDS_BAD_ARG;
  }
  return register_schema_json_text(std::string_view(reinterpret_cast<const char *>(json), json_len));
}

SedsResult seds_schema_register_json_file(const char * path, size_t path_len)
{
  if (path == nullptr && path_len != 0)
  {
    return SEDS_BAD_ARG;
  }
  std::ifstream in(std::string(path, path_len));
  if (!in)
  {
    return SEDS_IO;
  }
  std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
  return register_schema_json_text(text);
}

SedsResult seds_endpoint_remove(uint32_t endpoint)
{
  if (endpoint >= seds::kEndpointNames.size() || seds::kEndpointNames[endpoint] == nullptr)
  {
    return SEDS_OK;
  }
  if (is_internal_endpoint_id(endpoint))
  {
    return SEDS_BAD_ARG;
  }
  seds::kEndpointNames[endpoint] = nullptr;
  g_runtime_endpoint_names.erase(endpoint);
  g_runtime_endpoint_descriptions.erase(endpoint);
  g_runtime_endpoint_link_local.erase(endpoint);
  for (uint32_t ty = 0; ty < seds::kTypeInfo.size(); ++ty)
  {
    const auto & eps = seds::kTypeInfo[ty].endpoints;
    if (std::ranges::find(eps, endpoint) != eps.end())
    {
      seds::kTypeInfo[ty] = seds::TypeInfo{"", 0, 0, false, seds::ReliableMode::None,
                                           seds::ElementDataType::NoData, seds::MessageClass::Data, false, {}};
      g_runtime_type_names.erase(ty);
      g_runtime_type_descriptions.erase(ty);
      g_runtime_type_priorities.erase(ty);
      g_runtime_type_e2e_policies.erase(ty);
    }
  }
  return SEDS_OK;
}

SedsResult seds_endpoint_remove_by_name(const char * name, size_t name_len)
{
  if (name == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  const std::string_view wanted = sv_from(name, name_len);
  for (uint32_t i = 0; i < seds::kEndpointNames.size(); ++i)
  {
    if (seds::kEndpointNames[i] != nullptr && wanted == seds::kEndpointNames[i])
    {
      return seds_endpoint_remove(i);
    }
  }
  return SEDS_OK;
}

SedsResult seds_dtype_remove(uint32_t ty)
{
  ty = c_api_type_id(ty);
  if (!seds::valid_type(ty))
  {
    return SEDS_OK;
  }
  if (is_internal_type_id(ty))
  {
    return SEDS_BAD_ARG;
  }
  seds::kTypeInfo[ty] = seds::TypeInfo{"", 0, 0, false, seds::ReliableMode::None,
                                       seds::ElementDataType::NoData, seds::MessageClass::Data, false, {}};
  g_runtime_type_names.erase(ty);
  g_runtime_type_descriptions.erase(ty);
  g_runtime_type_priorities.erase(ty);
  g_runtime_type_e2e_policies.erase(ty);
  return SEDS_OK;
}

SedsResult seds_dtype_remove_by_name(const char * name, size_t name_len)
{
  if (name == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  const std::string_view wanted = sv_from(name, name_len);
  for (uint32_t i = 0; i < seds::kTypeInfo.size(); ++i)
  {
    if (seds::kTypeInfo[i].name != nullptr && seds::kTypeInfo[i].name[0] != '\0' && wanted == seds::kTypeInfo[i].name)
    {
      return seds_dtype_remove(i);
    }
  }
  return SEDS_OK;
}

int32_t seds_router_add_side_packed(SedsRouter * r, const char * name, size_t name_len, SedsTransmitFn tx,
                                    void * tx_user, bool reliable_enabled)
{
  return seds_router_add_side_serialized(r, name, name_len, tx, tx_user, reliable_enabled);
}

int32_t seds_router_add_side_packed_small_packets(SedsRouter * r, const char * name, size_t name_len,
                                                  SedsTransmitFn tx, void * tx_user, bool reliable_enabled,
                                                  size_t max_frame_bytes)
{
  const int32_t side_id = seds_router_add_side_serialized(r, name, name_len, tx, tx_user, reliable_enabled);
  if (side_id >= 0)
  {
    std::scoped_lock lock(r->mu);
    apply_side_transport_profile(r->sides[static_cast<size_t>(side_id)], SEDS_SIDE_TRANSPORT_PROFILE_IPV6_LIKE,
                                 max_frame_bytes, 40u, 64u);
  }
  return side_id;
}

int32_t seds_router_add_side_packed_profile(SedsRouter * r, const char * name, size_t name_len,
                                            SedsTransmitFn tx, void * tx_user, bool reliable_enabled,
                                            SedsSideTransportProfile profile, size_t max_frame_bytes,
                                            size_t compact_header_target_bytes,
                                            size_t max_side_transport_templates)
{
  if (profile != SEDS_SIDE_TRANSPORT_PROFILE_CANONICAL && profile != SEDS_SIDE_TRANSPORT_PROFILE_TEMPLATE &&
      profile != SEDS_SIDE_TRANSPORT_PROFILE_IPV6_LIKE && profile != SEDS_SIDE_TRANSPORT_PROFILE_IPV4_LIKE)
  {
    return SEDS_BAD_ARG;
  }
  const int32_t side_id = seds_router_add_side_serialized(r, name, name_len, tx, tx_user, reliable_enabled);
  if (side_id >= 0)
  {
    std::scoped_lock lock(r->mu);
    apply_side_transport_profile(r->sides[static_cast<size_t>(side_id)], profile, max_frame_bytes,
                                 compact_header_target_bytes, max_side_transport_templates);
  }
  return side_id;
}

SedsResult seds_router_note_side_link_probe_sample(SedsRouter * r, int32_t side_id, size_t bytes,
                                                   uint64_t duration_ms)
{
  (void)bytes;
  (void)duration_ms;
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  return side_id < 0 || static_cast<size_t>(side_id) >= r->sides.size() ? SEDS_INVALID_LINK_ID : SEDS_OK;
}

SedsResult seds_router_receive_packed(SedsRouter * r, const uint8_t * bytes, size_t len)
{
  return seds_router_receive_serialized(r, bytes, len);
}

SedsResult seds_router_transmit_packed_message_queue(SedsRouter * r, const uint8_t * bytes, size_t len)
{
  return seds_router_transmit_serialized_message_queue(r, bytes, len);
}

SedsResult seds_router_transmit_packed_message(SedsRouter * r, const uint8_t * bytes, size_t len)
{
  return seds_router_transmit_serialized_message(r, bytes, len);
}

SedsResult seds_router_rx_packed_packet_to_queue(SedsRouter * r, const uint8_t * bytes, size_t len)
{
  return seds_router_rx_serialized_packet_to_queue(r, bytes, len);
}

SedsResult seds_router_receive_packed_from_side(SedsRouter * r, uint32_t side_id, const uint8_t * bytes, size_t len)
{
  return seds_router_receive_serialized_from_side(r, side_id, bytes, len);
}

SedsResult seds_router_rx_packed_packet_to_queue_from_side(SedsRouter * r, uint32_t side_id,
                                                           const uint8_t * bytes, size_t len)
{
  return seds_router_rx_serialized_packet_to_queue_from_side(r, side_id, bytes, len);
}

int32_t seds_pkt_pack_len(const SedsPacketView * view)
{
  return seds_pkt_serialize_len(view);
}

int32_t seds_pkt_pack(const SedsPacketView * view, uint8_t * out, size_t out_len)
{
  return seds_pkt_serialize(view, out, out_len);
}

SedsOwnedPacket * seds_pkt_unpack_owned(const uint8_t * bytes, size_t len)
{
  return seds_pkt_deserialize_owned(bytes, len);
}

SedsResult seds_pkt_validate_packed(const uint8_t * bytes, size_t len)
{
  return seds_pkt_validate_serialized(bytes, len);
}

SedsOwnedHeader * seds_pkt_unpack_header_owned(const uint8_t * bytes, size_t len)
{
  return seds_pkt_deserialize_header_owned(bytes, len);
}

int32_t seds_relay_add_side_packed(SedsRelay * r, const char * name, size_t name_len, SedsTransmitFn tx,
                                   void * tx_user, bool reliable_enabled)
{
  return seds_relay_add_side_serialized(r, name, name_len, tx, tx_user, reliable_enabled);
}

int32_t seds_relay_add_side_packed_small_packets(SedsRelay * r, const char * name, size_t name_len,
                                                 SedsTransmitFn tx, void * tx_user, bool reliable_enabled,
                                                 size_t max_frame_bytes)
{
  const int32_t side_id = seds_relay_add_side_serialized(r, name, name_len, tx, tx_user, reliable_enabled);
  if (side_id >= 0)
  {
    std::scoped_lock lock(r->mu);
    apply_side_transport_profile(r->sides[static_cast<size_t>(side_id)], SEDS_SIDE_TRANSPORT_PROFILE_IPV6_LIKE,
                                 max_frame_bytes, 40u, 64u);
  }
  return side_id;
}

int32_t seds_relay_add_side_packed_profile(SedsRelay * r, const char * name, size_t name_len,
                                           SedsTransmitFn tx, void * tx_user, bool reliable_enabled,
                                           SedsSideTransportProfile profile, size_t max_frame_bytes,
                                           size_t compact_header_target_bytes,
                                           size_t max_side_transport_templates)
{
  if (profile != SEDS_SIDE_TRANSPORT_PROFILE_CANONICAL && profile != SEDS_SIDE_TRANSPORT_PROFILE_TEMPLATE &&
      profile != SEDS_SIDE_TRANSPORT_PROFILE_IPV6_LIKE && profile != SEDS_SIDE_TRANSPORT_PROFILE_IPV4_LIKE)
  {
    return SEDS_BAD_ARG;
  }
  const int32_t side_id = seds_relay_add_side_serialized(r, name, name_len, tx, tx_user, reliable_enabled);
  if (side_id >= 0)
  {
    std::scoped_lock lock(r->mu);
    apply_side_transport_profile(r->sides[static_cast<size_t>(side_id)], profile, max_frame_bytes,
                                 compact_header_target_bytes, max_side_transport_templates);
  }
  return side_id;
}

SedsResult seds_relay_note_side_link_probe_sample(SedsRelay * r, int32_t side_id, size_t bytes, uint64_t duration_ms)
{
  (void)bytes;
  (void)duration_ms;
  if (r == nullptr)
  {
    return SEDS_BAD_ARG;
  }
  return side_id < 0 || static_cast<size_t>(side_id) >= r->sides.size() ? SEDS_INVALID_LINK_ID : SEDS_OK;
}

SedsResult seds_relay_rx_packed_from_side(SedsRelay * r, uint32_t side_id, const uint8_t * bytes, size_t len)
{
  return seds_relay_rx_serialized_from_side(r, side_id, bytes, len);
}

int32_t seds_router_export_client_stats_len(SedsRouter * r, const char * sender, size_t sender_len)
{
  if (r == nullptr || (sender == nullptr && sender_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  return static_cast<int32_t>(client_stats_json(*r, sv_from(sender, sender_len)).size() + 1);
}

SedsResult seds_router_export_client_stats(SedsRouter * r, const char * sender, size_t sender_len,
                                           char * buf, size_t buf_len)
{
  if (r == nullptr || (sender == nullptr && sender_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  return copy_json(client_stats_json(*r, sv_from(sender, sender_len)), buf, buf_len);
}

int32_t seds_router_export_runtime_stats_len(SedsRouter * r)
{
  return r == nullptr ? SEDS_BAD_ARG : static_cast<int32_t>(runtime_stats_json(*r).size() + 1);
}

SedsResult seds_router_export_runtime_stats(SedsRouter * r, char * buf, size_t buf_len)
{
  return r == nullptr ? SEDS_BAD_ARG : copy_json(runtime_stats_json(*r), buf, buf_len);
}

int32_t seds_router_export_memory_layout_len(SedsRouter * r)
{
  return r == nullptr ? SEDS_BAD_ARG : static_cast<int32_t>(memory_layout_json(*r, "router").size() + 1);
}

SedsResult seds_router_export_memory_layout(SedsRouter * r, char * buf, size_t buf_len)
{
  return r == nullptr ? SEDS_BAD_ARG : copy_json(memory_layout_json(*r, "router"), buf, buf_len);
}

int32_t seds_relay_export_client_stats_len(SedsRelay * r, const char * sender, size_t sender_len)
{
  if (r == nullptr || (sender == nullptr && sender_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  return static_cast<int32_t>(client_stats_json(*r, sv_from(sender, sender_len)).size() + 1);
}

SedsResult seds_relay_export_client_stats(SedsRelay * r, const char * sender, size_t sender_len,
                                          char * buf, size_t buf_len)
{
  if (r == nullptr || (sender == nullptr && sender_len != 0))
  {
    return SEDS_BAD_ARG;
  }
  return copy_json(client_stats_json(*r, sv_from(sender, sender_len)), buf, buf_len);
}

int32_t seds_relay_export_runtime_stats_len(SedsRelay * r)
{
  return r == nullptr ? SEDS_BAD_ARG : static_cast<int32_t>(runtime_stats_json(*r).size() + 1);
}

SedsResult seds_relay_export_runtime_stats(SedsRelay * r, char * buf, size_t buf_len)
{
  return r == nullptr ? SEDS_BAD_ARG : copy_json(runtime_stats_json(*r), buf, buf_len);
}

int32_t seds_relay_export_memory_layout_len(SedsRelay * r)
{
  return r == nullptr ? SEDS_BAD_ARG : static_cast<int32_t>(memory_layout_json(*r, "relay").size() + 1);
}

SedsResult seds_relay_export_memory_layout(SedsRelay * r, char * buf, size_t buf_len)
{
  return r == nullptr ? SEDS_BAD_ARG : copy_json(memory_layout_json(*r, "relay"), buf, buf_len);
}

} // extern "C"
