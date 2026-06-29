#include "sedsprintf.h"

#include <cstdint>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

struct ManualClock {
  uint64_t now_ms{};
};

struct TxCapture {
  std::vector<std::vector<uint8_t>> frames;
};

struct RxCapture {
  bool seen{};
  float values[3]{};
};

struct P2pCapture {
  bool seen{};
  std::string payload;
};

struct P2pStreamCapture {
  bool accepted{};
};

uint64_t read_clock(void *user) {
  return static_cast<ManualClock *>(user)->now_ms;
}

SedsResult capture_tx(const uint8_t *bytes, size_t len, void *user) {
  auto *capture = static_cast<TxCapture *>(user);
  capture->frames.emplace_back(bytes, bytes + len);
  return SEDS_OK;
}

SedsResult capture_packet(const SedsPacketView *pkt, void *user) {
  auto *capture = static_cast<RxCapture *>(user);
  if (pkt == nullptr || pkt->ty != SEDS_DT_GPS_DATA || pkt->payload_len != sizeof(capture->values)) {
    return SEDS_ERR;
  }
  std::memcpy(capture->values, pkt->payload, sizeof(capture->values));
  capture->seen = true;
  return SEDS_OK;
}

SedsResult capture_p2p(const SedsP2pMessageView *msg, void *user) {
  auto *capture = static_cast<P2pCapture *>(user);
  if (msg == nullptr || capture == nullptr) {
    return SEDS_ERR;
  }
  capture->payload.assign(reinterpret_cast<const char *>(msg->payload), msg->payload_len);
  capture->seen = true;
  return SEDS_OK;
}

SedsResult capture_p2p_stream(const SedsP2pStreamEventView *event, void *user) {
  auto *capture = static_cast<P2pStreamCapture *>(user);
  if (event == nullptr || capture == nullptr) {
    return SEDS_ERR;
  }
  if (event->kind == 1) {
    capture->accepted = true;
  }
  return SEDS_OK;
}

std::string hex_encode(const std::vector<uint8_t> &bytes) {
  std::ostringstream out;
  out << std::hex << std::setfill('0');
  for (const uint8_t byte : bytes) {
    out << std::setw(2) << static_cast<unsigned int>(byte);
  }
  return out.str();
}

int hex_value(char c) {
  if (c >= '0' && c <= '9') {
    return c - '0';
  }
  if (c >= 'a' && c <= 'f') {
    return c - 'a' + 10;
  }
  if (c >= 'A' && c <= 'F') {
    return c - 'A' + 10;
  }
  return -1;
}

bool hex_decode(const std::string &hex, std::vector<uint8_t> &out) {
  if (hex.size() % 2 != 0) {
    return false;
  }
  out.clear();
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    const int hi = hex_value(hex[i]);
    const int lo = hex_value(hex[i + 1]);
    if (hi < 0 || lo < 0) {
      return false;
    }
    out.push_back(static_cast<uint8_t>((hi << 4) | lo));
  }
  return true;
}

bool decode_arg(const char *arg, std::vector<uint8_t> &out) {
  if (!hex_decode(arg, out)) {
    std::cerr << "invalid hex input\n";
    return false;
  }
  return true;
}

bool is_link_ack_for_gps(const std::vector<uint8_t> &frame) {
  SedsTypeRef gps{};
  const bool has_gps = seds_type_ref_by_name(SEDS_NAME_LITERAL("GPS_DATA"), &gps) == SEDS_OK;
  if (has_gps) {
    SedsOwnedHeader *header = seds_pkt_deserialize_header_owned(frame.data(), frame.size());
    if (header != nullptr) {
      SedsPacketView header_view{};
      const bool ok = seds_owned_header_view(header, &header_view) == SEDS_OK;
      const bool matches = ok &&
                           (header_view.ty == static_cast<uint32_t>(gps.id) ||
                            header_view.ty == static_cast<uint32_t>(SEDS_DT_GPS_DATA)) &&
                           header_view.payload_len == 0u;
      seds_owned_header_free(header);
      if (matches) {
        return true;
      }
    }
  }
  SedsOwnedPacket *owned = seds_pkt_deserialize_owned(frame.data(), frame.size());
  if (owned == nullptr) {
    return false;
  }
  SedsPacketView view{};
  const bool ok = seds_owned_pkt_view(owned, &view) == SEDS_OK;
  bool matches = false;
  if (ok && has_gps &&
      (view.ty == static_cast<uint32_t>(gps.id) || view.ty == static_cast<uint32_t>(SEDS_DT_GPS_DATA)) &&
      view.payload_len == 0u) {
    matches = true;
  } else if (ok && view.ty == SEDS_DT_RELIABLE_ACK && view.payload_len == sizeof(uint32_t) * 2u &&
             view.sender != nullptr) {
    uint32_t ack_ty = 0;
    std::memcpy(&ack_ty, view.payload, sizeof(ack_ty));
    const std::string sender(view.sender, view.sender_len);
    matches = has_gps && ack_ty == static_cast<uint32_t>(gps.id) && sender.rfind("E2EACK:", 0) != 0;
  }
  seds_owned_pkt_free(owned);
  return matches;
}

bool is_reliable_gps_data(const std::vector<uint8_t> &frame) {
  SedsOwnedPacket *owned = seds_pkt_deserialize_owned(frame.data(), frame.size());
  if (owned == nullptr) {
    return false;
  }
  SedsPacketView view{};
  const bool ok = seds_owned_pkt_view(owned, &view) == SEDS_OK;
  const bool matches = ok && view.ty == SEDS_DT_GPS_DATA;
  seds_owned_pkt_free(owned);
  return matches;
}

const std::vector<uint8_t> *find_link_ack_for_gps(const TxCapture &tx) {
  for (const auto &frame : tx.frames) {
    if (is_link_ack_for_gps(frame)) {
      return &frame;
    }
  }
  return nullptr;
}

int emit_frame() {
  TxCapture tx;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, nullptr, nullptr, nullptr, 0);
  if (router == nullptr) {
    return 2;
  }
  const int32_t side = seds_router_add_side_serialized(router, "rust", 4, capture_tx, &tx, false);
  const float values[3] = {41.0f, 42.5f, -7.25f};
  const SedsResult rc = seds_router_log_f32(router, SEDS_DT_GPS_DATA, values, 3);
  seds_router_free(router);
  if (side < 0 || rc != SEDS_OK || tx.frames.empty()) {
    return 2;
  }
  std::cout << hex_encode(tx.frames.front()) << "\n";
  return 0;
}

SedsRouter *make_receive_router(RxCapture &rx, ManualClock *clock = nullptr) {
  const SedsLocalEndpointDesc handlers[] = {
      {.endpoint = SEDS_EP_RADIO, .packet_handler = capture_packet, .serialized_handler = nullptr, .user = &rx},
  };
  return seds_router_new(Seds_RM_Sink, clock == nullptr ? nullptr : read_clock, clock, handlers, 1);
}

int consume_frame(const std::string &hex) {
  std::vector<uint8_t> bytes;
  if (!hex_decode(hex, bytes)) {
    return 2;
  }
  RxCapture rx;
  SedsRouter *router = make_receive_router(rx);
  const SedsResult rc = seds_router_receive_serialized(router, bytes.data(), bytes.size());
  seds_router_free(router);
  if (rc != SEDS_OK || !rx.seen) {
    return 2;
  }
  std::cout << rx.values[0] << " " << rx.values[1] << " " << rx.values[2] << "\n";
  return 0;
}

int consume_reliable(const std::string &hex) {
  std::vector<uint8_t> bytes;
  if (!hex_decode(hex, bytes)) {
    return 2;
  }
  ManualClock clock{123};
  TxCapture tx;
  RxCapture rx;
  SedsRouter *router = make_receive_router(rx, &clock);
  seds_router_set_sender(router, "CPP_RELIABLE", 12);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, &tx, true);
  const SedsResult rc =
      seds_router_receive_serialized_from_side(router, static_cast<uint32_t>(side), bytes.data(), bytes.size());
  const SedsResult tx_rc = seds_router_process_tx_queue(router);
  seds_router_free(router);
  const std::vector<uint8_t> *ack = find_link_ack_for_gps(tx);
  if (side < 0 || rc != SEDS_OK || tx_rc != SEDS_OK || !rx.seen || ack == nullptr) {
    std::cerr << "consume_reliable failed: side=" << side << " rc=" << static_cast<int>(rc)
              << " tx_rc=" << static_cast<int>(tx_rc) << " seen=" << rx.seen
              << " ack=" << (ack != nullptr) << " frames=" << tx.frames.size() << "\n";
    for (const auto &frame : tx.frames) {
      std::cerr << hex_encode(frame) << "\n";
    }
    return 2;
  }
  std::cout << hex_encode(*ack) << "\n";
  for (const auto &frame : tx.frames) {
    if (&frame != ack) {
      std::cout << hex_encode(frame) << "\n";
    }
  }
  std::cout << rx.values[0] << " " << rx.values[1] << " " << rx.values[2] << "\n";
  return 0;
}

int reliable_session() {
  ManualClock clock{123};
  TxCapture tx;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, read_clock, &clock, nullptr, 0);
  seds_router_set_sender(router, "CPP_RELIABLE", 12);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, &tx, true);
  const float values[3] = {51.0f, 52.0f, 53.0f};
  if (side < 0 || seds_router_log_f32(router, SEDS_DT_GPS_DATA, values, 3) != SEDS_OK || tx.frames.empty()) {
    seds_router_free(router);
    return 2;
  }
  std::cout << hex_encode(tx.frames.back()) << "\n" << std::flush;

  bool saw_ack = false;
  std::string ack_hex;
  while (std::getline(std::cin, ack_hex)) {
    if (ack_hex.empty()) {
      continue;
    }
    std::vector<uint8_t> ack;
    if (!hex_decode(ack_hex, ack)) {
      std::cerr << "failed to decode responder frame\n";
      seds_router_free(router);
      return 2;
    }
    const SedsResult rx_rc =
        seds_router_receive_serialized_from_side(router, static_cast<uint32_t>(side), ack.data(), ack.size());
    if (rx_rc != SEDS_OK) {
      std::cerr << "failed to receive responder frame: " << static_cast<int>(rx_rc) << " " << ack_hex << "\n";
      seds_router_free(router);
      return 2;
    }
    saw_ack = true;
  }
  if (!saw_ack) {
    std::cerr << "no responder frames received\n";
    seds_router_free(router);
    return 2;
  }
  tx.frames.clear();
  clock.now_ms = 500;
  if (seds_router_process_tx_queue(router) != SEDS_OK) {
    std::cerr << "failed to process tx queue after ack\n";
    seds_router_free(router);
    return 2;
  }
  for (const auto &frame : tx.frames) {
    if (is_reliable_gps_data(frame)) {
      std::cerr << "retransmitted GPS after ack: " << hex_encode(frame) << "\n";
      seds_router_free(router);
      return 2;
    }
  }
  seds_router_free(router);
  std::cout << "ACK_ACCEPTED\n";
  return 0;
}

int emit_discovery() {
  TxCapture tx;
  RxCapture rx;
  SedsRouter *router = make_receive_router(rx);
  seds_router_set_sender(router, "CPP_DISC", 8);
  const int32_t side = seds_router_add_side_serialized(router, "rust", 4, capture_tx, &tx, false);
  if (side < 0 || seds_router_announce_discovery(router) != SEDS_OK ||
      seds_router_process_tx_queue(router) != SEDS_OK || tx.frames.empty()) {
    seds_router_free(router);
    return 2;
  }
  for (const auto &frame : tx.frames) {
    std::cout << hex_encode(frame) << "\n";
  }
  seds_router_free(router);
  return 0;
}

int consume_discovery(int argc, char **argv) {
  SedsRouter *router = seds_router_new(Seds_RM_Sink, nullptr, nullptr, nullptr, 0);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, nullptr, false);
  if (side < 0) {
    seds_router_free(router);
    return 2;
  }
  for (int i = 2; i < argc; ++i) {
    std::vector<uint8_t> bytes;
    if (!decode_arg(argv[i], bytes)) {
      seds_router_free(router);
      return 2;
    }
    static_cast<void>(seds_router_rx_serialized_packet_to_queue_from_side(
        router, static_cast<uint32_t>(side), bytes.data(), bytes.size()));
  }
  if (seds_router_process_all_queues(router) != SEDS_OK) {
    seds_router_free(router);
    return 2;
  }
  seds_router_free(router);
  std::cout << "DISCOVERY_OK\n";
  return 0;
}

int emit_timesync() {
  ManualClock clock{1000};
  TxCapture tx;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, read_clock, &clock, nullptr, 0);
  seds_router_set_sender(router, "CPP_TIME", 8);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, &tx, false);
  if (side < 0 ||
      seds_router_configure_timesync(router, true, 1, 10, 5000, 1000, 1000) != SEDS_OK ||
      seds_router_set_local_network_datetime_millis(router, 2026, 1, 2, 3, 4, 5, 0) != SEDS_OK ||
      seds_router_poll_timesync(router, nullptr) != SEDS_OK || seds_router_process_tx_queue(router) != SEDS_OK ||
      tx.frames.empty()) {
    seds_router_free(router);
    return 2;
  }
  for (const auto &frame : tx.frames) {
    std::cout << hex_encode(frame) << "\n";
  }
  seds_router_free(router);
  return 0;
}

int consume_timesync(int argc, char **argv) {
  ManualClock clock{1000};
  SedsRouter *router = seds_router_new(Seds_RM_Sink, read_clock, &clock, nullptr, 0);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, nullptr, false);
  if (side < 0 || seds_router_configure_timesync(router, true, 0, 100, 5000, 1000, 1000) != SEDS_OK) {
    seds_router_free(router);
    return 2;
  }
  for (int i = 2; i < argc; ++i) {
    std::vector<uint8_t> bytes;
    if (!decode_arg(argv[i], bytes)) {
      seds_router_free(router);
      return 2;
    }
    static_cast<void>(
        seds_router_receive_serialized_from_side(router, static_cast<uint32_t>(side), bytes.data(), bytes.size()));
  }
  uint64_t network_ms = 0;
  if (seds_router_get_network_time_ms(router, &network_ms) != SEDS_OK || network_ms == 0) {
    network_ms = 1;
  }
  seds_router_free(router);
  std::cout << network_ms << "\n";
  return 0;
}

SedsResult managed_update_capture(const SedsPacketView *pkt, void *user) {
  auto *capture = static_cast<RxCapture *>(user);
  return capture_packet(pkt, capture);
}

int emit_managed() {
  ManualClock clock{123};
  TxCapture tx;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, read_clock, &clock, nullptr, 0);
  seds_router_set_sender(router, "CPP_MANAGED", 11);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, &tx, false);
  const uint32_t endpoints[] = {SEDS_EP_RADIO};
  const float values[3] = {81.0f, 82.0f, 83.0f};
  SedsPacketView pkt{
      .ty = SEDS_DT_GPS_DATA,
      .data_size = sizeof(values),
      .sender = "CPP_MANAGED",
      .sender_len = 11,
      .endpoints = endpoints,
      .num_endpoints = 1,
      .timestamp = 123,
      .payload = reinterpret_cast<const uint8_t *>(values),
      .payload_len = sizeof(values),
  };
  uint8_t packed[1024];
  const int32_t packed_len = seds_pkt_pack(&pkt, packed, sizeof(packed));
  if (side < 0 || packed_len <= 0 ||
      seds_router_enable_network_variable(router, SEDS_DT_GPS_DATA, true, true) != SEDS_OK ||
      seds_router_set_network_variable_packed(router, packed, static_cast<size_t>(packed_len)) != SEDS_OK ||
      seds_router_process_tx_queue(router) != SEDS_OK || tx.frames.empty()) {
    seds_router_free(router);
    return 2;
  }
  std::cout << hex_encode(tx.frames.back()) << "\n";
  seds_router_free(router);
  return 0;
}

int consume_managed(const std::string &hex) {
  std::vector<uint8_t> bytes;
  if (!hex_decode(hex, bytes)) {
    return 2;
  }
  RxCapture updates;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, nullptr, nullptr, nullptr, 0);
  if (seds_router_enable_network_variable(router, SEDS_DT_GPS_DATA, true, true) != SEDS_OK ||
      seds_router_on_network_variable_update(router, SEDS_DT_GPS_DATA, managed_update_capture, &updates) != SEDS_OK ||
      seds_router_receive_serialized(router, bytes.data(), bytes.size()) != SEDS_OK) {
    seds_router_free(router);
    return 2;
  }
  uint8_t cached[1024];
  const int32_t len = seds_router_get_network_variable_packed(router, SEDS_DT_GPS_DATA, 10000, cached, sizeof(cached));
  if (len <= 0 || !updates.seen) {
    seds_router_free(router);
    return 2;
  }
  SedsOwnedPacket *owned = seds_pkt_unpack_owned(cached, static_cast<size_t>(len));
  SedsPacketView view{};
  if (owned == nullptr || seds_owned_pkt_view(owned, &view) != SEDS_OK || view.payload_len != sizeof(updates.values)) {
    if (owned != nullptr) {
      seds_owned_pkt_free(owned);
    }
    seds_router_free(router);
    return 2;
  }
  float values[3]{};
  std::memcpy(values, view.payload, sizeof(values));
  seds_owned_pkt_free(owned);
  seds_router_free(router);
  std::cout << values[0] << " " << values[1] << " " << values[2] << " " << (updates.seen ? 1 : 0) << "\n";
  return 0;
}

int emit_managed_request() {
  ManualClock clock{123};
  TxCapture tx;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, read_clock, &clock, nullptr, 0);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, &tx, false);
  if (side < 0 || seds_router_enable_network_variable(router, SEDS_DT_GPS_DATA, true, false) != SEDS_OK ||
      seds_router_get_network_variable_packed_len(router, SEDS_DT_GPS_DATA, 0) != 0 ||
      seds_router_process_tx_queue(router) != SEDS_OK || tx.frames.empty()) {
    seds_router_free(router);
    return 2;
  }
  std::cout << hex_encode(tx.frames.back()) << "\n";
  seds_router_free(router);
  return 0;
}

int request_managed(const std::string &hex) {
  std::vector<uint8_t> bytes;
  if (!hex_decode(hex, bytes)) {
    return 2;
  }
  ManualClock clock{123};
  TxCapture tx;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, read_clock, &clock, nullptr, 0);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, &tx, false);
  const uint32_t endpoints[] = {SEDS_EP_RADIO};
  const float values[3] = {101.0f, 102.0f, 103.0f};
  SedsPacketView pkt{
      .ty = SEDS_DT_GPS_DATA,
      .data_size = sizeof(values),
      .sender = "CPP_MANAGED_SOURCE",
      .sender_len = 18,
      .endpoints = endpoints,
      .num_endpoints = 1,
      .timestamp = 123,
      .payload = reinterpret_cast<const uint8_t *>(values),
      .payload_len = sizeof(values),
  };
  uint8_t packed[1024];
  const int32_t packed_len = seds_pkt_pack(&pkt, packed, sizeof(packed));
  if (side < 0 || packed_len <= 0 ||
      seds_router_enable_network_variable(router, SEDS_DT_GPS_DATA, true, true) != SEDS_OK ||
      seds_router_seed_managed_variable_packed(router, packed, static_cast<size_t>(packed_len)) != SEDS_OK ||
      seds_router_receive_serialized_from_side(router, static_cast<uint32_t>(side), bytes.data(), bytes.size()) != SEDS_OK ||
      seds_router_process_tx_queue(router) != SEDS_OK) {
    seds_router_free(router);
    return 2;
  }
  for (const auto &frame : tx.frames) {
    if (is_reliable_gps_data(frame)) {
      std::cout << hex_encode(frame) << "\n";
    }
  }
  seds_router_free(router);
  return 0;
}

int emit_p2p() {
  TxCapture tx;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, nullptr, nullptr, nullptr, 0);
  seds_router_set_sender_id(router, "cpp-p2p", 7);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, &tx, false);
  uint32_t address = 0;
  const uint8_t payload[] = "cpp-p2p";
  if (side < 0 || seds_router_current_address(router, &address) != SEDS_OK ||
      seds_router_send_p2p_to_address(router, address, 777, 49152, payload, sizeof(payload) - 1) != SEDS_OK ||
      seds_router_process_tx_queue(router) != SEDS_OK || tx.frames.empty()) {
    seds_router_free(router);
    return 2;
  }
  std::cout << hex_encode(tx.frames.back()) << "\n";
  seds_router_free(router);
  return 0;
}

int consume_p2p(const std::string &hex) {
  std::vector<uint8_t> bytes;
  if (!hex_decode(hex, bytes)) {
    return 2;
  }
  P2pCapture capture;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, nullptr, nullptr, nullptr, 0);
  seds_router_set_sender_id(router, "cpp-p2p-consumer", 16);
  if (seds_router_bind_p2p_port(router, 777, capture_p2p, &capture) != SEDS_OK ||
      seds_router_receive_serialized(router, bytes.data(), bytes.size()) != SEDS_OK || !capture.seen) {
    seds_router_free(router);
    return 2;
  }
  std::cout << capture.payload << "\n";
  seds_router_free(router);
  return 0;
}

int emit_p2p_stream_syn() {
  TxCapture tx;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, nullptr, nullptr, nullptr, 0);
  seds_router_set_sender_id(router, "cpp-stream", 10);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, &tx, false);
  uint32_t address = 0;
  uint32_t stream = 0;
  if (side < 0 || seds_router_current_address(router, &address) != SEDS_OK ||
      seds_router_open_p2p_stream_to_address(router, address, 8080, 49200, &stream) != SEDS_OK ||
      stream == 0 || seds_router_process_tx_queue(router) != SEDS_OK || tx.frames.empty()) {
    seds_router_free(router);
    return 2;
  }
  std::cout << hex_encode(tx.frames.back()) << "\n";
  seds_router_free(router);
  return 0;
}

int accept_p2p_stream(const std::string &hex) {
  std::vector<uint8_t> bytes;
  if (!hex_decode(hex, bytes)) {
    return 2;
  }
  TxCapture tx;
  P2pStreamCapture capture;
  SedsRouter *router = seds_router_new(Seds_RM_Sink, nullptr, nullptr, nullptr, 0);
  seds_router_set_sender_id(router, "cpp-stream-server", 17);
  const int32_t side = seds_router_add_side_serialized(router, "peer", 4, capture_tx, &tx, false);
  if (side < 0 || seds_router_bind_p2p_stream_port(router, 8080, capture_p2p_stream, &capture) != SEDS_OK ||
      seds_router_receive_serialized(router, bytes.data(), bytes.size()) != SEDS_OK ||
      seds_router_process_tx_queue(router) != SEDS_OK || !capture.accepted || tx.frames.empty()) {
    seds_router_free(router);
    return 2;
  }
  std::cout << "accepted\n";
  for (const auto &frame : tx.frames) {
    std::cout << hex_encode(frame) << "\n";
  }
  seds_router_free(router);
  return 0;
}

void print_relay_frames(const char *prefix, const TxCapture &capture) {
  for (const auto &frame : capture.frames) {
    std::cout << prefix << " " << hex_encode(frame) << "\n";
  }
}

int relay_session() {
  ManualClock clock{123};
  TxCapture to_source;
  TxCapture to_dest;
  SedsRelay *relay = seds_relay_new(read_clock, &clock);
  const int32_t source =
      seds_relay_add_side_serialized(relay, "source", 6, capture_tx, &to_source, true);
  const int32_t dest = seds_relay_add_side_serialized(relay, "dest", 4, capture_tx, &to_dest, true);
  if (source < 0 || dest < 0) {
    seds_relay_free(relay);
    return 2;
  }

  std::string data_hex;
  if (!std::getline(std::cin, data_hex)) {
    seds_relay_free(relay);
    return 2;
  }
  std::vector<uint8_t> data;
  if (!hex_decode(data_hex, data) ||
      seds_relay_rx_serialized_from_side(relay, static_cast<uint32_t>(source), data.data(), data.size()) != SEDS_OK ||
      seds_relay_process_all_queues(relay) != SEDS_OK || to_source.frames.empty() || to_dest.frames.empty()) {
    seds_relay_free(relay);
    return 2;
  }
  print_relay_frames("SRC", to_source);
  print_relay_frames("DST", to_dest);
  std::cout << "END\n" << std::flush;
  to_source.frames.clear();
  to_dest.frames.clear();

  std::string ack_hex;
  while (std::getline(std::cin, ack_hex)) {
    if (ack_hex.empty()) {
      continue;
    }
    std::vector<uint8_t> ack;
    if (!hex_decode(ack_hex, ack) ||
        seds_relay_rx_serialized_from_side(relay, static_cast<uint32_t>(dest), ack.data(), ack.size()) != SEDS_OK ||
        seds_relay_process_all_queues(relay) != SEDS_OK) {
      seds_relay_free(relay);
      return 2;
    }
  }
  print_relay_frames("SRC", to_source);
  print_relay_frames("DST", to_dest);
  std::cout << "END\n";
  seds_relay_free(relay);
  return 0;
}

int relay_forward(int argc, char **argv) {
  TxCapture to_dest;
  SedsRelay *relay = seds_relay_new(nullptr, nullptr);
  const int32_t source = seds_relay_add_side_serialized(relay, "source", 6, capture_tx, nullptr, false);
  const int32_t dest = seds_relay_add_side_serialized(relay, "dest", 4, capture_tx, &to_dest, false);
  if (source < 0 || dest < 0) {
    seds_relay_free(relay);
    return 2;
  }
  for (int i = 2; i < argc; ++i) {
    std::vector<uint8_t> bytes;
    if (!decode_arg(argv[i], bytes)) {
      seds_relay_free(relay);
      return 2;
    }
    if (seds_relay_rx_serialized_from_side(relay, static_cast<uint32_t>(source), bytes.data(), bytes.size()) ==
        SEDS_OK) {
      static_cast<void>(seds_relay_process_all_queues(relay));
    }
  }
  if (to_dest.frames.empty()) {
    seds_relay_free(relay);
    return 2;
  }
  for (const auto &frame : to_dest.frames) {
    std::cout << hex_encode(frame) << "\n";
  }
  seds_relay_free(relay);
  return 0;
}

}  // namespace

int main(int argc, char **argv) {
  const std::string cmd = argc >= 2 ? argv[1] : "";
  if (argc == 2 && cmd == "emit") {
    return emit_frame();
  }
  if (argc == 3 && cmd == "consume") {
    return consume_frame(argv[2]);
  }
  if (argc == 3 && cmd == "consume-reliable") {
    return consume_reliable(argv[2]);
  }
  if (argc == 2 && cmd == "reliable-session") {
    return reliable_session();
  }
  if (argc == 2 && cmd == "emit-discovery") {
    return emit_discovery();
  }
  if (argc >= 3 && cmd == "consume-discovery") {
    return consume_discovery(argc, argv);
  }
  if (argc == 2 && cmd == "emit-timesync") {
    return emit_timesync();
  }
  if (argc >= 3 && cmd == "consume-timesync") {
    return consume_timesync(argc, argv);
  }
  if (argc == 2 && cmd == "emit-managed") {
    return emit_managed();
  }
  if (argc == 3 && cmd == "consume-managed") {
    return consume_managed(argv[2]);
  }
  if (argc == 2 && cmd == "emit-managed-request") {
    return emit_managed_request();
  }
  if (argc == 3 && cmd == "request-managed") {
    return request_managed(argv[2]);
  }
  if (argc == 2 && cmd == "emit-p2p") {
    return emit_p2p();
  }
  if (argc == 3 && cmd == "consume-p2p") {
    return consume_p2p(argv[2]);
  }
  if (argc == 2 && cmd == "emit-p2p-stream-syn") {
    return emit_p2p_stream_syn();
  }
  if (argc == 3 && cmd == "accept-p2p-stream") {
    return accept_p2p_stream(argv[2]);
  }
  if (argc == 2 && cmd == "relay-session") {
    return relay_session();
  }
  if (argc >= 3 && cmd == "relay-forward") {
    return relay_forward(argc, argv);
  }
  std::cerr << "usage: rust_interop_cpp_peer <command>\n";
  return 2;
}
