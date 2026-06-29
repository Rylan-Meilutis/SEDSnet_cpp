#ifndef SEDSNET_C_WRAPPER_H
#define SEDSNET_C_WRAPPER_H

#include "sedsnet.h"
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct SedsWrapperRouterConfig
{
    SedsRouterMode mode;
    SedsNowMsFn now_ms;
    void * now_user;
    const SedsLocalEndpointDesc * handlers;
    size_t num_handlers;
    SedsName sender;
    uint8_t e2e_mode;
    uint32_t e2e_key_id;

    bool configure_timesync;
    uint32_t timesync_role;
    uint64_t timesync_priority;
    uint64_t timesync_source_timeout_ms;
    uint64_t timesync_announce_interval_ms;
    uint64_t timesync_request_interval_ms;

    bool announce_discovery;
} SedsWrapperRouterConfig;

typedef struct SedsWrapperRouter
{
    SedsRouter * router;
    uint8_t created;
    uint64_t start_time_ms;
    SedsSideRef primary_side;
    int32_t init_error;
} SedsWrapperRouter;

typedef struct SedsWrapperRelayConfig
{
    SedsNowMsFn now_ms;
    void * now_user;
    SedsName sender;
    bool announce_discovery;
} SedsWrapperRelayConfig;

typedef struct SedsWrapperRelay
{
    SedsRelay * relay;
    uint8_t created;
    SedsSideRef primary_side;
    int32_t init_error;
} SedsWrapperRelay;

SedsWrapperRouterConfig seds_wrapper_router_default_config(void);
SedsWrapperRelayConfig seds_wrapper_relay_default_config(void);

SedsResult seds_wrapper_router_init(SedsWrapperRouter * node,
                                    const SedsWrapperRouterConfig * cfg);
void seds_wrapper_router_free(SedsWrapperRouter * node);

SedsRouter * seds_wrapper_router_handle(SedsWrapperRouter * node);
int32_t seds_wrapper_router_init_error(const SedsWrapperRouter * node);
SedsRouter * seds_global_router_handle(void);
int32_t seds_global_router_init_error(void);
SedsResult seds_global_router_init(const SedsWrapperRouterConfig * cfg);
void seds_global_router_free(void);

SedsSideRef seds_wrapper_router_add_packed_side(SedsWrapperRouter * node,
                                                    SedsName name,
                                                    SedsTransmitFn tx,
                                                    void * tx_user,
                                                    bool reliable_enabled);
SedsSideRef seds_wrapper_router_add_packed_small_side(SedsWrapperRouter * node,
                                                          SedsName name,
                                                          SedsTransmitFn tx,
                                                          void * tx_user,
                                                          bool reliable_enabled,
                                                          size_t max_frame_bytes);
SedsSideRef seds_wrapper_router_add_packet_side(SedsWrapperRouter * node,
                                                SedsName name,
                                                SedsEndpointHandlerFn tx,
                                                void * tx_user,
                                                bool reliable_enabled);
SedsSideRef seds_global_router_add_packed_side(SedsName name,
                                                   SedsTransmitFn tx,
                                                   void * tx_user,
                                                   bool reliable_enabled);
SedsSideRef seds_global_router_add_packed_small_side(SedsName name,
                                                         SedsTransmitFn tx,
                                                         void * tx_user,
                                                         bool reliable_enabled,
                                                         size_t max_frame_bytes);
SedsSideRef seds_global_router_add_packet_side(SedsName name,
                                               SedsEndpointHandlerFn tx,
                                               void * tx_user,
                                               bool reliable_enabled);
SedsResult seds_global_router_remove_side(SedsSideRef side);
SedsResult seds_global_router_set_side_ingress_enabled(SedsSideRef side, bool enabled);
SedsResult seds_global_router_set_side_egress_enabled(SedsSideRef side, bool enabled);
SedsResult seds_global_router_set_route(SedsSideRef src_side, SedsSideRef dst_side, bool enabled);
SedsResult seds_global_router_clear_route(SedsSideRef src_side, SedsSideRef dst_side);
SedsResult seds_global_router_set_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side, bool enabled);
SedsResult seds_global_router_clear_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side);
SedsResult seds_global_router_set_source_route_mode(SedsSideRef src_side, SedsRouteSelectionMode mode);
SedsResult seds_global_router_clear_source_route_mode(SedsSideRef src_side);
SedsResult seds_global_router_set_route_weight(SedsSideRef src_side, SedsSideRef dst_side, uint32_t weight);
SedsResult seds_global_router_clear_route_weight(SedsSideRef src_side, SedsSideRef dst_side);
SedsResult seds_global_router_set_route_priority(SedsSideRef src_side, SedsSideRef dst_side, uint32_t priority);
SedsResult seds_global_router_clear_route_priority(SedsSideRef src_side, SedsSideRef dst_side);

SedsResult seds_wrapper_router_rx_packed(SedsWrapperRouter * node,
                                             const uint8_t * bytes,
                                             size_t len);
SedsResult seds_wrapper_router_rx_packed_from_side(SedsWrapperRouter * node,
                                                       SedsSideRef side,
                                                       const uint8_t * bytes,
                                                       size_t len);
SedsResult seds_global_router_rx_packed(const uint8_t * bytes, size_t len);
SedsResult seds_global_router_rx_packed_from_side(SedsSideRef side,
                                                      const uint8_t * bytes,
                                                      size_t len);

SedsResult seds_wrapper_router_process(SedsWrapperRouter * node, uint32_t timeout_ms);
SedsResult seds_wrapper_router_periodic(SedsWrapperRouter * node, uint32_t timeout_ms);
SedsResult seds_wrapper_router_poll_timesync(SedsWrapperRouter * node, bool * out_did_queue);
SedsResult seds_wrapper_router_announce_discovery(SedsWrapperRouter * node);
SedsResult seds_wrapper_router_announce_leave(SedsWrapperRouter * node);
SedsResult seds_wrapper_router_poll_discovery(SedsWrapperRouter * node, bool * out_did_queue);
SedsResult seds_wrapper_router_enable_managed_variable(SedsWrapperRouter * node, SedsTypeRef ty);
SedsResult seds_wrapper_router_enable_network_variable(SedsWrapperRouter * node,
                                                       SedsTypeRef ty,
                                                       bool can_read,
                                                       bool can_write);
SedsResult seds_wrapper_router_on_network_variable_update(SedsWrapperRouter * node,
                                                          SedsTypeRef ty,
                                                          SedsEndpointHandlerFn cb,
                                                          void * user);
void seds_wrapper_router_disable_managed_variable(SedsWrapperRouter * node, SedsTypeRef ty);
SedsResult seds_wrapper_router_request_managed_variable(SedsWrapperRouter * node, SedsTypeRef ty);
SedsResult seds_wrapper_router_set_network_variable_packed(SedsWrapperRouter * node,
                                                               const uint8_t * bytes,
                                                               size_t len);
SedsResult seds_wrapper_router_seed_managed_variable_packed(SedsWrapperRouter * node,
                                                                const uint8_t * bytes,
                                                                size_t len);
int32_t seds_wrapper_router_cached_managed_variable_packed_len(SedsWrapperRouter * node,
                                                                   SedsTypeRef ty);
int32_t seds_wrapper_router_cached_managed_variable_packed(SedsWrapperRouter * node,
                                                               SedsTypeRef ty,
                                                               uint8_t * out,
                                                               size_t out_len);
int32_t seds_wrapper_router_get_network_variable_packed_len(SedsWrapperRouter * node,
                                                                SedsTypeRef ty,
                                                                uint32_t stale_after_ms);
int32_t seds_wrapper_router_get_network_variable_packed(SedsWrapperRouter * node,
                                                            SedsTypeRef ty,
                                                            uint32_t stale_after_ms,
                                                            uint8_t * out,
                                                            size_t out_len);
SedsResult seds_global_router_process(uint32_t timeout_ms);
SedsResult seds_global_router_periodic(uint32_t timeout_ms);
SedsResult seds_global_router_periodic_no_timesync(uint32_t timeout_ms);
SedsResult seds_global_router_poll_timesync(bool * out_did_queue);
SedsResult seds_global_router_announce_discovery(void);
SedsResult seds_global_router_announce_leave(void);
SedsResult seds_global_router_poll_discovery(bool * out_did_queue);
SedsResult seds_global_router_enable_managed_variable(SedsTypeRef ty);
SedsResult seds_global_router_enable_network_variable(SedsTypeRef ty, bool can_read, bool can_write);
SedsResult seds_global_router_on_network_variable_update(SedsTypeRef ty,
                                                         SedsEndpointHandlerFn cb,
                                                         void * user);
void seds_global_router_disable_managed_variable(SedsTypeRef ty);
SedsResult seds_global_router_request_managed_variable(SedsTypeRef ty);
SedsResult seds_global_router_set_network_variable_packed(const uint8_t * bytes, size_t len);
SedsResult seds_global_router_seed_managed_variable_packed(const uint8_t * bytes, size_t len);
int32_t seds_global_router_cached_managed_variable_packed_len(SedsTypeRef ty);
int32_t seds_global_router_cached_managed_variable_packed(SedsTypeRef ty,
                                                              uint8_t * out,
                                                              size_t out_len);
int32_t seds_global_router_get_network_variable_packed_len(SedsTypeRef ty,
                                                               uint32_t stale_after_ms);
int32_t seds_global_router_get_network_variable_packed(SedsTypeRef ty,
                                                           uint32_t stale_after_ms,
                                                           uint8_t * out,
                                                           size_t out_len);
SedsResult seds_global_router_get_network_time_ms(uint64_t * out_ms);
SedsResult seds_global_router_get_network_time(SedsNetworkTime * out);
int32_t seds_global_router_export_topology_len(void);
SedsResult seds_global_router_export_topology(char * buf, size_t buf_len);
int32_t seds_global_router_export_client_stats_len(SedsName sender);
SedsResult seds_global_router_export_client_stats(SedsName sender, char * buf, size_t buf_len);
int32_t seds_global_router_export_runtime_stats_len(void);
SedsResult seds_global_router_export_runtime_stats(char * buf, size_t buf_len);
int32_t seds_global_router_export_memory_layout_len(void);
SedsResult seds_global_router_export_memory_layout(char * buf, size_t buf_len);

SedsResult seds_wrapper_router_log_typed(SedsWrapperRouter * node,
                                         SedsTypeRef ty,
                                         const void * data,
                                         size_t count,
                                         size_t elem_size,
                                         SedsElemKind elem_kind,
                                         const uint64_t * timestamp_ms_opt,
                                         int queue);
SedsResult seds_wrapper_router_log_string(SedsWrapperRouter * node,
                                          SedsTypeRef ty,
                                          const char * text,
                                          const uint64_t * timestamp_ms_opt,
                                          int queue);
SedsResult seds_global_router_log_typed(SedsTypeRef ty,
                                        const void * data,
                                        size_t count,
                                        size_t elem_size,
                                        SedsElemKind elem_kind,
                                        const uint64_t * timestamp_ms_opt,
                                        int queue);
SedsResult seds_global_router_log_string(SedsTypeRef ty,
                                         const char * text,
                                         const uint64_t * timestamp_ms_opt,
                                         int queue);

SedsResult seds_wrapper_relay_init(SedsWrapperRelay * node,
                                   const SedsWrapperRelayConfig * cfg);
void seds_wrapper_relay_free(SedsWrapperRelay * node);
SedsRelay * seds_wrapper_relay_handle(SedsWrapperRelay * node);
int32_t seds_wrapper_relay_init_error(const SedsWrapperRelay * node);
SedsRelay * seds_global_relay_handle(void);
int32_t seds_global_relay_init_error(void);
SedsResult seds_global_relay_init(const SedsWrapperRelayConfig * cfg);
void seds_global_relay_free(void);

SedsSideRef seds_wrapper_relay_add_packed_side(SedsWrapperRelay * node,
                                                   SedsName name,
                                                   SedsTransmitFn tx,
                                                   void * tx_user,
                                                   bool reliable_enabled);
SedsSideRef seds_wrapper_relay_add_packed_small_side(SedsWrapperRelay * node,
                                                         SedsName name,
                                                         SedsTransmitFn tx,
                                                         void * tx_user,
                                                         bool reliable_enabled,
                                                         size_t max_frame_bytes);
SedsSideRef seds_wrapper_relay_add_packet_side(SedsWrapperRelay * node,
                                               SedsName name,
                                               SedsEndpointHandlerFn tx,
                                               void * tx_user,
                                               bool reliable_enabled);
SedsSideRef seds_global_relay_add_packed_side(SedsName name,
                                                  SedsTransmitFn tx,
                                                  void * tx_user,
                                                  bool reliable_enabled);
SedsSideRef seds_global_relay_add_packed_small_side(SedsName name,
                                                        SedsTransmitFn tx,
                                                        void * tx_user,
                                                        bool reliable_enabled,
                                                        size_t max_frame_bytes);
SedsSideRef seds_global_relay_add_packet_side(SedsName name,
                                              SedsEndpointHandlerFn tx,
                                              void * tx_user,
                                              bool reliable_enabled);

SedsResult seds_wrapper_relay_rx_packed_from_side(SedsWrapperRelay * node,
                                                      SedsSideRef side,
                                                      const uint8_t * bytes,
                                                      size_t len);
SedsResult seds_wrapper_relay_rx_packet_from_side(SedsWrapperRelay * node,
                                                  SedsSideRef side,
                                                  const SedsPacketView * view);
SedsResult seds_global_relay_rx_packed_from_side(SedsSideRef side,
                                                     const uint8_t * bytes,
                                                     size_t len);
SedsResult seds_global_relay_rx_packet_from_side(SedsSideRef side,
                                                 const SedsPacketView * view);

SedsResult seds_wrapper_relay_process(SedsWrapperRelay * node, uint32_t timeout_ms);
SedsResult seds_wrapper_relay_periodic(SedsWrapperRelay * node, uint32_t timeout_ms);
SedsResult seds_wrapper_relay_announce_discovery(SedsWrapperRelay * node);
SedsResult seds_wrapper_relay_announce_leave(SedsWrapperRelay * node);
SedsResult seds_wrapper_relay_poll_discovery(SedsWrapperRelay * node, bool * out_did_queue);
SedsResult seds_global_relay_process(uint32_t timeout_ms);
SedsResult seds_global_relay_periodic(uint32_t timeout_ms);
SedsResult seds_global_relay_announce_discovery(void);
SedsResult seds_global_relay_announce_leave(void);
SedsResult seds_global_relay_poll_discovery(bool * out_did_queue);
int32_t seds_global_relay_export_topology_len(void);
SedsResult seds_global_relay_export_topology(char * buf, size_t buf_len);
int32_t seds_global_relay_export_client_stats_len(SedsName sender);
SedsResult seds_global_relay_export_client_stats(SedsName sender, char * buf, size_t buf_len);
int32_t seds_global_relay_export_runtime_stats_len(void);
SedsResult seds_global_relay_export_runtime_stats(char * buf, size_t buf_len);
int32_t seds_global_relay_export_memory_layout_len(void);
SedsResult seds_global_relay_export_memory_layout(char * buf, size_t buf_len);

SedsResult seds_global_relay_remove_side(SedsSideRef side);
SedsResult seds_global_relay_set_side_ingress_enabled(SedsSideRef side, bool enabled);
SedsResult seds_global_relay_set_side_egress_enabled(SedsSideRef side, bool enabled);
SedsResult seds_global_relay_set_route(SedsSideRef src_side, SedsSideRef dst_side, bool enabled);
SedsResult seds_global_relay_clear_route(SedsSideRef src_side, SedsSideRef dst_side);
SedsResult seds_global_relay_set_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side, bool enabled);
SedsResult seds_global_relay_clear_typed_route(SedsSideRef src_side, SedsTypeRef ty, SedsSideRef dst_side);
SedsResult seds_global_relay_set_source_route_mode(SedsSideRef src_side, SedsRouteSelectionMode mode);
SedsResult seds_global_relay_clear_source_route_mode(SedsSideRef src_side);
SedsResult seds_global_relay_set_route_weight(SedsSideRef src_side, SedsSideRef dst_side, uint32_t weight);
SedsResult seds_global_relay_clear_route_weight(SedsSideRef src_side, SedsSideRef dst_side);
SedsResult seds_global_relay_set_route_priority(SedsSideRef src_side, SedsSideRef dst_side, uint32_t priority);
SedsResult seds_global_relay_clear_route_priority(SedsSideRef src_side, SedsSideRef dst_side);

#ifdef __cplusplus
}
#endif

#endif
