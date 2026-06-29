#include "sedsprintf.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void require_endpoint(const char *name) {
    SedsEndpointInfo info = {0};
    const size_t len = strlen(name);
    assert(seds_endpoint_get_info_by_name(name, len, &info) == SEDS_OK);
    assert(info.exists);
    assert(info.name_len == len);
    assert(strncmp(info.name, name, len) == 0);
}

static void require_type(const char *name, size_t fixed_size) {
    SedsDataTypeInfo info = {0};
    uint32_t endpoints[4] = {0};
    const size_t len = strlen(name);
    assert(seds_dtype_get_info_by_name(name, len, endpoints, 4, &info) == SEDS_OK);
    assert(info.exists);
    assert(info.name_len == len);
    assert(strncmp(info.name, name, len) == 0);
    assert(info.fixed_size == fixed_size);
    assert(info.num_endpoints == 1);
}

int main(void) {
    require_endpoint("ENV_BASE_ENDPOINT");
    require_type("ENV_BASE_TYPE", 2);
    require_endpoint("ENV_IPC_ENDPOINT");
    require_type("ENV_IPC_TYPE", 4);
    printf("runtime env schema ok\n");
    return 0;
}
