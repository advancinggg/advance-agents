/* advance_bridge.h — CONTRACT-210 C ABI (Wave-27 C210) */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADVANCE_BRIDGE_ABI_VERSION 1

#define ADVANCE_BRIDGE_OK                 0
#define ADVANCE_BRIDGE_ERR_INVALID_ARG    1
#define ADVANCE_BRIDGE_ERR_INVALID_UTF8   2
#define ADVANCE_BRIDGE_ERR_INVALID_CONFIG 3
#define ADVANCE_BRIDGE_ERR_INVALID_WS     4
#define ADVANCE_BRIDGE_ERR_ALREADY_RUN    5
#define ADVANCE_BRIDGE_ERR_INVALID_HANDLE 6
#define ADVANCE_BRIDGE_ERR_CONFIG         7
#define ADVANCE_BRIDGE_ERR_BOOTSTRAP      8
#define ADVANCE_BRIDGE_ERR_SUPERVISE      9
#define ADVANCE_BRIDGE_ERR_TIMEOUT       10
#define ADVANCE_BRIDGE_ERR_NESTED_RT     11
#define ADVANCE_BRIDGE_ERR_BUFFER        12
#define ADVANCE_BRIDGE_ERR_INTERNAL      13

typedef struct AdvanceBridgeHandle AdvanceBridgeHandle;

/*
 * On success: *out_handle is non-null.
 * On failure: *out_handle is set to NULL (when out_handle non-null); status != 0.
 */
int32_t advance_bridge_start(
    const char *workspace_root_utf8,
    int32_t platform,          /* 0=Mac 1=Ios 2=Android 3=Windows */
    int32_t engine_mode,       /* 0=Jit 1=Interpreter */
    int32_t composition_mode,  /* 0=Embed 1=Supervise */
    const char *config_path_utf8_or_null,
    const char *supervise_command_utf8_or_null,
    int32_t supervise_kill_on_drop, /* 1=default true; 0=keep-available detach */
    const char *supervise_ready_file_utf8_or_null,
    AdvanceBridgeHandle **out_handle
);

/* Idempotent while handle pointer is live. Does NOT free memory. */
int32_t advance_bridge_stop(AdvanceBridgeHandle *handle);

/*
 * Writes NUL-terminated UTF-8 JSON into json_out when buffer is large enough.
 * On ADVANCE_BRIDGE_ERR_BUFFER: writes required size (including NUL) into
 * *required_len if non-null; does not partially write JSON.
 */
int32_t advance_bridge_health(
    const AdvanceBridgeHandle *handle,
    char *json_out,
    size_t json_out_len,
    size_t *required_len_or_null
);

/* battery_pct: 0-100, or -1 if unknown. network_class_utf8_or_null may be NULL. */
int32_t advance_bridge_on_lifecycle(
    AdvanceBridgeHandle *handle,
    int32_t lifecycle_state, /* 0=Foreground 1=Background 2=Suspended 3=Restricted */
    int32_t battery_pct,
    const char *network_class_utf8_or_null
);

/* Thread-local UTF-8; valid until next bridge call on this thread. Redacted. */
const char *advance_bridge_last_error(void);

/*
 * Terminal free. After this returns, the pointer must not be passed to any
 * bridge function (UB / must-not). No-op on NULL.
 * Embed: always stops if not already stopped.
 * Supervise: stops/reaps if supervise_kill_on_drop (default true); if false,
 * detaches without killing the child (keep-available opt-in).
 */
void advance_bridge_free_handle(AdvanceBridgeHandle *handle);

uint32_t advance_bridge_abi_version(void);

#ifdef __cplusplus
} /* extern "C" */
#endif
