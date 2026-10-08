/* advance_bridge.h — CONTRACT-210 C ABI (Wave-27 C210) */
#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ADVANCE_BRIDGE_ABI_VERSION 2

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
#define ADVANCE_BRIDGE_ERR_UNSUPPORTED   14  /* impossible on this target or by the platform table, or no Client API on this handle */
#define ADVANCE_BRIDGE_ERR_COMPOSE       15  /* composition failed; advance_bridge_last_error() has the redacted reason */

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

/* ── ABI v2 (additive) ──────────────────────────────────────────────────────────────────── */

/*
 * Starts a v2 handle: composes the workspace's runtime inside this process (embedded profile).
 * options_json_utf8_or_null: NULL (every default) or a JSON object; every key is optional:
 *   "platform"    "mac" | "ios" | "android" | "windows" | "linux"   default: the compiled target
 *                 ("linux" on a host outside this list); an ios/android build accepts only its own
 *   "composition" "full" | "host_only"                               default: "full"
 *   "engine"      "native" | "pulley"     default: "pulley" on ios/android, else "native"
 *   "processes"   "allow" | "forbid"      default: "forbid" on ios/android, else "allow"
 *   "client_api"  {"port": 0..65535} | null   default {"port": 0}; null: no Client API;
 *                                          "host_only" never has one
 *   "state_root"  absolute path outside the workspace; required by "full" on ios/android
 *   "config_path" path inside the workspace; default ".advance/runtime-config.yaml";
 *                 "full" accepts only the default
 * ios/android require "engine":"pulley" and "processes":"forbid".
 * Returns 0 with *out_handle set, or: 1 / 2 bad argument; 3 malformed JSON, unknown key or value;
 * 4 workspace; 11 called inside a Tokio runtime; 14 UNSUPPORTED; 15 COMPOSE. "host_only" answers
 * v1's codes. On failure *out_handle is NULL (when out_handle is non-NULL).
 * Every v1 function accepts a v2 handle: advance_bridge_health writes schema_version 2 (adds
 * "composition_profile", "agent_loop_up", "client_api_base"); advance_bridge_on_lifecycle with
 * Foreground re-verifies the Client API listener before it returns (bounded, about 2 s);
 * advance_bridge_stop and advance_bridge_free_handle shut the composition down.
 * After a Foreground call returns, re-read the base and the session before any request and never
 * reuse a base from before suspension; a pair read while that call runs may be the old one.
 */
int32_t advance_bridge_start_v2(const char *workspace_root_utf8,
                                const char *options_json_utf8_or_null,
                                AdvanceBridgeHandle **out_handle);

/*
 * Writes the Client API base ("http://127.0.0.1:<port>", NUL-terminated). Buffer protocol as
 * advance_bridge_health: *required_len gets the size including the NUL; ADVANCE_BRIDGE_ERR_BUFFER
 * and no partial write when out is NULL or too small. 14 when the handle has no Client API: a v1
 * or "host_only" handle, "client_api": null, a stopped handle, or a listener lost by a failed
 * foreground rebind.
 */
int32_t advance_bridge_client_api_base(const AdvanceBridgeHandle *handle, char *out,
                                       size_t out_len, size_t *required_len_or_null);

/*
 * Writes the bearer token of a session minted inside this process for this handle
 * (NUL-terminated); buffer protocol as above (a size query mints at most once; the retry returns
 * the same token). The Client API admits no login without a credential, so this is how the host
 * gets a session. The token is a credential: keep it in memory, send it only in the
 * Authorization header or the WebSocket bearer subprotocol, never write it to disk, a log or a
 * URL, and wipe the buffer after use. The same token is returned while its session has at least
 * 5 minutes left and the listener's port has not changed; otherwise a new session is minted, and
 * when the port changed every earlier session of this runtime is revoked first. 14 as for the base.
 */
int32_t advance_bridge_client_api_session(const AdvanceBridgeHandle *handle, char *out,
                                          size_t out_len, size_t *required_len_or_null);

#ifdef __cplusplus
} /* extern "C" */
#endif
