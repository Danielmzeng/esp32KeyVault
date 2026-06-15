# Configurable Idle Auto-Lock Timeout — Design

**Date:** 2026-06-14
**Status:** Approved
**Branch:** task/Vault-Adjust_webui

## Problem

The vault auto-locks after a fixed 3-minute idle window. The timeout is a
compile-time constant (`VS_IDLE_MS` in `vault_session.h`), so changing it
requires a rebuild and reflash. Users want to set their own idle timeout from
the web UI sidebar.

## Goals

- Let an authenticated (unlocked) user set the idle auto-lock timeout from the
  sidebar.
- Persist the chosen value across reboots and power loss.
- Apply the new value immediately, without forcing a re-login.
- Preserve the security guarantee that the vault **always** auto-locks (no
  "never lock" option).

## Non-Goals

- Per-session or per-user timeouts (single-user device).
- Configuring the login-lockout window (`VS_LOCKOUT_MS`) or max-fail count.

## Decisions

- **Persistence:** stored in the existing `"vault"` NVS namespace via `Store`.
- **Input unit / range:** seconds, fine-grained. Valid range **30–3600 s**
  (30 s to 60 min). Out-of-range values are rejected server-side.
- **Ownership (Approach A):** the timeout is runtime state on `Session`;
  load/save persistence is owned by `ApiServer` (which already orchestrates the
  HTTP layer and holds the `Session`). `Session` stays a pure, NVS-free unit so
  its doctest suite is unaffected.

## Architecture

### 1. `vault_session` — timeout becomes runtime state

`include/vault_session.h`:
- Rename `VS_IDLE_MS` → `VS_IDLE_DEFAULT_MS` (value unchanged: `3 * 60 * 1000`).
- Add bounds constants:
  - `VS_IDLE_MIN_MS` = `30 * 1000`
  - `VS_IDLE_MAX_MS` = `3600 * 1000`
- Add to `Session`:
  - `uint32_t idle_ms_ = VS_IDLE_DEFAULT_MS;` (private member)
  - `void set_idle_ms(uint32_t ms);` — clamps `ms` to `[VS_IDLE_MIN_MS, VS_IDLE_MAX_MS]` defensively
  - `uint32_t idle_ms() const;`

`vault_session.cpp`:
- `check_idle` and `idle_remaining_ms` use `idle_ms_` instead of `VS_IDLE_MS`.
- `set_idle_ms` clamps and stores; `idle_ms` returns the member.

### 2. `vault_api` — persistence + endpoint

`include/vault_api.h`:
- Constructor gains `Store& store`: `ApiServer(Vault&, Session&, StatusLed&, Store&)`.
- Add member `Store& store_;`.
- Add `esp_err_t h_idle_set_impl(httpd_req_t*)` and its static trampoline
  `h_idle_set`.

`vault_api.cpp`:
- In `start()`: read the `"idle_ms"` uint32 blob from `store_`; if present and
  non-zero, call `session_.set_idle_ms(v)`. Register the new URI handler.
- `h_state_impl`: report `session_.idle_ms()` for the `idle_ms` field (replaces
  the `VS_IDLE_MS` constant).
- `h_idle_set_impl` — **`POST /api/idle`**, requires auth (`authed(r)` → 401 if
  not):
  1. Parse body `{ "seconds": N }`.
  2. Reject `N < 30 || N > 3600` with `400`.
  3. `session_.set_idle_ms(N * 1000)`.
  4. Persist: `store_.set_blob("idle_ms", &ms, sizeof ms); store_.commit();`
  5. Return `200 {}`.
  - The `authed()` check refreshes `last_seen_ms_`, so the new window starts
    from "now" and the session does not instantly lock.

`main/main.cpp`:
- Pass the existing `store` into the `ApiServer` constructor.

### 3. UI — `components/vault_api/www/index.html`

- New sidebar block, placed under the existing Lock / Reset button rows:
  - A label ("Auto-lock after"), a number input (`id=idlesec`, `min=30`,
    `max=3600`, value populated from server), a "Save" button (`id=idlesave`),
    and an inline status/error line (`id=idlemsg`).
- On render, populate the input from the current `idleMs / 1000`.
- On Save click:
  - Read and bounds-check the input client-side (defense-in-depth; server is
    authoritative).
  - `POST /api/idle` with `{ seconds }`.
  - On success: update the client `idleMs` mirror to `seconds * 1000`,
    re-arm the idle timer (`armIdle()`), and show a brief confirmation.
  - On error: show the message inline.

## Data Flow

```
Save click
  → POST /api/idle {seconds}
      → authed? (refreshes last_seen)
      → validate 30..3600
      → session_.set_idle_ms(seconds*1000)
      → store_.set_blob("idle_ms") + commit
      → 200
  → client updates idleMs mirror + armIdle()

Boot
  → ApiServer.start() reads "idle_ms" blob → session_.set_idle_ms(v)

GET /api/state → idle_ms = session_.idle_ms()  (client mirrors on boot())
```

## Error Handling

- Missing/short body or bad JSON → `400 "bad json"` (matches existing handlers).
- Out-of-range seconds → `400 "timeout out of range (30-3600s)"`.
- Not authed → `401` (vault locked / no valid session).
- NVS write failure → handler's try/catch returns `500` (existing pattern); the
  in-RAM value still took effect for the current boot.
- Absent `"idle_ms"` blob at boot → keep `VS_IDLE_DEFAULT_MS`.

## Testing

`components/vault_session/test/test_vault_session.cpp` (doctest):
- Update existing references from `VS_IDLE_MS` to `VS_IDLE_DEFAULT_MS`.
- New case: after `set_idle_ms(custom)`, a token expires at the custom window,
  not the default.
- New case: `set_idle_ms` clamps below `VS_IDLE_MIN_MS` and above
  `VS_IDLE_MAX_MS`; `idle_ms()` reflects the clamped value.

Manual / on-device (post-build):
- Set a short timeout (30 s), confirm the vault locks and the UI returns to the
  unlock screen at the new window.
- Reboot, confirm the value persists (sidebar shows it; lock honors it).

## Build Verification

Both projects must still compile:
- Main firmware (`idf.py build`).
- `test_app` doctest runner (component unit tests).
