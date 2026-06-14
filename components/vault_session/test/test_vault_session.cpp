#include "doctest/doctest.h"
#include "vault_session.h"
#include <cstring>

using namespace vault;

TEST_CASE("token validates, expires on idle, dies on logout") {
    Session s;
    char tok[VS_TOKEN_HEX];
    s.create(1000, tok);
    CHECK(s.validate(tok, 1000 + VS_IDLE_DEFAULT_MS - 1));
    CHECK_FALSE(s.validate(tok, 1000 + 2 * VS_IDLE_DEFAULT_MS + 10));

    s.create(1, tok);
    CHECK(s.validate(tok, 2));
    s.destroy();
    CHECK_FALSE(s.validate(tok, 3));
}

TEST_CASE("bad token never validates") {
    Session s;
    char tok[VS_TOKEN_HEX]; s.create(1, tok);
    CHECK_FALSE(s.validate("deadbeef", 2));
    CHECK_FALSE(s.validate("", 2));
}

TEST_CASE("login lockout after repeated failures, clears after window") {
    Session s;
    for (int i = 0; i < VS_MAX_FAILS; i++) {
        CHECK(s.login_allowed(0));
        s.note_login_result(false, 0);
    }
    CHECK_FALSE(s.login_allowed(0));
    CHECK_FALSE(s.login_allowed(VS_LOCKOUT_MS - 1));
    CHECK(s.login_allowed(VS_LOCKOUT_MS + 1));

    s.note_login_result(true, VS_LOCKOUT_MS + 1);
    CHECK(s.login_allowed(VS_LOCKOUT_MS + 2));
}

TEST_CASE("idle window follows the runtime-configured timeout") {
    Session s;
    char tok[VS_TOKEN_HEX];
    s.set_idle_ms(30 * 1000);               // 30 s
    CHECK(s.idle_ms() == 30u * 1000);
    s.create(1000, tok);
    CHECK(s.validate(tok, 1000 + 30 * 1000 - 1));        // still inside window
    s.create(1000, tok);                                  // refresh (validate above moved last_seen)
    CHECK_FALSE(s.validate(tok, 1000 + 30 * 1000 + 10)); // past the 30 s window
}

TEST_CASE("set_idle_ms clamps to [MIN, MAX]") {
    Session s;
    s.set_idle_ms(1);                       // below 30 s floor
    CHECK(s.idle_ms() == VS_IDLE_MIN_MS);
    s.set_idle_ms(0xFFFFFFFFu);             // above 3600 s ceiling
    CHECK(s.idle_ms() == VS_IDLE_MAX_MS);
}
