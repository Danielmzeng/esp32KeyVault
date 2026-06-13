#include "unity.h"
#include "vault_session.h"
#include <string.h>

TEST_CASE("token validates, expires on idle, dies on logout", "[vault_session]")
{
    vsess_reset();
    char tok[VS_TOKEN_HEX];
    vsess_create(1000, tok);
    TEST_ASSERT_TRUE(vsess_validate(tok, 1000 + VS_IDLE_MS - 1));
    /* validation refreshed the timer at the above call; advance from there */
    TEST_ASSERT_FALSE(vsess_validate(tok, 1000 + 2 * VS_IDLE_MS + 10));

    vsess_create(1, tok);
    TEST_ASSERT_TRUE(vsess_validate(tok, 2));
    vsess_destroy();
    TEST_ASSERT_FALSE(vsess_validate(tok, 3));
}

TEST_CASE("bad token never validates", "[vault_session]")
{
    vsess_reset();
    char tok[VS_TOKEN_HEX]; vsess_create(1, tok);
    TEST_ASSERT_FALSE(vsess_validate("deadbeef", 2));
    TEST_ASSERT_FALSE(vsess_validate("", 2));
}

TEST_CASE("login lockout after repeated failures, clears after window", "[vault_session]")
{
    vsess_reset();
    for (int i = 0; i < VS_MAX_FAILS; i++) {
        TEST_ASSERT_TRUE(vsess_login_allowed(0));
        vsess_note_login_result(false, 0);
    }
    TEST_ASSERT_FALSE(vsess_login_allowed(0));               /* locked out */
    TEST_ASSERT_FALSE(vsess_login_allowed(VS_LOCKOUT_MS - 1));
    TEST_ASSERT_TRUE(vsess_login_allowed(VS_LOCKOUT_MS + 1)); /* window passed */

    vsess_note_login_result(true, VS_LOCKOUT_MS + 1);        /* success resets */
    TEST_ASSERT_TRUE(vsess_login_allowed(VS_LOCKOUT_MS + 2));
}
