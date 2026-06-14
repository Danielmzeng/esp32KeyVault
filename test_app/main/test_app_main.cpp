#define DOCTEST_CONFIG_IMPLEMENT
#include "doctest/doctest.h"
#include "esp_log.h"

extern "C" void app_main(void)
{
    doctest::Context ctx;
    ctx.setOption("no-breaks", true);   // don't try to break into a debugger on failure
    int res = ctx.run();                // runs all registered TEST_CASEs
    ESP_LOGI("doctest", "test run complete, result=%d", res);
}
