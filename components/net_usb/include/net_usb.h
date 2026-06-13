#pragma once
#include "esp_err.h"
/* Brings up a TinyUSB NCM network interface with a static IP (10.10.0.1)
 * and a DHCP server handing out 10.10.0.2+ to the host. */
esp_err_t net_usb_start(void);
