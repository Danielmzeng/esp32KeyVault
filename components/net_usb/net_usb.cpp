#include "net_usb.h"
#include "vault_error.h"
#include "esp_netif.h"
#include "tinyusb.h"
#include "tinyusb_net.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

namespace vault {

static esp_netif_t *s_usb_netif;

/* Glue: TinyUSB -> esp_netif (host->device frames). */
static esp_err_t rx_cb(void *buffer, uint16_t len, void *ctx)
{
    return esp_netif_receive(s_usb_netif, buffer, len, NULL);
}

/* Glue: esp_netif -> TinyUSB (device->host frames). */
static esp_err_t netif_transmit(void *h, void *buffer, size_t len)
{
    return tinyusb_net_send_sync(buffer, len, NULL, portMAX_DELAY);
}

static void l2_free(void *h, void *buffer) { (void)h; (void)buffer; }

void UsbNet::start()
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    /* Custom esp-netif config: static IP, no DHCP client, we run a DHCP server. */
    esp_netif_inherent_config_t base = ESP_NETIF_INHERENT_DEFAULT_ETH();
    base.if_desc = "usb";
    base.route_prio = 10;
    base.flags = (esp_netif_flags_t)(ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP);

    esp_netif_ip_info_t ip = {};
    ip.ip.addr      = ESP_IP4TOADDR(10, 10, 0, 1);
    ip.gw.addr      = ESP_IP4TOADDR(10, 10, 0, 1);
    ip.netmask.addr = ESP_IP4TOADDR(255, 255, 255, 0);
    base.ip_info = &ip;

    esp_netif_config_t cfg = {};
    cfg.base   = &base;
    cfg.driver = nullptr;
    cfg.stack  = ESP_NETIF_NETSTACK_DEFAULT_ETH;
    s_usb_netif = esp_netif_new(&cfg);

    esp_netif_driver_ifconfig_t drv = {};
    drv.handle = (void *)1;
    drv.transmit = netif_transmit;
    drv.driver_free_rx_buffer = l2_free;
    check(esp_netif_set_driver_config(s_usb_netif, &drv), "usb netif driver");

    tinyusb_config_t tusb_cfg = {};
    tusb_cfg.external_phy = false;
    check(tinyusb_driver_install(&tusb_cfg), "tinyusb install");

    tinyusb_net_config_t net_cfg = {};
    net_cfg.on_recv_callback = rx_cb;
    memcpy(net_cfg.mac_addr, mac, 6);
    check(tinyusb_net_init(TINYUSB_USBDEV_0, &net_cfg), "tinyusb net init");

    /* Bring the interface up AND mark the link connected. Unlike the Wi-Fi AP,
     * this hand-rolled driver has no event handlers to drive the lifecycle, so
     * without action_connected the netif stays "started but not connected" and
     * the DHCP server never starts -> the USB host gets no 10.10.0.x lease. */
    esp_netif_action_start(s_usb_netif, NULL, 0, NULL);
    esp_netif_action_connected(s_usb_netif, NULL, 0, NULL);
}

}  // namespace vault
