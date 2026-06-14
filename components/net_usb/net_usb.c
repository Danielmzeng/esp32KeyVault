#include "net_usb.h"
#include "esp_netif.h"
#include "tinyusb.h"
#include "tinyusb_net.h"
#include "esp_mac.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

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

esp_err_t net_usb_start(void)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);

    /* Custom esp-netif config: static IP, no DHCP client, we run a DHCP server. */
    esp_netif_inherent_config_t base = ESP_NETIF_INHERENT_DEFAULT_ETH();
    base.if_desc = "usb";
    base.route_prio = 10;
    base.flags = ESP_NETIF_DHCP_SERVER | ESP_NETIF_FLAG_AUTOUP;

    esp_netif_ip_info_t ip = {0};
    ip.ip.addr      = ESP_IP4TOADDR(10, 10, 0, 1);
    ip.gw.addr      = ESP_IP4TOADDR(10, 10, 0, 1);
    ip.netmask.addr = ESP_IP4TOADDR(255, 255, 255, 0);
    base.ip_info = &ip;

    esp_netif_config_t cfg = {
        .base   = &base,
        .driver = NULL,
        .stack  = ESP_NETIF_NETSTACK_DEFAULT_ETH,
    };
    s_usb_netif = esp_netif_new(&cfg);

    esp_netif_driver_ifconfig_t drv = {
        .handle = (void *)1,
        .transmit = netif_transmit,
        .driver_free_rx_buffer = l2_free,
    };
    ESP_ERROR_CHECK(esp_netif_set_driver_config(s_usb_netif, &drv));

    const tinyusb_config_t tusb_cfg = { .external_phy = false };
    ESP_ERROR_CHECK(tinyusb_driver_install(&tusb_cfg));

    tinyusb_net_config_t net_cfg = {
        .on_recv_callback = rx_cb,
    };
    memcpy(net_cfg.mac_addr, mac, 6);
    ESP_ERROR_CHECK(tinyusb_net_init(TINYUSB_USBDEV_0, &net_cfg));

    /* Bring the interface up AND mark the link connected. Unlike the Wi-Fi AP,
     * this hand-rolled driver has no event handlers to drive the lifecycle, so
     * without action_connected the netif stays "started but not connected" and
     * the DHCP server never starts -> the USB host gets no 10.10.0.x lease. */
    esp_netif_action_start(s_usb_netif, NULL, 0, NULL);
    esp_netif_action_connected(s_usb_netif, NULL, 0, NULL);
    return ESP_OK;
}
