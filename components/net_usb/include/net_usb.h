#pragma once

namespace vault {

// Brings up a TinyUSB NCM interface with static IP 10.10.0.1 and a DHCP server
// handing out 10.10.0.2+ to the host.
class UsbNet {
public:
    void start();   // throws vault::Error on failure
};

}  // namespace vault
