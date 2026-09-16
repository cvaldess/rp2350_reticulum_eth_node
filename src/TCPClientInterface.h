// microReticulum interface that connects to a Reticulum TCPServerInterface over the W5500.
//
// Wire format is the reference implementation's (RNS/Interfaces/TCPInterface.py): every packet
// is HDLC-framed, FLAG + escape(data) + FLAG, where 0x7E/0x7D inside the data become
// 0x7D followed by the byte XOR 0x20. No handshake; frames flow as soon as the socket is up.
// The initiator (us) reconnects every RECONNECT_WAIT_MS while the socket is down.
#pragma once

#include <Arduino.h>
#include <Ethernet.h>
#include <microReticulum.h>

class TCPClientInterface : public RNS::InterfaceImpl
{
  public:
    static constexpr uint8_t HDLC_FLAG = 0x7E;
    static constexpr uint8_t HDLC_ESC = 0x7D;
    static constexpr uint8_t HDLC_ESC_MASK = 0x20;
    // Reticulum packets are 500 bytes; this leaves room for an IFAC and matches the library's UDP interface.
    static constexpr uint16_t MTU = 1064;
    static constexpr uint32_t BITRATE_GUESS = 10 * 1000 * 1000;
    static constexpr uint32_t RECONNECT_WAIT_MS = 5000;
    static constexpr uint16_t CONNECT_TIMEOUT_MS = 3000;

    TCPClientInterface(const char *name, IPAddress host, uint16_t port);
    virtual ~TCPClientInterface();

    bool connected() { return _client.connected(); }
    uint32_t reconnects() const { return _reconnects; }

  protected:
    virtual bool start() override;
    virtual void stop() override;
    virtual void loop() override;
    virtual bool send_outgoing(const RNS::Bytes &data) override;

  private:
    bool tryConnect();
    void dropConnection(const char *why);
    void readAvailable();
    void feed(uint8_t byte);

    EthernetClient _client;
    IPAddress _host;
    uint16_t _port;
    uint32_t _lastAttempt = 0;
    uint32_t _reconnects = 0;
    bool _wasConnected = false;  // socket was up on the previous loop pass
    bool _everConnected = false; // at least one successful connect since boot

    // HDLC receive state
    bool _inFrame = false;
    bool _escape = false;
    RNS::Bytes _rx;
};
