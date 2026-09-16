#include "TCPClientInterface.h"

TCPClientInterface::TCPClientInterface(const char *name, IPAddress host, uint16_t port)
    : RNS::InterfaceImpl(name), _host(host), _port(port)
{
    _IN = true;
    _OUT = true;
    _bitrate = BITRATE_GUESS;
    _HW_MTU = MTU;
}

TCPClientInterface::~TCPClientInterface()
{
    stop();
    _name = "deleted";
}

bool TCPClientInterface::start()
{
    // Connect from loop(): DHCP may not have finished when Transport starts us.
    _lastAttempt = millis() - RECONNECT_WAIT_MS;
    _online = false;
    return true;
}

void TCPClientInterface::stop()
{
    _client.stop();
    _online = false;
    _inFrame = false;
    _escape = false;
    _rx.clear();
}

void TCPClientInterface::loop()
{
    if (!_client.connected()) {
        if (_wasConnected)
            dropConnection("socket closed");
        if (millis() - _lastAttempt >= RECONNECT_WAIT_MS)
            tryConnect();
        return;
    }
    readAvailable();
}

bool TCPClientInterface::tryConnect()
{
    _lastAttempt = millis();
    if (Ethernet.linkStatus() != LinkON || Ethernet.localIP() == IPAddress(0, 0, 0, 0))
        return false;

    _client.setConnectionTimeout(CONNECT_TIMEOUT_MS);
    if (!_client.connect(_host, _port)) {
        _client.stop();
        DEBUGF("%s: connection to %u.%u.%u.%u:%u failed, retrying in %u s", toString().c_str(), _host[0], _host[1],
               _host[2], _host[3], _port, RECONNECT_WAIT_MS / 1000);
        return false;
    }
    _inFrame = false;
    _escape = false;
    _rx.clear();
    _online = true;
    if (_everConnected)
        _reconnects++;
    _everConnected = true;
    _wasConnected = true;
    INFOF("%s: connected to %u.%u.%u.%u:%u", toString().c_str(), _host[0], _host[1], _host[2], _host[3], _port);
    return true;
}

void TCPClientInterface::dropConnection(const char *why)
{
    WARNINGF("%s: %s, reconnecting", toString().c_str(), why);
    _client.stop();
    _online = false;
    _wasConnected = false; // set again on the next successful connect
    _inFrame = false;
    _escape = false;
    _rx.clear();
    _lastAttempt = millis();
}

void TCPClientInterface::readAvailable()
{
    // Bound the work per loop so LoRa and the rest of Transport keep getting served.
    uint8_t buf[256];
    size_t budget = 4096;
    int avail;
    while (budget > 0 && (avail = _client.available()) > 0) {
        int n = _client.read(buf, min((size_t)avail, min(sizeof(buf), budget)));
        if (n <= 0)
            break;
        budget -= n;
        for (int i = 0; i < n; i++)
            feed(buf[i]);
    }
}

void TCPClientInterface::feed(uint8_t byte)
{
    if (byte == HDLC_FLAG) {
        if (_inFrame && _rx.size() > 0) {
            if (_rx.size() > RNS::Type::Reticulum::HEADER_MINSIZE && _rx.size() <= _HW_MTU) {
                try {
                    InterfaceImpl::handle_incoming(_rx);
                } catch (const std::bad_alloc &) {
                    ERRORF("%s: handle_incoming: out of memory", toString().c_str());
                } catch (const std::exception &e) {
                    ERRORF("%s: handle_incoming: %s", toString().c_str(), e.what());
                }
            } else {
                DEBUGF("%s: dropping invalid HDLC frame of %u bytes", toString().c_str(), _rx.size());
            }
        }
        _inFrame = true;
        _escape = false;
        _rx.clear();
        return;
    }
    if (!_inFrame)
        return;
    if (byte == HDLC_ESC) {
        _escape = true;
        return;
    }
    if (_escape) {
        byte ^= HDLC_ESC_MASK;
        _escape = false;
    }
    if (_rx.size() < (size_t)_HW_MTU * 2) {
        _rx.append(byte);
    } else {
        WARNINGF("%s: oversized frame, resynchronising", toString().c_str());
        _inFrame = false;
        _rx.clear();
    }
}

bool TCPClientInterface::send_outgoing(const RNS::Bytes &data)
{
    if (!_client.connected())
        return false;
    try {
        RNS::Bytes frame;
        frame.append(HDLC_FLAG);
        const uint8_t *p = data.data();
        for (size_t i = 0; i < data.size(); i++) {
            if (p[i] == HDLC_FLAG || p[i] == HDLC_ESC) {
                frame.append(HDLC_ESC);
                frame.append((uint8_t)(p[i] ^ HDLC_ESC_MASK));
            } else {
                frame.append(p[i]);
            }
        }
        frame.append(HDLC_FLAG);

        size_t wrote = _client.write(frame.data(), frame.size());
        if (wrote != frame.size()) {
            dropConnection("short write");
            return false;
        }
        InterfaceImpl::handle_outgoing(data);
        return true;
    } catch (const std::bad_alloc &) {
        ERRORF("%s: send_outgoing: out of memory", toString().c_str());
    } catch (const std::exception &e) {
        ERRORF("%s: send_outgoing: %s", toString().c_str(), e.what());
    }
    return false;
}
