#include "LoRaInterface.h"

#include "board_pins.h"

static inline bool isSplitPacket(uint8_t h)
{
    return (h & LoRaInterface::HEADER_SPLIT) != 0;
}
static inline uint8_t packetSequence(uint8_t h)
{
    return h & LoRaInterface::HEADER_SEQ_MASK;
}

// Antenna dBm -> what the SX1262 is asked for: the module PA adds LORA_PA_GAIN_DB, and the
// chip itself only accepts -9..LORA_SX1262_MAX_DBM.
static int8_t sxPowerFor(int8_t antennaDbm)
{
    int8_t sxPower = antennaDbm - LORA_PA_GAIN_DB;
    if (sxPower > LORA_SX1262_MAX_DBM)
        sxPower = LORA_SX1262_MAX_DBM;
    if (sxPower < -9)
        sxPower = -9;
    return sxPower;
}

bool LoRaInterface::setTxPowerDbm(int8_t dbm)
{
    if (!_radio)
        return false;
    int8_t sxPower = sxPowerFor(dbm);
    int state = _radio->setOutputPower(sxPower);
    if (state != RADIOLIB_ERR_NONE) {
        ERRORF("%s: setOutputPower(%d) failed, code %d", toString().c_str(), sxPower, state);
        return false;
    }
    // setOutputPower leaves the radio in standby on the SX126x; put it back in receive.
    if ((state = _radio->startReceive()) != RADIOLIB_ERR_NONE) {
        ERRORF("%s: startReceive after setOutputPower failed, code %d", toString().c_str(), state);
        return false;
    }
    _params.txPowerDbm = dbm;
    INFOF("%s: tx power now %d dBm at the antenna (SX1262 %d dBm)", toString().c_str(), dbm, sxPower);
    return true;
}

LoRaInterface::LoRaInterface(const char *name, const Params &params) : RNS::InterfaceImpl(name), _params(params)
{
    _IN = true;
    _OUT = true;
    // Raw LoRa symbol rate estimate, as the reference LoRaInterface and RNode do.
    _bitrate = (uint32_t)((double)params.spreadingFactor * ((4.0 / params.codingRate) /
                                                            (pow(2, params.spreadingFactor) / params.bandwidthKHz)) *
                          1000.0);
    _HW_MTU = 508;
}

LoRaInterface::~LoRaInterface()
{
    stop();
    _name = "deleted";
}

bool LoRaInterface::start()
{
    _online = false;

    // E22 LNA enable: HIGH before the radio is touched, never toggled afterwards.
    pinMode(LORA_RXEN, OUTPUT);
    digitalWrite(LORA_RXEN, HIGH);

    if (!_spi) {
        _spi = new SPIClassRP2040(spi1, LORA_MISO, LORA_CS, LORA_SCK, LORA_MOSI);
        _spi->begin();
        _module = new Module(LORA_CS, LORA_DIO1, LORA_RESET, LORA_BUSY, *_spi);
        _radio = new SX1262(_module);
    }

    int8_t sxPower = sxPowerFor(_params.txPowerDbm);

    int state = _radio->begin(_params.frequencyMHz, _params.bandwidthKHz, _params.spreadingFactor,
                              _params.codingRate, RADIOLIB_SX126X_SYNC_WORD_PRIVATE, sxPower,
                              _params.preambleSymbols, LORA_TCXO_VOLTAGE, false /* DC-DC */);
    if (state != RADIOLIB_ERR_NONE) {
        ERRORF("%s: SX1262 begin failed, code %d", toString().c_str(), state);
        return false;
    }
    // TXEN follows DIO2 through the bridge on the module.
    if ((state = _radio->setDio2AsRfSwitch(true)) != RADIOLIB_ERR_NONE) {
        ERRORF("%s: setDio2AsRfSwitch failed, code %d", toString().c_str(), state);
        return false;
    }
    if ((state = _radio->setCurrentLimit(140)) != RADIOLIB_ERR_NONE) {
        ERRORF("%s: setCurrentLimit failed, code %d", toString().c_str(), state);
        return false;
    }
    _radio->setRxBoostedGainMode(true);
    if ((state = _radio->startReceive()) != RADIOLIB_ERR_NONE) {
        ERRORF("%s: startReceive failed, code %d", toString().c_str(), state);
        return false;
    }

    INFOF("%s: %.3f MHz bw %.1f kHz sf %u cr 4/%u preamble %u, %d dBm requested -> SX1262 %d dBm, ~%lu bps",
          toString().c_str(), _params.frequencyMHz, _params.bandwidthKHz, _params.spreadingFactor,
          _params.codingRate, _params.preambleSymbols, _params.txPowerDbm, sxPower, (unsigned long)_bitrate);
    _online = true;
    return true;
}

void LoRaInterface::stop()
{
    if (_radio)
        _radio->standby();
    _online = false;
}

void LoRaInterface::loop()
{
    if (!_online)
        return;
    if (!_radio->checkIrq(RADIOLIB_IRQ_RX_DONE))
        return;

    size_t len = _radio->getPacketLength();
    uint8_t rxBuf[256];
    if (len > sizeof(rxBuf))
        len = sizeof(rxBuf);
    int state = _radio->readData(rxBuf, len);
    if (state == RADIOLIB_ERR_NONE && len > 1) {
        _lastRssi = _radio->getRSSI();
        _lastSnr = _radio->getSNR();
        _rxFrames++;
        DEBUGF("%s: rx %u bytes rssi %.1f snr %.1f", toString().c_str(), len, _lastRssi, _lastSnr);

        uint8_t hdr = rxBuf[0];
        uint8_t seq = packetSequence(hdr);
        if (isSplitPacket(hdr)) {
            if (_rxSeq == SEQ_UNSET || _rxSeq != seq) {
                // First half of a split packet.
                _rxSeq = seq;
                _buffer.clear();
                _buffer.append(rxBuf + 1, len - 1);
            } else {
                // Second half: same sequence number.
                _buffer.append(rxBuf + 1, len - 1);
                _rxSeq = SEQ_UNSET;
                onIncoming(_buffer);
            }
        } else {
            if (_rxSeq != SEQ_UNSET) {
                // A whole packet interrupts a split in progress: drop the half.
                _rxSeq = SEQ_UNSET;
            }
            _buffer.clear();
            _buffer.append(rxBuf + 1, len - 1);
            onIncoming(_buffer);
        }
    } else if (state != RADIOLIB_ERR_NONE) {
        DEBUGF("%s: readData failed, code %d", toString().c_str(), state);
        // A CRC error leaves the radio in RX like any other frame; anything else (SPI timeout, ...)
        // is a chip we no longer trust to be listening, so re-arm it.
        if (state != RADIOLIB_ERR_CRC_MISMATCH)
            _radio->startReceive();
    }
    // Do NOT re-arm with startReceive() here. The SX1262 stays in continuous RX after RX_DONE and
    // stores the next frame at the offset readData() honours (getPacketLength(true, &offset)), whereas
    // RadioLib's startReceive() goes through standby() + setBufferBaseAddress() + clearIrqStatus():
    // a frame that started arriving while we were processing this one (hashlist write, decrypt, a
    // signature check: 100+ ms) would be silently aborted, and one that already completed would be
    // erased unread. That is how the IDENTIFY of `rnstatus -R` (sent right behind the link RTT) was
    // lost on every two-hop attempt. The only re-arm is after a transmit, in send_outgoing().
}

bool LoRaInterface::transmitFrame(const uint8_t *buf, size_t len)
{
    int state = _radio->transmit(const_cast<uint8_t *>(buf), len);
    if (state != RADIOLIB_ERR_NONE) {
        ERRORF("%s: transmit failed, code %d", toString().c_str(), state);
        return false;
    }
    _txFrames++;
    return true;
}

bool LoRaInterface::send_outgoing(const RNS::Bytes &data)
{
    if (!_online)
        return false;
    bool success = true;
    try {
        uint8_t txBuf[256];
        uint8_t randNibble = (uint8_t)(RNS::Cryptography::randomnum(256)) & 0xF0;
        if ((int)data.size() <= LORA_MAX_PAYLOAD) {
            txBuf[0] = randNibble;
            memcpy(txBuf + 1, data.data(), data.size());
            success = transmitFrame(txBuf, 1 + data.size());
        } else if (data.size() <= (size_t)2 * LORA_MAX_PAYLOAD) {
            uint8_t seq = (_txSeqCtr++) & HEADER_SEQ_MASK;
            uint8_t splitHdr = randNibble | HEADER_SPLIT | seq;
            txBuf[0] = splitHdr;
            memcpy(txBuf + 1, data.data(), LORA_MAX_PAYLOAD);
            success = transmitFrame(txBuf, 1 + LORA_MAX_PAYLOAD);
            size_t remainder = data.size() - LORA_MAX_PAYLOAD;
            txBuf[0] = splitHdr;
            memcpy(txBuf + 1, data.data() + LORA_MAX_PAYLOAD, remainder);
            success = transmitFrame(txBuf, 1 + remainder) && success;
        } else {
            WARNINGF("%s: packet of %u bytes exceeds two LoRa frames, dropped", toString().c_str(), data.size());
            success = false;
        }
        _radio->startReceive();
        InterfaceImpl::handle_outgoing(data);
    } catch (const std::exception &e) {
        ERRORF("%s: send_outgoing: %s", toString().c_str(), e.what());
        success = false;
    }
    return success;
}

void LoRaInterface::onIncoming(const RNS::Bytes &data)
{
    try {
        InterfaceImpl::handle_incoming(data);
    } catch (const std::bad_alloc &) {
        ERRORF("%s: handle_incoming: out of memory", toString().c_str());
    } catch (const std::exception &e) {
        ERRORF("%s: handle_incoming: %s", toString().c_str(), e.what());
    }
}
