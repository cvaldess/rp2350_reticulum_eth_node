// microReticulum interface over the EBYTE E22-900M30S (SX1262) on SPI1, via RadioLib.
//
// Derived from microReticulum's examples/common/lora_interface (Apache-2.0, Chad Attermann):
// same RNode-compatible air format, one header byte per LoRa frame (random high nibble,
// bit 3 = split flag, bits 2:0 = sequence) so a packet longer than 254 bytes travels as two
// frames. Board specifics come from the Meshtastic port of this carrier:
//   - RXEN (GP3) is driven HIGH once and never touched: the E22 LNA is off otherwise.
//   - DIO2 drives TXEN through the bridge on the module (setDio2AsRfSwitch).
//   - TCXO 1.8 V on DIO3; DC-DC regulator; 140 mA OCP.
//   - The module PA adds ~10 dB: requested dBm - LORA_PA_GAIN_DB is what the SX1262 is set to.
#pragma once

#include <Arduino.h>
#include <RadioLib.h>
#include <SPI.h>
#include <microReticulum.h>

class LoRaInterface : public RNS::InterfaceImpl
{
  public:
    static constexpr uint8_t HEADER_SPLIT = 0x08;
    static constexpr uint8_t HEADER_SEQ_MASK = 0x07;
    static constexpr uint8_t SEQ_UNSET = 0xFF;
    static constexpr int LORA_MAX_PAYLOAD = 254; // 255 - 1 header byte

    struct Params {
        float frequencyMHz;
        float bandwidthKHz;
        uint8_t spreadingFactor;
        uint8_t codingRate; // 5..8 = 4/5..4/8
        uint16_t preambleSymbols;
        int8_t txPowerDbm; // at the antenna connector, PA gain already accounted for
    };

    LoRaInterface(const char *name, const Params &params);
    virtual ~LoRaInterface();

    bool online() const { return _online; }
    int8_t txPowerDbm() const { return _params.txPowerDbm; }
    // Retunes the PA without restarting the radio (the air parameters must not change at
    // runtime: every node of the mesh has to agree on them). Power is at the antenna.
    bool setTxPowerDbm(int8_t dbm);
    float lastRssi() const { return _lastRssi; }
    float lastSnr() const { return _lastSnr; }
    uint32_t rxFrames() const { return _rxFrames; }
    uint32_t txFrames() const { return _txFrames; }

  protected:
    virtual bool start() override;
    virtual void stop() override;
    virtual void loop() override;
    virtual bool send_outgoing(const RNS::Bytes &data) override;

  private:
    bool transmitFrame(const uint8_t *buf, size_t len);
    void onIncoming(const RNS::Bytes &data);

    Params _params;
    SPIClassRP2040 *_spi = nullptr;
    Module *_module = nullptr;
    SX1262 *_radio = nullptr;

    RNS::Bytes _buffer;
    uint8_t _rxSeq = SEQ_UNSET;
    uint8_t _txSeqCtr = 0;
    float _lastRssi = 0;
    float _lastSnr = 0;
    uint32_t _rxFrames = 0;
    uint32_t _txFrames = 0;
};
