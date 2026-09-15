// Pin map of the pico2_w5500_e22 / wiznet_5500_evb_pico2_e22p carriers.
// Source of truth: variants/rp2350/diy/pico2_w5500_e22/variant.h in the Meshtastic fork,
// validated on hardware (RF path, RXEN behaviour, SE050 on I2C 0x48).
#pragma once

// --- LoRa: EBYTE E22-900M30S (SX1262) on SPI1 ---
#define LORA_SCK 10
#define LORA_MOSI 11
#define LORA_MISO 12
#define LORA_CS 13
#define LORA_RESET 15
#define LORA_DIO1 14 // IRQ
#define LORA_BUSY 2
// E22 RXEN must stay HIGH permanently (LNA on); toggling it leaves the radio deaf.
// TXEN is driven by the SX1262 itself through the DIO2->TXEN bridge on the module.
#define LORA_RXEN 3
#define LORA_TCXO_VOLTAGE 1.8f
// Module PA: ~10 dB gain, 30 dBm rated. Requested dBm must be reduced by this
// before it reaches the SX1262 (Meshtastic: TX_GAIN_LORA 10, SX126X_MAX_POWER 22).
#define LORA_PA_GAIN_DB 10
#define LORA_SX1262_MAX_DBM 22

// --- Ethernet: WIZnet W5500 on SPI0 ---
#define ETH_MISO 16
#define ETH_CS 17
#define ETH_SCK 18
#define ETH_MOSI 19
#define ETH_RESET 20

// --- NXP SE050E secure element on I2C0 (shared with the SHT40 at 0x44) ---
#define SE050_I2C_ADDR 0x48
#define I2C_SDA 4
#define I2C_SCL 5
// ENA on GP7 only on carriers with the hardware mod (pin 11/12 bridge cut + 6.8k/47nF).
// Without the mod the pin is tied to VIN: never drive it low on an unmodified board.
#define SE050_ENA_PIN 7

// --- Misc ---
#define LED_PIN 25
#define EXT_PWR_DETECT 24
#define BATTERY_PIN 29
