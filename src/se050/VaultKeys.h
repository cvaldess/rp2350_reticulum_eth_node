// Identity keys that live in the SE050.
//
// microReticulum sees two ordinary key objects; sign() and exchange() go to the chip
// and the private halves never exist in RAM. Built on the External constructors the
// vault branch of microReticulum adds to X25519PrivateKey and Ed25519PrivateKey, and
// handed to an Identity through load_private_keys(). Public halves come from the
// driver (identityEnsure / signingEnsure), already in RFC 7748 / RFC 8032 order.
//
// The library expects exchange() and sign() to throw on failure (that is what the
// software keys do for a bad peer key), so a chip that refuses is reported the same way.
#pragma once

#include "SE050.h"

#include <microReticulum/Bytes.h>
#include <microReticulum/Cryptography/Ed25519.h>
#include <microReticulum/Cryptography/X25519.h>

#include <stdexcept>

class Se050ExchangeKey : public RNS::Cryptography::X25519PrivateKey
{
  public:
    Se050ExchangeKey(SE050 &chip, const uint8_t publicKey[32])
        : X25519PrivateKey(External{}, RNS::Bytes(publicKey, 32)), chip(chip)
    {
    }

    // One key agreement in the chip (64 ms measured; AN12413 4.10.3: an NVM write
    // per call on this curve). Identity::decrypt is the only caller.
    const RNS::Bytes exchange(const RNS::Bytes &peer_public_key) override
    {
        if (peer_public_key.size() != 32)
            throw std::runtime_error("Peer key is invalid");
        RNS::Bytes shared;
        if (!chip.identityEcdh(peer_public_key.data(), shared.writable(32)))
            throw std::runtime_error("SE050 key agreement failed");
        return shared;
    }

  private:
    SE050 &chip;
};

class Se050SigningKey : public RNS::Cryptography::Ed25519PrivateKey
{
  public:
    Se050SigningKey(SE050 &chip, const uint8_t publicKey[32])
        : Ed25519PrivateKey(External{}, RNS::Bytes(publicKey, 32)), chip(chip)
    {
    }

    // EdDSA in the chip (242 ms measured): announces, link proofs, packet proofs.
    const RNS::Bytes sign(const RNS::Bytes &message) override
    {
        RNS::Bytes signature;
        if (!chip.sign(message.data(), message.size(), signature.writable(64)))
            throw std::runtime_error("SE050 signing failed");
        return signature;
    }

  private:
    SE050 &chip;
};
