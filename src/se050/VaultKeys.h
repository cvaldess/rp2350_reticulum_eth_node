// Identity keys that live in the SE050.
//
// microReticulum sees ordinary key objects; sign() and exchange() go to the chip and
// the private halves never exist in RAM. Built on the External constructors the vault
// branch of microReticulum adds to X25519PrivateKey and Ed25519PrivateKey, and handed
// to an Identity through load_private_keys(). Each key is one SE050 object, addressed
// by id; se050Identity() builds a whole identity from a pair of them.
//
// The library expects exchange() and sign() to throw on failure (that is what the
// software keys do for a bad peer key), so a chip that refuses is reported the same way.
#pragma once

#include "SE050.h"

#include <microReticulum/Bytes.h>
#include <microReticulum/Cryptography/Ed25519.h>
#include <microReticulum/Cryptography/X25519.h>
#include <microReticulum/Identity.h>

#include <memory>
#include <stdexcept>

// Object ids of the node's identities in the chip. The application identity reuses
// the driver's well-known pair (SE050::IDENTITY_OBJ / SIGNING_OBJ), so its hash is
// the one the boot self-test prints. The transport identity gets its own pair.
constexpr uint32_t VAULT_TRANSPORT_EXCHANGE_OBJ = 0x524E5458u; // "RNTX", X25519
constexpr uint32_t VAULT_TRANSPORT_SIGNING_OBJ = 0x524E5453u;  // "RNTS", Ed25519

class Se050ExchangeKey : public RNS::Cryptography::X25519PrivateKey
{
  public:
    Se050ExchangeKey(SE050 &chip, uint32_t objId, const uint8_t publicKey[32])
        : X25519PrivateKey(External{}, RNS::Bytes(publicKey, 32)), chip(chip), objId(objId)
    {
    }

    // One key agreement in the chip (66 ms measured). Identity::decrypt is the only
    // caller: links use ephemeral software keys, announces sign. AN12543 4.10.3 says
    // this form (peer key as bytes) writes NVM per call on this curve; measured on this
    // chip it does not show one, so the driver keeps it and the transient-object form
    // stays an option - docs/se050_ecdh_nvm.md.
    const RNS::Bytes exchange(const RNS::Bytes &peer_public_key) override
    {
        if (peer_public_key.size() != 32)
            throw std::runtime_error("Peer key is invalid");
        RNS::Bytes shared;
        if (!chip.x25519Ecdh(objId, peer_public_key.data(), shared.writable(32)))
            throw std::runtime_error("SE050 key agreement failed");
        return shared;
    }

  private:
    SE050 &chip;
    uint32_t objId;
};

class Se050SigningKey : public RNS::Cryptography::Ed25519PrivateKey
{
  public:
    Se050SigningKey(SE050 &chip, uint32_t objId, const uint8_t publicKey[32])
        : Ed25519PrivateKey(External{}, RNS::Bytes(publicKey, 32)), chip(chip), objId(objId)
    {
    }

    // EdDSA in the chip (242 ms measured): announces, link proofs, packet proofs.
    const RNS::Bytes sign(const RNS::Bytes &message) override
    {
        RNS::Bytes signature;
        if (!chip.ed25519Sign(objId, message.data(), message.size(), signature.writable(64)))
            throw std::runtime_error("SE050 signing failed");
        return signature;
    }

  private:
    SE050 &chip;
    uint32_t objId;
};

// An Identity whose private halves are the two objects, generated in the chip the
// first time they are asked for. Nothing about it touches the filesystem: it is
// rebuilt from the chip's public keys on every boot, and the hash is the same as
// long as the chip is. Returns a NONE identity if the chip cannot provide them.
inline RNS::Identity se050Identity(SE050 &chip, uint32_t exchangeObj, uint32_t signingObj)
{
    uint8_t exchangePublic[32], signingPublic[32];
    if (!chip.x25519Ensure(exchangeObj, exchangePublic) || !chip.ed25519Ensure(signingObj, signingPublic))
        return {RNS::Type::NONE};
    RNS::Identity identity(false);
    if (!identity.load_private_keys(std::make_shared<Se050ExchangeKey>(chip, exchangeObj, exchangePublic),
                                    std::make_shared<Se050SigningKey>(chip, signingObj, signingPublic)))
        return {RNS::Type::NONE};
    return identity;
}
