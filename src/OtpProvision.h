// Bench-only OTP provisioning console (-D NODE_OTP_PROVISION), docs/secure_boot.md.
//
// Every write is a separate command, confirmed with a trailing '!', checked for its
// preconditions and read back. Sequence on a board: s (seed) -> R ! (SE050 rotation, main
// console) -> l (lock seed page) -> k0/k1 (boot key fingerprints) -> v (KEY_VALID/INVALID) ->
// S (secure boot) -> reboot and prove the signed image boots -> d (lockdown) -> p (lock pages 1-2).
#pragma once

#include <Arduino.h>

#ifdef NODE_OTP_PROVISION
// Called from the USB console on 'O'. Reads the rest of the line and runs one sub-command.
void otpProvisionConsole(Stream &io);
#endif
