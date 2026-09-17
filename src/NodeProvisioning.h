// The node's settings over the radio: a microReticulum Provisioning namespace ("Node", id 200)
// that exposes NodeSettings to the remote management destination's /provision path, so a node
// without Ethernet can be retuned the way docs/config.md does it over HTTP (docs/provisioning.md).
//
// One source of truth: NodeSettings keeps validating, applying and persisting (/node_settings);
// the namespace is a facade over it. Fields have getters and no setters - a COMMIT is turned into
// the same PUT the HTTP route would make, all or nothing, inside the namespace's commit hook.
// The Provisioner still mirrors the committed values into its own file (/config/ns200.msgpack);
// nothing reads it back into effect (no setters), and nodeProvisioningSync() keeps its working
// map equal to NodeSettings after every change and after boot, so it can never disagree.
#pragma once

// Register the namespace and the reboot / factory-reset hooks. Before reticulum.start(), which
// is where the Provisioner begins and loads its files.
void nodeProvisioningRegister();
// Working map <- NodeSettings. After reticulum.start(), and NodeSettings calls it after any change.
void nodeProvisioningSync();
