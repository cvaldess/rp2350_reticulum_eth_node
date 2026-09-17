#!/usr/bin/env python3
"""The node's settings over the radio: tools/node_config.py for nodes without Ethernet.

Talks to the microReticulum Provisioning engine through the node's remote management
destination (rnstransport.remote.management of its transport identity), path /provision, the
way `rnstatus -R` reaches /status: a Link, IDENTIFY with an allowed identity, then Requests.
The wire protocol is the library's docs/provisioning_client_guide.md: every request and
response is a MsgPack array [op, seq, payload]. Runs where an RNS stack with a path to the
node is (the Pine64), with its own Python (~/rns-venv); needs no msgpack package, RNS
vendors one.

    rnprovision.py <transport identity hash> [--identity ~/mgmt_identity]      # show
    rnprovision.py <hash> --set announce_interval_s=600 --set lora_tx_power_dbm=0
    rnprovision.py <hash> --reset            # drop every override (POST /config/reset)
    rnprovision.py <hash> --set tcp_port=4243 --reboot   # apply a boot-only change (POST /reboot)
    rnprovision.py <hash> --schema           # every namespace the node exposes, by name and id
    rnprovision.py <hash> --namespace Reticulum --set transport_enabled=false   # the built-ins

Fields are named as in docs/config.md; the schema (several kB) is fetched once and cached per
node in ~/.rnprovision/<hash>.json, keyed by the hash the node reports in GET_INFO, so a LoRa-only
node is not asked for it on every call.

Every write is verified: after the commit (or after the node is back, with --reboot) the state
is read again and each value compared with what was asked, and the exit status says whether
it took (0 verified, 1 not, 2 could not tell). That is what makes a lost packet harmless -
two hops of LoRa lose some - because a commit whose ack never came back is not a commit that
did not happen, nor the other way round. --no-verify skips the read-back. A COMMIT the node
refuses (a value NodeSettings will not take, e.g. ip_mode=static without an ip) shows up as
a MISMATCH, with the reason from `last_error`.
"""
import argparse
import json
import os
import sys
import time

import RNS

OP = {"schema": 1, "info": 2, "caps": 3, "get": 4, "set": 5, "commit": 6, "discard": 7, "factory_reset": 8, "reboot": 9}
OP_ERROR = 101
ERRORS = {0: "ok", 1: "malformed request", 2: "unknown op", 3: "unknown namespace", 4: "unknown field",
          5: "invalid value", 6: "constraint violation", 7: "read-only", 8: "storage error",
          9: "provisioning not started", 99: "internal"}
TYPE = {1: "bool", 2: "int", 3: "float", 4: "string", 5: "bytes", 6: "enum", 7: "bytes_list", 8: "void"}
FF_LIVE, FF_REBOOT, FF_READ_ONLY, FF_SECRET, FF_WRITE_ONLY = 1, 2, 4, 8, 16
NODE_NAMESPACE = "Node"
CACHE_DIR = os.path.expanduser("~/.rnprovision")
LINK_ATTEMPTS = 3    # a link request is one packet each way per hop; a lost one is ordinary
REBOOT_WAIT_S = 240  # how long to keep trying to reach a node after telling it to reboot


class Failure(Exception):
    """Something the tool cannot get past; main() prints it and exits with 2."""


class Session:
    """One link to the node's remote management destination, IDENTIFYd, serving requests."""

    def __init__(self, identity_hash, identity, timeout=30, verbose=False, attempts=LINK_ATTEMPTS):
        self.verbose = verbose
        self.timeout = timeout
        self.seq = 0
        self.link = None
        # What rnstatus -R does: the management destination is derived from the transport
        # identity, and its identity is recalled from the node's announces.
        dest_hash = RNS.Destination.hash_from_name_and_identity("rnstransport.remote.management", identity_hash)
        if not RNS.Transport.has_path(dest_hash):
            RNS.Transport.request_path(dest_hash)
            t0 = time.time()
            while not RNS.Transport.has_path(dest_hash) and time.time() - t0 < timeout:
                time.sleep(0.1)
            if not RNS.Transport.has_path(dest_hash):
                raise Failure("no path to %s within %d s" % (RNS.prettyhexrep(dest_hash), timeout))
        remote_identity = RNS.Identity.recall(dest_hash)
        if remote_identity is None:
            raise Failure("identity of %s unknown: has it announced?" % RNS.prettyhexrep(dest_hash))
        dest = RNS.Destination(remote_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
                               "rnstransport", "remote", "management")
        for attempt in range(attempts):
            link = RNS.Link(dest)
            t0 = time.time()
            while link.status != RNS.Link.ACTIVE and time.time() - t0 < timeout:
                time.sleep(0.1)
            if link.status == RNS.Link.ACTIVE:
                self.link = link
                break
            link.teardown()
            if verbose:
                print("link: no answer in %d s%s" % (timeout, ", asking again" if attempt + 1 < attempts else ""))
            if attempt + 1 < attempts:
                # Seen on the bench: the relay put the link request on the air while the node
                # was sending its own announce (half duplex), and the next attempt never left
                # the local stack, which was waiting on its own path rediscovery. Ask for the
                # path again ourselves and give the answer time to arrive before retrying.
                RNS.Transport.request_path(dest_hash)
                time.sleep(min(10, timeout / 3))
        if self.link is None:
            raise Failure("link to %s not established (%d attempt%s of %d s)" %
                          (RNS.prettyhexrep(dest_hash), attempts, "" if attempts == 1 else "s", timeout))
        self.link.identify(identity)
        self.hops = RNS.Transport.hops_to(dest_hash)
        if verbose:
            print("link up, rtt %.2f s, %d hop%s" % (self.link.rtt, self.hops, "" if self.hops == 1 else "s"))

    def call(self, op, payload=None, must=True):
        """One request. A node silent for `timeout` is asked once more, and the answer to
        either copy is taken - after a reboot the relay queues requests behind a burst of
        announces for tens of seconds, and the first answer then arrives after the second
        request went out. With must=False two silences return None instead of failing, for
        the caller to read the node's state instead of guessing."""
        answers = {}
        sent = []
        t0 = time.time()
        for attempt in range(2):
            self.seq += 1
            seq = self.seq
            sent.append(seq)

            def got(rr, seq=seq):
                answers[seq] = rr.response

            def failed(rr, seq=seq):
                answers.setdefault(seq, None)  # RNS gave up on it: timeout, or refused

            self.link.request("/provision", data=[OP[op], seq, payload], response_callback=got,
                              failed_callback=failed, timeout=self.timeout)
            t1 = time.time()
            while time.time() - t1 < self.timeout + 2:
                answered = [s for s in sent if answers.get(s) is not None]
                if answered:
                    break
                time.sleep(0.05)
            answered = [s for s in sent if answers.get(s) is not None]
            if answered:
                break
            if attempt == 0 and self.verbose:
                print("%s: no answer in %d s, asking again" % (op, self.timeout))
        if not answered:
            if not must:
                return None
            raise Failure("%s: no answer (lost on the way, or this identity is not in the node's allow-list)" % op)
        seq = answered[0]
        if self.verbose:
            print("%s: %.2f s%s" % (op, time.time() - t0, "" if len(sent) == 1 else " (answer to request %d of %d)" % (sent.index(seq) + 1, len(sent))))
        resp = answers[seq]
        if not isinstance(resp, (list, tuple)) or len(resp) not in (2, 3):
            raise Failure("%s: malformed reply %r" % (op, resp))
        rop, rseq = resp[0], resp[1]
        rpayload = resp[2] if len(resp) == 3 else None  # REBOOT acks without a payload
        if rop == OP_ERROR:
            code = rpayload.get(1) if isinstance(rpayload, dict) else None
            msg = rpayload.get(2, "") if isinstance(rpayload, dict) else ""
            raise Failure("%s: error %s%s" % (op, ERRORS.get(code, code), (": " + msg) if msg else ""))
        if rseq != seq:
            raise Failure("%s: reply for seq %s, expected %s" % (op, rseq, seq))
        return rpayload

    def state(self, ns):
        """The namespace's committed values, {field id: value}."""
        return (self.call("get", {1: [ns["id"]], 2: False}) or {}).get(ns["id"], {})

    def close(self):
        if self.link is not None:
            self.link.teardown()
            self.link = None


# ------------------------------------------------------------------------------ the schema

def schema_path(identity_hash):
    return os.path.join(CACHE_DIR, identity_hash.hex() + ".json")


def load_schema(session, identity_hash, refresh=False):
    """The namespaces and fields, from the cache when the node's schema hash still matches."""
    info = session.call("info")
    node_hash = info.get(4)
    path = schema_path(identity_hash)
    if not refresh and node_hash is not None and os.path.exists(path):
        with open(path) as f:
            cached = json.load(f)
        if cached.get("hash") == node_hash:
            return cached["namespaces"], info
    raw = session.call("schema")
    namespaces = []
    for entry in raw:
        ns_id, ns_name = entry[0], entry[1]
        parent, fields = (entry[2], entry[3]) if len(entry) >= 4 else (0, entry[2])
        namespaces.append({
            "id": ns_id, "name": ns_name, "parent": parent,
            "fields": [{
                "id": fm[1], "name": fm[2], "type": fm[3], "flags": fm[4], "default": jsonable(fm.get(12)),
                "min": fm.get(5, fm.get(7)), "max": fm.get(6, fm.get(8)), "max_len": fm.get(9),
                "enum_values": fm.get(10), "enum_labels": fm.get(11),
            } for fm in fields],
        })
    os.makedirs(CACHE_DIR, exist_ok=True)
    with open(path, "w") as f:
        json.dump({"hash": node_hash, "namespaces": namespaces}, f)
    return namespaces, info


def jsonable(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, list):
        return [jsonable(x) for x in v]
    return v


def find_namespace(namespaces, name):
    for ns in namespaces:
        if ns["name"] == name or str(ns["id"]) == name:
            return ns
    raise Failure("no namespace '%s'; the node has: %s" % (name, ", ".join("%s (%d)" % (n["name"], n["id"]) for n in namespaces)))


def find_field(ns, name):
    for f in ns["fields"]:
        if f["name"] == name or str(f["id"]) == name:
            return f
    raise Failure("no field '%s' in %s; it has: %s" % (name, ns["name"], ", ".join(f["name"] for f in ns["fields"])))


def field_by_id(ns, fid):
    return next(f for f in ns["fields"] if f["id"] == fid)


def settable(f):
    return not f["flags"] & (FF_READ_ONLY | FF_WRITE_ONLY | FF_SECRET)


def parse_value(field, text):
    """The command line's text as the field's wire type."""
    t = field["type"]
    if t == 1:
        if text.lower() in ("true", "1", "yes", "on"):
            return True
        if text.lower() in ("false", "0", "no", "off"):
            return False
        raise Failure("%s: expected true/false" % field["name"])
    if t == 2:
        return int(text)
    if t == 3:
        return float(text)
    if t == 4:
        return text
    if t == 5:
        return bytes.fromhex(text)
    if t == 6:
        labels = field.get("enum_labels") or []
        values = field.get("enum_values") or []
        if text in labels:
            return values[labels.index(text)]
        if text.lstrip("-").isdigit() and int(text) in values:
            return int(text)
        raise Failure("%s: expected one of %s" % (field["name"], ", ".join(labels)))
    if t == 7:
        return [bytes.fromhex(x) for x in text.split(",") if x]
    raise Failure("%s: unsupported type %s" % (field["name"], t))


def same(field, a, b):
    """Two values of the field, equal as the node sees them (floats within 1e-9, bytes as hex)."""
    if field["type"] == 3:
        return a is not None and b is not None and abs(float(a) - float(b)) <= 1e-9 * max(1.0, abs(float(b)))
    return jsonable(a) == jsonable(b)


def show_value(field, v):
    if v is None:
        return "-"
    if field["type"] == 6:
        labels, values = field.get("enum_labels") or [], field.get("enum_values") or []
        if v in values:
            return labels[values.index(v)]
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, list):
        return ",".join(x.hex() if isinstance(x, bytes) else str(x) for x in v)
    if v == "":
        return '""'
    return str(v)


def flags_text(flags):
    parts = []
    if flags & FF_LIVE:
        parts.append("live")
    if flags & FF_REBOOT:
        parts.append("reboot")
    if flags & FF_READ_ONLY:
        parts.append("read-only")
    if flags & FF_SECRET:
        parts.append("secret")
    if flags & FF_WRITE_ONLY:
        parts.append("command")
    return ",".join(parts)


# ------------------------------------------------------------------------------ commands

def show(session, ns, info):
    values = session.state(ns)
    print("%s (namespace %d)%s" % (ns["name"], ns["id"], "   REBOOT PENDING" if info.get(3) else ""))
    width = max(len(f["name"]) for f in ns["fields"])
    for f in ns["fields"]:
        if f["flags"] & FF_WRITE_ONLY:
            print("  %-*s  <command>" % (width, f["name"]))
            continue
        v = values.get(f["id"])
        mark = ""
        if settable(f) and v is not None and not same(f, v, f["default"]):
            mark = "   (default %s)" % show_value(f, f["default"])
        print("  %-*s  %-20s %s%s" % (width, f["name"], show_value(f, v), flags_text(f["flags"]), mark))


def verify(session, ns, wanted, what):
    """Reads the namespace back and compares each wanted {field id: value}. True when every
    one is there; otherwise says which are not, and why the node refused if it says."""
    values = session.state(ns)
    ok = True
    for fid, want in wanted.items():
        f = field_by_id(ns, fid)
        have = values.get(fid)
        if same(f, have, want):
            print("  verified  %-20s %s" % (f["name"], show_value(f, have)))
        else:
            print("  MISMATCH  %-20s is %s, wanted %s" % (f["name"], show_value(f, have), show_value(f, want)))
            ok = False
    if ok:
        print("%s: verified on the node" % what)
        return True
    err_field = next((f for f in ns["fields"] if f["name"] == "last_error"), None)
    if err_field and values.get(err_field["id"]):
        print("%s: NOT applied - the node's last refusal: %s" % (what, values[err_field["id"]]))
    else:
        print("%s: NOT applied" % what)
    return False


def set_fields(session, ns, wanted, do_verify):
    """Stages, commits and (unless told not to) verifies {field id: value}."""
    r = session.call("set", {ns["id"]: wanted})
    errors = r.get(3) or []
    for ns_id, fid, code in errors:
        print("refused before commit: %s: %s" % (field_by_id(ns, fid)["name"], ERRORS.get(code, code)))
    if errors:
        session.call("discard", [ns["id"]])
        raise Failure("nothing committed")
    if r.get(1, 0) == 0:
        print("nothing to change: every value equals what the node already has")
    else:
        c = session.call("commit", [ns["id"]], must=False)
        if c is None:
            print("commit: no answer twice - reading the node to see whether it landed")
        else:
            applied = c.get(1, 0)
            print("commit: applied %d field%s%s" % (applied, "" if applied == 1 else "s",
                                                   ", REBOOT REQUIRED" if c.get(2) else ""))
    if not do_verify:
        return True
    return verify(session, ns, wanted, "set")


def command(session, ns, name, do_verify):
    field = find_field(ns, name)
    if not field["flags"] & FF_WRITE_ONLY:
        raise Failure("%s is not a command" % name)
    session.call("set", {ns["id"]: {field["id"]: None}})
    c = session.call("commit", [ns["id"]], must=False)
    if c is None:
        print("%s: commit: no answer twice" % name)
    else:
        print("%s: %s" % (name, "done" if c.get(1, 0) else "not applied"))
    if not do_verify:
        return True
    if name == "reset_overrides":
        # After a reset every settable value is its schema default: that can be read back.
        wanted = {f["id"]: f["default"] for f in ns["fields"] if settable(f)}
        return verify(session, ns, wanted, name)
    print("%s: a command leaves nothing to read back" % name)
    return True


def reboot_and_verify(session, identity_hash, identity, ns, wanted, args):
    """Tells the node to reboot, then waits for it to answer again and checks the values."""
    session.timeout = 5
    session.call("reboot", must=False)
    session.close()
    print("rebooting")
    if not args.verify:
        return True
    t0 = time.time()
    # The node is back in ~10 s, but it and its relay then spend tens of seconds of LoRa
    # airtime on announces and path responses; asking before that only queues behind them.
    time.sleep(30)
    back = None
    while time.time() - t0 < REBOOT_WAIT_S:
        try:
            back = Session(identity_hash, identity, timeout=args.timeout, verbose=args.verbose, attempts=1)
            break
        except Failure:
            time.sleep(5)
    if back is None:
        print("the node did not answer within %d s of the reboot" % REBOOT_WAIT_S)
        return False
    try:
        info = back.call("info")
        print("back after %d s%s" % (time.time() - t0, ", REBOOT STILL PENDING" if info.get(3) else ""))
        wanted = dict(wanted)
        pending = next((f for f in ns["fields"] if f["name"] == "reboot_pending"), None)
        if pending:
            wanted[pending["id"]] = False
        return verify(back, ns, wanted, "reboot") and not info.get(3)
    finally:
        back.close()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("dest", help="the node's transport identity hash (what rnstatus -R takes)")
    ap.add_argument("--identity", default="~/mgmt_identity", help="identity file in the node's allow-list")
    ap.add_argument("--namespace", "-n", default=NODE_NAMESPACE, help="namespace by name or id (default: %s)" % NODE_NAMESPACE)
    ap.add_argument("--set", action="append", default=[], metavar="NAME=VALUE", help="stage a value; every --set commits together")
    ap.add_argument("--reset", action="store_true", help="drop every override (the Node namespace's reset_overrides)")
    ap.add_argument("--reboot", action="store_true", help="reboot the node (after any --set), wait for it and verify")
    ap.add_argument("--command", metavar="NAME", help="fire a command field of the namespace")
    ap.add_argument("--schema", action="store_true", help="list every namespace and field")
    ap.add_argument("--refresh-schema", action="store_true", help="ignore the cached schema")
    ap.add_argument("--no-verify", dest="verify", action="store_false", help="do not read the node back after a write")
    ap.add_argument("--timeout", type=float, default=30)
    ap.add_argument("--verbose", "-v", action="store_true")
    ap.add_argument("--config", help="RNS config directory")
    args = ap.parse_args()

    identity_hash = bytes.fromhex(args.dest)
    RNS.Reticulum(configdir=args.config, loglevel=RNS.LOG_VERBOSE if args.verbose else RNS.LOG_ERROR)
    identity = RNS.Identity.from_file(os.path.expanduser(args.identity))
    if identity is None:
        raise Failure("cannot load the identity at %s" % args.identity)
    session = Session(identity_hash, identity, timeout=args.timeout, verbose=args.verbose)
    ok = True
    try:
        namespaces, info = load_schema(session, identity_hash, refresh=args.refresh_schema)
        if args.schema:
            for ns in namespaces:
                print("%s (namespace %d%s)" % (ns["name"], ns["id"], ", under %d" % ns["parent"] if ns["parent"] else ""))
                for f in ns["fields"]:
                    print("  %-28s %-10s %-12s default %s" % (f["name"], TYPE.get(f["type"], f["type"]), flags_text(f["flags"]), show_value(f, f["default"])))
            return 0
        ns = find_namespace(namespaces, args.namespace)
        wanted = {}
        for text in args.set:
            if "=" not in text:
                raise Failure("--set wants name=value, got '%s'" % text)
            name, value = text.split("=", 1)
            f = find_field(ns, name)
            if f["flags"] & FF_READ_ONLY:
                raise Failure("%s is read-only" % name)
            wanted[f["id"]] = parse_value(f, value)
        if wanted:
            ok = set_fields(session, ns, wanted, args.verify) and ok
        if args.command:
            ok = command(session, ns, args.command, args.verify) and ok
        if args.reset:
            ok = command(session, find_namespace(namespaces, NODE_NAMESPACE), "reset_overrides", args.verify) and ok
        if args.reboot:
            # After the reboot, check what was just set (it persists, live or not) - unless the
            # commit already failed, in which case only the reboot itself is checked.
            ok = reboot_and_verify(session, identity_hash, identity, ns, wanted if ok else {}, args) and ok
            return 0 if ok else 1
        if not wanted and not args.command and not args.reset:
            show(session, ns, info)
        return 0 if ok else 1
    finally:
        session.close()
        time.sleep(0.3)


if __name__ == "__main__":
    try:
        code = main()
    except Failure as e:
        print(e, file=sys.stderr)
        code = 2
    # RNS's exit handler turns a plain sys.exit(n) into 0 (measured: sys.exit(3) -> 0 with a
    # Reticulum instance up); RNS.exit() runs that handler and then os._exit(code), so the
    # status survives. os._exit skips Python's buffers, hence the flush.
    sys.stdout.flush()
    sys.stderr.flush()
    RNS.exit(code)
