# Netlink Guard (kguard)

Netlink Guard is a minimal Linux learning project that combines a kernel module with a small netlink CLI. The kernel module enforces a simple IPv4 blocklist via netfilter and exposes counters + toggles through `/proc/kguard` and `/sys/kernel/kguard/enabled`. The user-facing `kgctl` tool speaks netlink directly, so you can check status or update the blocklist without an extra daemon.

## Architecture

- **Kernel space:** `kernel/kguard_lkm.c` registers IPv4 netfilter hooks against `NF_INET_PRE_ROUTING` and `NF_INET_LOCAL_OUT`, tracks packets/blocks, and exports a netlink listener for `status`, `list`, `block`, and `unblock` requests.
- **IPC:** a tiny custom netlink protocol (`userspace/common/protocol.h`) enumerates message types and payload size (status/list responses, block/unblock acknowledgements).
- **Userspace CLI:** `userspace/bin/kgctl` opens a netlink socket for each command, sends the appropriate message, waits for the kernel reply, and prints the payload.

## Build

From the repo root:

```bash
make all
```

Artifacts:

- `kernel/kguard_lkm.ko`
- `userspace/bin/kgctl`

## Run (Manual)

1. **Load the module:** `sudo make load`
2. **Use the CLI (`kgctl`) from the repo root:**
   ```bash
   ./userspace/bin/kgctl status
   ./userspace/bin/kgctl list
   ./userspace/bin/kgctl block 1.2.3.4
   ./userspace/bin/kgctl unblock 1.2.3.4
   ```
3. **Disable enforcement (optional):** `echo 0 | sudo tee /sys/kernel/kguard/enabled`
4. **Re-enable:** `echo 1 | sudo tee /sys/kernel/kguard/enabled`

## Commands (kgctl)

- `status` returns counters (`enabled`, `packets_seen`, `packets_dropped`, `connect_events`, etc.).
- `list` prints the current in-kernel IPv4 blocklist.
- `block <ip>` asks the kernel to add `ip` to the blocklist and prints the acknowledgement.
- `unblock <ip>` removes `ip` from the blocklist.

## Runtime Introspection

- `cat /proc/kguard` prints the same counters and a comma-separated list of blocked IPv4 addresses.
- `echo 0 | sudo tee /sys/kernel/kguard/enabled` temporarily turns off the drop decisions.

## Stop / Unload

```bash
sudo make unload
```

The module cleanup also resets the netlink socket and proc entries.
