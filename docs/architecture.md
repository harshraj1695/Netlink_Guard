# Architecture

The diagram captures the simplified deployment of a single kernel module talking to a command-line tool over a custom netlink channel. Everything revolves around enforcing an IPv4 blocklist while providing observability through proc/sysfs.

## Kernel space (ring 0)

1. **Core LKM (`kernel/kguard_lkm.c`)**
   * Maintains a fixed-size in-kernel array (`blocked_ips[KGUARD_MAX_BLOCKED]`) protected by a spinlock for fast lookups and updates. Each entry is stored as `__be32` and reported as `%pI4` in text outputs.
   * Provides helper APIs: `kguard_block_ip`, `kguard_unblock_ip`, and `kguard_is_blocked` to manage the list with error tracking (`-ENOMEM`, `-ENOENT`).

2. **Netfilter enforcement**
   * Registers two `nf_hook_ops` entries at `NF_INET_PRE_ROUTING` and `NF_INET_LOCAL_OUT` with priority `NF_IP_PRI_FIRST`.
   * `kguard_nf_hook` is invoked for each IPv4 packet; it increments `packets_seen`, checks `guard_enabled`, validates the parsed IP (`ip_hdr(skb)`), and drops the packet if `kguard_is_blocked` returns true while incrementing `packets_dropped`.
   * If enforcement is disabled via `/sys/kernel/kguard/enabled`, the hook immediately accepts packets without checking the blocklist.

3. **Kprobe telemetry**
   * A kprobe attaches to `__x64_sys_connect` (falls back to `sys_connect` if the symbol is missing) and increments `connect_events` to detect outbound connection attempts.
   * This metric provides insight into how often userland is invoking `connect`, independent of packet drops handled by netfilter.

4. **Proc/sysfs interfaces**
   * `/proc/kguard` (read-only) is exposed via `proc_create` and `seq_file`, printing:
     ```
     enabled: <0|1>
     packets_seen: <value>
     packets_dropped: <value>
     connect_events: <value>
     blocked_count: <value>
     blocked_ips: <csv> | none
     ```
   * Atomic counters expose `packets_seen/dropped/connect_events`, so even if netlink is unavailable you can see activity via `cat /proc/kguard`.
   * `/sys/kernel/kguard/enabled` (`sysfs_create_file`) uses `enabled_show`/`enabled_store` to let operators toggle packet drops at runtime (1 = enforce, 0 = bypass). There is no log toggle anymore because the kernel replies immediately through netlink; the previous `log_events` flag has been removed for simplicity.

5. **Netlink listener**
   * The kernel creates a `netlink_kernel_cfg` with `.input = kguard_netlink_recv` and listens on `KGUARD_NETLINK_FAMILY = 31`.
   * `kguard_netlink_recv` validates the message length, parses the shared `struct kguard_msg`, and drives behaviors for each message type:
     * `KGUARD_MSG_HELLO`: replies with `KGUARD_MSG_EVENT` payload `{"event":"hello_ack"}`.
     * `KGUARD_MSG_STATUS_REQ`: replies with counters via `kguard_send_status`.
     * `KGUARD_MSG_LIST_REQ`: enumerates `blocked_ips` and returns either a comma-separated list or `none`.
     * `KGUARD_MSG_BLOCK_IP`/`KGUARD_MSG_UNBLOCK_IP`: parse the IPv4 string, update the list, and acknowledge success/failure through `KGUARD_MSG_EVENT` payloads (`ip_blocked`, `ip_unblocked`, `ip_block_failed`, `ip_unblock_failed`).
   * Responses are sent via `kguard_send_reply`, which packages a new `struct kguard_msg` inside a netlink message with the same sequence and replies directly to `req->nlmsg_pid` (the originating CLI PID). This keeps the kernel in control of the LKM<->userspace state machine.

## Netlink protocol

1. **Shared definition** in `userspace/common/protocol.h`:
   ```c
   struct kguard_msg {
       uint16_t type;
       uint16_t reserved;
       uint32_t pid;
       char payload[256];
   };
   ```
   The fixed payload makes encoding human-readable strings (JSON or key=value) trivial.

2. **Message types**
   * `KGUARD_MSG_HELLO` (1) – optional handshake, kernel responds with `KGUARD_MSG_EVENT`.
   * `KGUARD_MSG_STATUS_REQ`/`LIST_REQ` (2/7) – requests a snapshot.
   * `KGUARD_MSG_STATUS_RESP`/`LIST_RESP` (3/8) – command responses.
   * `KGUARD_MSG_BLOCK_IP`/`UNBLOCK_IP` (4/5) – configuration commands; kernel replies with event notifications.
   * `KGUARD_MSG_EVENT` (6) – used for acknowledgements and notifications (e.g., `{"event":"ip_blocked"}`).

3. **Bidirectional behavior**
   * The kernel never stores a userspace PID; each request includes `nlmsg_pid`, and replies use that PID so any process can talk to the guard module without additional registration.
   * Payloads remain short (`256` bytes) so the kernel can fill them with human-readable status lines or simple JSON events and `kgctl` can print them verbatim.

## Userspace / CLI (ring 3)

1. **`userspace/bin/kgctl`**
   * Opens a new netlink socket per invocation (`open_netlink`), binds to `AF_NETLINK`, and identifies itself with `getpid()`.
   * Constructs a request message with the desired command, populates `struct kguard_msg`, and `sendto` the kernel on `KGUARD_NETLINK_FAMILY`.
   * Waits for a reply using `poll(2)` with a `RECV_TIMEOUT_MS = 1000` ms window; if no reply arrives the command fails with a timeout.
   * Validates the response type (optional – e.g., expecting `KGUARD_MSG_STATUS_RESP`) and prints the payload string to stdout.

2. **Supported commands**
   * `status` – requests `KGUARD_MSG_STATUS_REQ`, prints counters such as `enabled=1 blocked=3 packets_seen=...`.
   * `list` – requests `KGUARD_MSG_LIST_REQ`, prints comma-separated IP list or `none`.
   * `block <ip>`/`unblock <ip>` – send `KGUARD_MSG_BLOCK_IP`/`KGUARD_MSG_UNBLOCK_IP`; kernel replies with a JSON event acknowledging success or failure. These commands rely on string parsing in the kernel and the caller receiving the `KGUARD_MSG_EVENT`.

3. **Build**
   * `userspace/Makefile` builds only `kgctl` (the rest of the tree is gone). The CLI depends on `userspace/common/protocol.h` for shared definitions and uses standard libc/poll functions.

4. **No daemon**
   * There is no `kgd` process, no UNIX socket, and no logger module. The CLI directly drives the kernel over netlink, which makes the runtime footprint extremely small and avoids socket management or service supervision.

## Operational flow summary

1. Load `kernel/kguard_lkm.ko` (e.g., `sudo make load`).
2. Run `userspace/bin/kgctl status`/`list`/`block <ip>`/`unblock <ip>` — each invocation:
   * Opens a netlink socket, builds the request, and sends it to PID `0` (kernel).
   * Kernel processes the message, updates state if necessary, and replies to your PID with a textual payload.
   * CLI prints the response and exits.
3. Inspect stats via `/proc/kguard` and toggle enforcement via `/sys/kernel/kguard/enabled`.

Because the kernel handles both enforcement (netfilter) and control (netlink), there is no intermediary userspace daemon. If you need additional event sinks, extend `kgctl` or add another process that speaks `KGUARD_NETLINK_FAMILY = 31` and handles replies/events as needed.
