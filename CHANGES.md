1.0.5
   - Upgraded dependencies
   - Fixed spinning in netinfo during startup.
1.0.3
   - Upgraded dependencies, cleaned up new clippy warnings.
1.0.1-rc1
   - Beginnings of LLDP added by rayhaanj, not yet active.
   - Upgraded nix dependency.
1.0.0
   - Better error handling for DHCP pool failures.
   - Fix a bunch of cargo warnings.
0.2.12-rc7
   - Fix mio upgrade missing "os-poll" feature.
0.2.12-rc6
   - Clippy cleanups, bumping dependencies etc.
0.2.12-rc5
   - DHCP: Bug Fix: If there are multiple active leases for a host, don't flip
     between them, but instead try and keep one.
0.2.12-rc4
   - Harden DNS listeners to avoid premature exits.
   - Add `default-listen-style` to allow multiple DNS servers on one host.
   - Removed `dhcp-listeners` as the feature could never possibly work: If you
     bind to an address, you don't receive broadcast packets and thus never see
     DHCP requests.
0.2.12-rc3
   - DHCP should not silently ignore prefixes that don't have 0 bits in the network address.
0.2.12-rc2
   - Merged in the new DNS branch.
0.2.9
   - Workaround for not compiling on NixOS.
0.2.8
   - Cookies are now sent on error
   - Fixed some metrics bugs.
0.2.7
   - Added ACL subsystem.
   - Massive restructuring of the DNS service to start to get it into shape.
0.2.5
   - Added API listeners, supports abstract, and non abstract unix sockets, as well as IPv4 and IPv6.
     Simple HTTP protocol, currently read only. Supports /, /metrics, /api/v1/leases.json
   - Listens on /var/log/erbium/control by default.
   - Changed to use "log" crate.
0.2.4
 - Configuration changes:
   - "dhcp" section is now "dhcp-policies", and no longer has a separate "policies" subsections.
   - the "router-advertisements" section now has interface names as keys, instead of a list of interfaces with a
     required interface name.
   - $self4 and $self6 can now be used in place of a v4 or v6 address respectively, to use the address of the
     local interface.
