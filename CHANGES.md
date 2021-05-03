0.2.12-rc3 unreleased
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
