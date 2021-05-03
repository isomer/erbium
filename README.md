Erbium
======

Erbium[^0] provides networking services for use on small/home networks.  Erbium
currently supports both DNS and DHCP, with other protocols hopefully coming soon.

Erbium is in early development.

   * DNS is beta quality.  Should be ready for test use.
   * DHCP is beta quality.  Should be ready for test use.
   * Router Advertisements are beta quality.  Should be ready for test use.

Building
========

Erbium uses the standard rust build chain: cargo.

To download, compile, link and install erbium you can use the following command:
```shell
$ cargo install erbium --bin erbium --root /usr/local
```

You will need a [configuration file][erbium.conf.example]

IRC
===

We discuss erbium on #erbium on irc.freenode.net


[^0]: Erbium is the 68th element in the periodic table, the same as the client
port number for DHCP.
