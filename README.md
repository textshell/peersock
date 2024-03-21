peersock
========

peersock extends the idea of [Magic Wormhole](https://github.com/magic-wormhole/magic-wormhole) from file transfer
to bidirectional reliable connections.

In tcp forwarding mode, one side listens on a port, tunnels the data via ICE to the other side which then connects
to a tcp port and thus makes a bidirectional connecting between processes in potentially completely different
fire-walled/NAT·ed networks.

It also supports similar operation on stdin/stdout and local (unix) sockets support is planned.

peersock is in early development and currently depends on the unmerged openssl quic server branch.

Security and principle
----------------------

peersock uses the ICE protocol to connect both sides.
The connection is opened and secured using a connection code that the parties to the connections must transfer
in a secure out of band way (e.g. via instant messaging or a voice connection).

The connection is bootstrapped using a numeric "nameplate" and a rendevouz-server (using the magic-wormhole
rendezvous-server protocol).
This might expose ICE candidate and connection information to third parties (the magic-wormhole server uses
unencrypted websockets).

One the ICE connection is established, the actual data connection is built on top of it, using the QUIC protocol.
QUIC uses TLS 1.3 to encrypt the connection. The TLS 1.3 handshake is done using hardcoded keys and certificates,
because there is no good way to encode enough entropy in the connection code for real keys.

The resulting QUIC connection is than authenticated using
[Socialist Millionaires' Protocol](https://en.wikipedia.org/wiki/Socialist_millionaire_problem)
(as implemented by [libotr](https://github.com/off-the-record/libotr/)) and channel binding (Using
[RFC5705 style exporters from RFC8446](https://www.rfc-editor.org/rfc/rfc8446.html#section-7.5)).

For this authentication the full connection code is used as a password.

peersock currently uses the following hard coded external services:
* relay.magic-wormhole.io for ICE data exchange via nameplates.

And the following default services:
* freestun.org as STUN/TURN server

Usage
-----

The connection process is based on a "connection code" that contains information to match connection attempts as
well as to secure the connection. One side generates a connection code and the other side needs to use that
code to complete the connection. You can pick which side generates the code as is convinient.

Both sides need to use opposite peersock subcommands for the connection to work.
For example "listen" and "connect" match for TCP connections.
Mixing should mostly work for example "listen" matches with "stdio-a".

```
Usage: peersock listen port [connect code]
       peersock connect host:port [connect code]
       peersock stdio-a [connect code]
       peersock stdio-b [connect code]
```

Example
-------

To give access to a locally running VNC server listening on port 5900:
```
alice$ peersock connect localhost:5900
Connection Code is: 8-lab-name-blanket

bob$ peersock listen 5900 8-lab-name-blanket
Auth success
```

Now a connection to localhost port 5900 on host bob will be forwarded to port 5900 on host alice.

Configuration
-------------

Configuration is read from $XDG_CONFIG_DIR/peersock.conf (e.g. $HOME/.config/peersock.conf).

If the file does not exist or a value is not set, a default is used.

Example:

```
[ice]
stun=freestun.net
stun-port=3479

turn=freestun.net
turn-port=3479
turn-user=free
turn-password=free
```

Building
--------

First install dependencies. On a debian based system this should be a good start:

```
$ apt install build-essential git meson ninja-build pkg-config libglib2.0-dev libfmt-dev nlohmann-json3-dev libotr5-dev libsoup2.4-dev libnice-dev
```

This software needs a version of openssl with QUIC server support.
Currently this is only supported in a unmerged branch of openssl, see
[Pull Request #23334](https://github.com/openssl/openssl/pull/23334).

So first you need to build this branch:
```
$ PEERSOCK_BASEDIR=$PWD
$ git clone https://github.com/hlandau/openssl.git -b quic-server-api-impl-4
$ cd openssl
$ ./Configure --prefix=$PEERSOCK_BASEDIR/openssl-prefix
$ make -j10
$ make -j10 install
$ cd ..
```

Then checkout and build peersock
```
$ git clone https://github.com/textshell/peersock
$ cd peersock
$ PKG_CONFIG_PATH=$PEERSOCK_BASEDIR/openssl-prefix/lib64/pkgconfig/ meson setup _build
$ ninja -C _build/
```
The build executable will be in _build/peersock

If you encounter the following error:

> libsoup2 symbols detected. Using libsoup2 and libsoup3 in the same process is not supported.

Try building with the following change:
```
$ PKG_CONFIG_PATH=$PEERSOCK_BASEDIR/openssl-prefix/lib64/pkgconfig/ meson setup _build -Davoidsoup3=true
```

Thanks
------

Thanks to:
* magic wormhole for inspiring this project
* libotr for the Socialist Millionaires' Protocol implementation
* libnice for ICE support
