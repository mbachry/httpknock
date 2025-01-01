# httpknock

A port knocking service for hosts with already set up https server.

While a VPN is a preferred way to keep your SSH port closed to the
internet, it's not always convenient. At the same time, traditional
port knocking methods like fwknopf or custom nftables can be hard to
set up and may require poking holes in firewalls if your server isn't
directly exposed to the internet. If you happen to have a running
httpd service and SSL, the simplest way is to use an authenticated
HTTP endpoint.

Currently iptables rules built with Fedora's `firewalld` are not
supported.

## Build and releases

Static binaries for x64 and aarch64 are provided in github releases.

Build your own binaries with meson:

```
meson setup build
ninja -C build
```

or run `make` for dev/debug builds.

## Install

Drop `httpknock-server` somewhere in your file system. You can use the following systemd service:

```
[Unit]
Description=HTTP port knocking
After=network.target

[Service]
EnvironmentFile=/etc/default/httpknock
ExecStart=/usr/local/bin/httpknock-server --port $PORT --timeout $TIMEOUT --http-port $HTTP_PORT --db-path $DB_PATH
Restart=always
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=full
ProtectHome=read-only
NoNewPrivileges=yes
SystemCallFilter=@basic-io @network-io @io-event @file-system @signal @process @setuid ioctl madvise
CapabilityBoundingSet=CAP_SETGID CAP_SETUID CAP_NET_ADMIN
RestrictAddressFamilies=AF_INET AF_NETLINK
MemoryDenyWriteExecute=yes
RestrictRealtime=yes

[Install]
WantedBy=multi-user.target
```

Put config file in `/etc/default/httpknock`:

```
PORT=22
TIMEOUT=60
HTTP_PORT=8089
DB_PATH=/var/lib/httpknock/db
```

and make sure `/var/lib/httpknock` exists.

Example nginx snippet:

```
location /50624a749b9b4f029f102f1ffa1add5a/k {
    proxy_pass http://127.0.0.1:8089;
    proxy_set_header Host $host;
    rewrite ^/50624a749b9b4f029f102f1ffa1add5a/k/(.*) /$1 break;
    proxy_pass_header Authorization;
}
```

Note the random uuid to obscure the endpoint path.

Run `httpknock-addcred` to create an auth token.

## CLI client

Use `httpknock` command to open the SSH port. Its config file is
located in `~/.config/httpknock.conf`. Example:

```
[httpknock]
url = https://example.com/50624a749b9b4f029f102f1ffa1add5a/k/knock
key = TOKEN from httpknock-addcred
```

## Android client

The release includes an APK file with a simple Android client.

## Security

Httpknock is designed to run with least possible privileges and
doesn't require launching external commands with `sudo`.

Httpknock starts as root, spawns a nftables helper process and drops
privileges. The provided systemd unit add a syscall filter and
capability bounding set.
