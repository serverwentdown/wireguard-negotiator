
# wireguard-negotiator

Not-very-secure manual WireGuard negotiator

## Purpose

`wireguard-negotiator` is built for scenarios where a simple mechanism to exchange and manually accept WireGuard keys is needed. This makes it slightly easier to provision a group of Linux WireGuard peers that peer with a "server".

In summary:

* Set up "client" keys
* Exchange keys over HTTP(S)
* Exchange IP addressing
* Manually gate new "clients"
* Sets up network interface on the "client"
* Generate Ansible INI inventory

The primary scenario this tool is going to be used for is to manage machines using Ansible within an unknown LAN behind NAT. I am planning to use it for FOSSASIA Summit 2020.

## Limitations

* Linux-only
* Relies on the `wg` and `systemctl` commands
* Server manages existing config files only
* Removing peers is a manual process

# Usage

## Server

The "server" manages a WireGuard interface, ~~treating a WireGuard configuration file as a database~~ (TODO). It assumes this interface and configuration exists. It only adds new peers to the configuration file and interface, and does not delete existing configuration. 

```
wireguard-negotiator server --endpoint wireguard-endpoint:port
```

It can generate an Ansible inventory on the same system. This reads off the same WireGuard configuration file as a database.

```
wireguard-negotiator ansible-inventory --group test > inventory
```

The "server" exposes the HTTP server with the following endpoints:

### `POST /request`

Request for the assignment of an IP address and accepted as a peer. This blocks until the server has finished configuring the peer, therefore the client SHOULD NOT timeout. 

#### Request Body

Content-Type: application/x-www-form-urlencoded

| Name | Description | Required |
|------|-------------|----------|
| PublicKey | The public key of the "client" peer | X |

#### Response Body

Content-Type: application/json

| Name | Type | Description |
|------|------|-------------|
| PublicKey | String | Base64 encoded public key of the "server" peer |
| Endpoint | String | The endpoint of the "server" peer |
| PersistentKeepaliveInterval | Number | Suggests a PersistentKeepaliveInterval |
| AllowedIPs | []String | List of allowed IP addresses in CIDR notation |
| InterfaceIPs | []String | List of IP addresses assigned to the "client" interface |

## Client

The "client" sets up a WireGuard interface, and relies on network backends to do so. *It should not be run more than once*. The following network backends are supported:

- (Not implemented) `none`: Creates an interface and WireGuard configuration file
- `networkd`: Creates a `systemd.netdev` and `systemd.network` file in `/etc/systemd/network`

It obtains peer and interface configuration by performing `POST /request` to the "server".

```
wireguard-negotiator request --server https://url-of-server
```
