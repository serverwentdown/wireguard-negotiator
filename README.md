
# wireguard-negotiator

A not-very-secure manual WireGuard negotiator

## Purpose

`wireguard-negotiator` is built for scenarios where a simple mechanism to exchange and manually accept WireGuard keys is needed. This makes it slightly easier to provision a group of Linux WireGuard peers that peer with a "server".

In summary:

* Manage "client" keys
* Exchange keys over HTTP(S)
* Exchange IP addressing (DHCP-like)
* Manually gate new peers
* Sets up network interface on the "client"
* Generate Ansible INI inventory

The primary scenario this tool is going to be used for is to manage machines using Ansible within an unknown LAN behind NAT. I am planning to use it for FOSSASIA Summit 2020.

## Limitations

* Linux-only
* Manages existing config files only
* Removing peers is a manual process

# Usage

> TODO
