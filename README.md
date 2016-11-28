# stateful-iptables-firewall
Dual stack capable iptables firewall script

```
supports two interfaces/addresses plus NAT support for VPN servers

Terminology used in the script:
"Public" an address where services are available
"Private" (optional) another address where services are available

Example:
public and private are both public facing interfaces
but have different ports allowed.  e.g. private (1.1.1.2)
IP allows SSH and VPN access while public (1.1.1.1) allows
HTTP.
```
