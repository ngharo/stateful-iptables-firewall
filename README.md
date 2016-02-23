# stateful-iptables-firewall
Dual stack capable iptables firewall script

```
public and private are both public facing interfaces
but have different ports allowed.  e.g. private (1.1.1.2)
IP allows SSH and VPN access while public (1.1.1.1) allows
HTTP.

+----------+                 +-------------+
|          |    "public"     |   1.1.1.1   |
|          <----------------->   2001::1   |
| internet |                 |    eth0     |
|          <----------------->   1.1.1.2   |
|          |    "private"    |   2001::2   |
+----------+                 +-------------+


+-----------+                +-------------+
|           | 172.16.23.0/24 |             |
|    VPN    <---------------->    tun0     |
|           |                | 172.16.23.1 |
+-----------+                +-------------+
```
