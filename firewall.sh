#!/bin/bash
# Created by Nicholas Hall <ngharo@gmail.com>
declare -A public_services_tcp
declare -A public_services_udp
declare -A private_services_tcp
declare -A private_services_udp

public_ipv4="1.1.1.1/32"
public_ipv6="2001::1/128"
public_services_tcp=([HTTP]=80 [HTTPS]=443)
public_services_udp=()

private_ipv4="1.1.1.2/32"
private_ipv6="2001::2/128"
                                             # port range
private_services_tcp=([SSH]=22022 [rtorrent]="61000:61100")
private_services_udp=([OpenVPN]=35221)

vpn_interface="tun0"
vpn_subnet="172.16.23.0/24"
vpn_gateway="172.16.23.1/32"

# reply to pings?
allow_icmp_ping=true

##########################################################
# helper functions
#
# dual firewall (ipv4+ipv6) wrapper
run() {
    # by default run command for ipv4 and ipv6 firewall
    local commands="/sbin/iptables /sbin/ip6tables";

    # override to specify which firewall
    if [[ "-4" == "${1}" ]]; then
        commands="/sbin/iptables"
        shift
    elif [[ "-6" == "${1}" ]]; then
        commands="/sbin/ip6tables"
        shift
    fi

    local iptables_args="$1"
    for cmd in $commands; do
        [[ "$cmd" == "/sbin/ip6tables" ]] && iptables_args=$(echo "$iptables_args" | to6)
        echo "${cmd} ${iptables_args}"
        $($cmd $iptables_args)
    done
}

# replace IPv4 specific bits with IPv6 bits
to6() {
    declare -A mapping
    # add any additional ipv4 -> ipv6 replacements to the following array
    mapping=(
        ["icmp-port-unreachable"]="icmp6-port-unreachable"
        ["icmp-proto-unreachable"]="icmp6-adm-prohibited"
    )

    # build a list of sed expressions
    local expressions=()
    for k in "${!mapping[@]}"; do
        expressions+=("-e s/${k}/${mapping[$k]}/g")
    done

    while read -r line_in; do
        sed "${expressions[@]}" <<< $line_in
    done
}

# helper to open an array of ports
# example:
#
# ports=(80 443)
# openports -4 TCP 127.0.0.2 ports
openports() {
    local ipv="${1}"
    local proto="${2}"
    local address="${3}"
    declare -n ports=$4
    
    local _protochain="-A TCP -p tcp"
    [[ "UDP" == "${proto}" ]] &&  _protochain="-A UDP -p udp"

    for port in "${ports[@]}"; do
        run "${ipv}" "${_protochain} -d ${address} --dport ${port} -j ACCEPT"
    done
}

# Flush and allow all
run "-F"
run "-X"
run "-t nat -F"
run "-t nat -X"
run "-t mangle -F"
run "-t mangle -X"
run "-P INPUT ACCEPT"
run "-P FORWARD ACCEPT"
run "-P OUTPUT ACCEPT"

# Chains we'll be using
run "-N TCP"
run "-N UDP"
run -4 "-N natchain"
run -4 "-N natforwarding"

# Establish default policies
run "-P FORWARD DROP"
run "-P OUTPUT ACCEPT"
run "-P INPUT DROP"

# allow already established (passed firewall inspection) traffic right away
run "-A INPUT -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"

# Trusted interfaces
run "-A INPUT -i lo -j ACCEPT"
run "-A INPUT -i tun0 -j ACCEPT"

# allow ICMPv6 neighbor discovery
# We do this because ICMPv6 remain untracked and get classified as invalid
# which would be dropped by the rule following
run "-A INPUT -p 41 -j ACCEPT"

# Drop "invalid" packets right away
run "-A INPUT -m conntrack --ctstate INVALID -j DROP"

if $allow_icmp_ping; then
    run -4 "-A INPUT -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT"
    run -6 "-A INPUT -p ipv6-icmp -j ACCEPT"
fi

# append any new traffic onto our UDP/TCP chains for further analysis
run "-A INPUT -p udp -m conntrack --ctstate NEW -j UDP"
run "-A INPUT -p tcp --syn -m conntrack --ctstate NEW -j TCP"

# Traffic does not match UDP/TCP chains, reject with icmp-port-unreachable / tcp-rst packets
run "-A INPUT -p udp -j REJECT --reject-with icmp-port-unreachable"
run "-A INPUT -p tcp -j REJECT --reject-with tcp-reset"
run "-A INPUT -m limit --limit 10/min -j LOG --log-level 7"
run "-A INPUT -j REJECT --reject-with icmp-proto-unreachable"

###########################################################################
# Open defined ports
openports -4 TCP $public_ipv4 public_services_tcp
openports -4 UDP $public_ipv4 public_services_udp
openports -6 TCP $public_ipv6 public_services_tcp
openports -6 UDP $public_ipv6 public_services_udp

openports -4 TCP $private_ipv4 private_services_tcp
openports -4 UDP $private_ipv4 private_services_udp
openports -6 TCP $private_ipv6 private_services_tcp
openports -6 UDP $private_ipv6 private_services_udp

# port scan trickery
# https://wiki.archlinux.org/index.php/Simple_Stateful_Firewall#Tricking_port_scanners
run "-I TCP -p tcp -m recent --update --seconds 60 --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset"
run "-D INPUT -p tcp -j REJECT --reject-with tcp-reset"
run "-A INPUT -p tcp -m recent --set --name TCP-PORTSCAN -j REJECT --reject-with tcp-reset"
run "-I UDP -p udp -m recent --update --seconds 60 --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable"
run "-D INPUT -p udp -j REJECT --reject-with icmp-port-unreachable"
run "-A INPUT -p udp -m recent --set --name UDP-PORTSCAN -j REJECT --reject-with icmp-port-unreachable"

# Anything past here is not UDP or TCP, block it.
# delete and readd to ensure it's last on the chain
run "-D INPUT -j REJECT --reject-with icmp-proto-unreachable"
run "-A INPUT -j REJECT --reject-with icmp-proto-unreachable"

# IPv4 NAT for VPN clients
run -4 "-A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
run -4 "-A FORWARD -j natchain"
run -4 "-A FORWARD -j natforwarding"
run -4 "-A FORWARD -j REJECT --reject-with icmp-host-unreach"
run -4 "-P FORWARD DROP"
run -4 "-A natchain -i ${vpn_interface} -o ${vpn_interface} -j DROP" # drop client-to-client traffic
run -4 "-A natchain -i ${vpn_interface} -j ACCEPT"
run -4 "-t nat -A POSTROUTING -s ${vpn_subnet} -o eth0 -j MASQUERADE"
