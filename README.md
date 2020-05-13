# host-simple-ipam

A golang simple and stateless ipam. It allows you to get free ips from a subnet. IPs are looked for use using ICMP.

It was created to be a companion for Docker macvlan networks and since a host can not contact ips it manages through macvlan, ICMP can not work with them, that is why this binary can look for used ips in the subnet being a Docker client and inspecting a Docker network list you provided.
