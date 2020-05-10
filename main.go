package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/google/go-cmp/cmp"
	"github.com/tatsushid/go-fastping"
	"log"
	"math/big"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

func main() {
	var (
		subnet                    = flag.String("subnet", "192.168.0.0/24", "Subnet to look for free IPs")
		excludeIps                = flag.String("exclude-ips", "", "IPs you want to ignore (separated by comma if you want to specify several ones)")
		pingMaxTtlMs              = flag.Int64("ping-max-ttl-ms", 2000, "Ping max ttl in ms (2000ms by default)")
		notInDockerNetworks       = flag.String("not-used-in-docker-networks", "", "Docker network to look for already used IPs (separated by comma if you want to specify several ones)")
		limit                     = flag.Int("limit", 0, "Number of IPs you want to pick (default 0, means all)")
		skipFirst                 = flag.Bool("skip-first", true, "Skip first IP in subnet")
		skipLast                  = flag.Bool("skip-last", true, "Skip last IP in subnet")
		addrs                     []net.IP
		ipv4                      bool
		excludeIpsParsed          = []string{}
		notInDockerNetworksParsed = []string{}
		mu                        sync.Mutex
	)

	flag.Parse()

	ip, ipNet, err := net.ParseCIDR(*subnet)

	if err == nil {
		ipToV4 := ip.To4()
		ipv4 = (ipToV4 != nil)

		addrsMaxLen := AddressCount(ipNet)
		addrs = make([]net.IP, 0, addrsMaxLen)

		nIp := ip
		p := fastping.NewPinger()
		p.MaxRTT = time.Duration(*pingMaxTtlMs) * time.Millisecond
		p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
			mu.Lock()

			ipIdx := -1
			for idx, ip := range addrs {
				if cmp.Equal(ip, addr.IP) {
					ipIdx = idx
					break
				}
			}

			if ipIdx > -1 {
				addrs[ipIdx] = addrs[len(addrs)-1]
				addrs = addrs[:len(addrs)-1]
			}
			mu.Unlock()
		}

		if *excludeIps != "" {
			excludeIpsParsed = strings.Split(*excludeIps, ",")
		}

		if *notInDockerNetworks != "" {
			notInDockerNetworksParsed = strings.Split(*notInDockerNetworks, ",")
		}

		var usedIpsInDocker = []string{}

		if len(notInDockerNetworksParsed) > 0 {
			cli, err := client.NewClientWithOpts(client.FromEnv)
			if err != nil {
				log.Fatalf("%s", err)
			}

			for _, dockerNet := range notInDockerNetworksParsed {
				ntwk, err := cli.NetworkInspect(context.Background(), dockerNet, types.NetworkInspectOptions{})
				if err != nil {
					log.Fatalf("%s", err)
					continue
				}

				for _, ct := range ntwk.Containers {
					var ctIp net.IP
					if ipv4 {
						ctIp, _, err = net.ParseCIDR(ct.IPv4Address)
					} else {
						ctIp, _, err = net.ParseCIDR(ct.IPv6Address)
					}
					if err == nil {
						if ipNet.Contains(ctIp) {
							usedIpsInDocker = append(usedIpsInDocker, ctIp.String())
						}
					}
				}

			}
		}

		sort.Strings(excludeIpsParsed)
		sort.Strings(usedIpsInDocker)
		excludeIpsParsedLen := len(excludeIpsParsed)
		usedIpsInDockerLen := len(usedIpsInDocker)

		if *skipFirst {
			nIp = Inc(nIp)
		}
		_, lastIp := AddressRange(ipNet)

		for ; ipNet.Contains(nIp); nIp = Inc(nIp) {
			if *skipLast && (lastIp.String() == nIp.String()) {
				break
			}

			if sort.SearchStrings(excludeIpsParsed, nIp.String()) >= excludeIpsParsedLen && sort.SearchStrings(usedIpsInDocker, nIp.String()) >= usedIpsInDockerLen {
				addrs = append(addrs, nIp)
				p.AddIP(nIp.String())
			}
		}

		err = p.Run()
		if err != nil {
			log.Fatalf("%s", err)
		}

		sort.Slice(addrs, func(i, j int) bool {
			return (bytes.Compare(addrs[i], addrs[j]) < 0)
		})

		if *limit == 0 {
			for _, ip := range addrs {
				fmt.Printf("%s\n", ip)
			}
		} else {
			i := 0
			for _, ip := range addrs {
				if i < *limit {
					fmt.Printf("%s\n", ip)
					i++
				} else {
					break
				}
			}
		}

	} else {
		log.Fatalf("%s", err)
	}
}

func AddressRange(network *net.IPNet) (net.IP, net.IP) {
	// the first IP is easy
	firstIP := network.IP

	// the last IP is the network address OR NOT the mask address
	prefixLen, bits := network.Mask.Size()
	if prefixLen == bits {
		// Easy!
		// But make sure that our two slices are distinct, since they
		// would be in all other cases.
		lastIP := make([]byte, len(firstIP))
		copy(lastIP, firstIP)

		return firstIP, lastIP
	}

	firstIPInt, bits := IpToInt(firstIP)
	hostLen := uint(bits) - uint(prefixLen)
	lastIPInt := big.NewInt(1)
	lastIPInt.Lsh(lastIPInt, hostLen)
	lastIPInt.Sub(lastIPInt, big.NewInt(1))
	lastIPInt.Or(lastIPInt, firstIPInt)

	return firstIP, IntToIP(lastIPInt, bits)
}

func IpToInt(ip net.IP) (*big.Int, int) {
	val := &big.Int{}
	val.SetBytes([]byte(ip))
	if len(ip) == net.IPv4len {
		return val, 32
	} else if len(ip) == net.IPv6len {
		return val, 128
	} else {
		panic(fmt.Errorf("Unsupported address length %d", len(ip)))
	}
}

func IntToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	ret := make([]byte, bits/8)
	// Pack our IP bytes into the end of the return array,
	// since big.Int.Bytes() removes front zero padding.
	for i := 1; i <= len(ipBytes); i++ {
		ret[len(ret)-i] = ipBytes[len(ipBytes)-i]
	}

	return net.IP(ret)
}

func AddressCount(network *net.IPNet) uint64 {
	prefixLen, bits := network.Mask.Size()
	return 1 << (uint64(bits) - uint64(prefixLen))
}

func Inc(IP net.IP) net.IP {
	IP = checkIPv4(IP)
	incIP := make([]byte, len(IP))
	copy(incIP, IP)
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++
		if incIP[j] > 0 {
			break
		}
	}
	return incIP
}

func checkIPv4(ip net.IP) net.IP {
	// Go for some reason allocs IPv6len for IPv4 so we have to correct it
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}
