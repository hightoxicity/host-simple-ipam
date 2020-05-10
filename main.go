package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
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
		addrs                     = make(map[string]*net.IP)
		excludeIpsParsed          = []string{}
		notInDockerNetworksParsed = []string{}
		mu                        sync.Mutex
	)

	flag.Parse()

	ip, ipNet, err := net.ParseCIDR(*subnet)

	if err == nil {
		nIp := ip
		p := fastping.NewPinger()
		p.MaxRTT = time.Duration(*pingMaxTtlMs) * time.Millisecond
		p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
			mu.Lock()
			delete(addrs, addr.IP.String())
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
					ctIp, _, err := net.ParseCIDR(ct.IPv4Address)
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
			nIp = NextIp(nIp, 1)
		}
		_, lastIp := AddressRange(ipNet)

		for ; ipNet.Contains(nIp); nIp = NextIp(nIp, 1) {
			if *skipLast && (lastIp.String() == nIp.String()) {
				break
			}

			if sort.SearchStrings(excludeIpsParsed, nIp.String()) >= excludeIpsParsedLen && sort.SearchStrings(usedIpsInDocker, nIp.String()) >= usedIpsInDockerLen {
				addrs[nIp.String()] = &nIp
				p.AddIP(nIp.String())
			}
		}

		err = p.Run()
		if err != nil {
			log.Fatalf("%s", err)
		}

		if *limit == 0 {
			for ipStr, _ := range addrs {
				fmt.Printf("%s\n", ipStr)
			}
		} else {
			i := 0
			for ipStr, _ := range addrs {
				if i < *limit {
					fmt.Printf("%s\n", ipStr)
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

func NextIp(ip net.IP, inc uint) net.IP {
	i := ip.To4()
	v := uint(i[0])<<24 + uint(i[1])<<16 + uint(i[2])<<8 + uint(i[3])
	v += inc
	v3 := byte(v & 0xFF)
	v2 := byte((v >> 8) & 0xFF)
	v1 := byte((v >> 16) & 0xFF)
	v0 := byte((v >> 24) & 0xFF)

	return net.IPv4(v0, v1, v2, v3)
}
