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

type PingBulkResult struct {
	Processed uint
	Unreached uint
}

const (
	QueryModeGetFreeIp = "get-free-ip"
	QueryModeGetRelatatedLocalInterface = "get-related-local-interface"
)

func main() {
	var (
		subnet                    = flag.String("subnet", "192.168.0.0/24", "Subnet to look for free IPs")
		excludeIps                = flag.String("exclude-ips", "", "IPs you want to ignore (separated by comma if you want to specify several ones)")
		pingMaxTtlMs              = flag.Int64("ping-max-ttl-ms", 2000, "Ping max ttl in ms (2000ms by default)")
		notInDockerNetworks       = flag.String("not-used-in-docker-networks", "", "Docker network to look for already used IPs (separated by comma if you want to specify several ones)")
		limit                     = flag.Uint64("limit", 0, "Number of IPs you want to pick/limit returned interfaces count in get-including-interface query mode (default 0, means all)")
		skipFirst                 = flag.Bool("skip-first", true, "Skip first IP in subnet")
		skipLast                  = flag.Bool("skip-last", true, "Skip last IP in subnet")
		bulkSize                  = flag.Uint("bulk-size", 20, "Ping concurrency")
		queryMode                 = flag.String("query-mode", "get-free-ip", "Query mode (get-free-ip, get-related-local-interface)")
		ipChan                    chan net.IP
		ipv4                      bool
		excludeIpsParsed          = []string{}
		notInDockerNetworksParsed = []string{}
	)

	flag.Parse()

	ip, ipNet, err := net.ParseCIDR(*subnet)

	if err == nil {
		if *queryMode == QueryModeGetRelatatedLocalInterface {
			itfInc := 0

			itfs, err := net.Interfaces()
			if err == nil {
				for _, itf := range itfs {
					itfAddrs, err := itf.Addrs()
					if err == nil {

						for _, addr := range itfAddrs {
							ip, _, err := net.ParseCIDR(addr.String())
							if err == nil {
								if ipNet.Contains(ip) {
									if int(*limit) == 0 || itfInc < int(*limit) {
										fmt.Printf("%s\n", itf.Name)
									} else {
										return
									}
									itfInc++
								}
							}
						}
					}
				}
			} else {
				log.Fatalf("%s\n", err)
			}
			return
		}

		ipv4 = (nil != ip.To4())

		ipChan = make(chan net.IP, 5)
		procChan := make(chan PingBulkResult, 5)

		if *limit > 0 && *limit < uint64(*bulkSize) {
			*bulkSize = uint(*limit)
		}

		nIp := ip

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
				log.Fatalf("%s\n", err)
			}

			for _, dockerNet := range notInDockerNetworksParsed {
				ntwk, err := cli.NetworkInspect(context.Background(), dockerNet, types.NetworkInspectOptions{})
				if err != nil {
					log.Fatalf("%s\n", err)
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

		go BulkPingIps(ipChan, procChan, time.Duration(*pingMaxTtlMs)*time.Millisecond, *bulkSize, *limit)

		var (
			count, processed, unreached uint64
			batch, n                    uint
		)

		count = 0
		batch = 0
		processed = 0
		unreached = 0

		for ; ipNet.Contains(nIp); nIp = Inc(nIp) {
			if *skipLast && (lastIp.String() == nIp.String()) {
				break
			}

			if sort.SearchStrings(excludeIpsParsed, nIp.String()) >= excludeIpsParsedLen && sort.SearchStrings(usedIpsInDocker, nIp.String()) >= usedIpsInDockerLen {

				if *limit > 0 && unreached >= *limit {
					break
				}

				if batch == *bulkSize {
					n = 0

					for n < *bulkSize {
						select {
						case bRes, more := <-procChan:
							if more {
								n += bRes.Processed
								unreached += uint64(bRes.Unreached)
							}
						default:
						}
					}
					processed += uint64(*bulkSize)
					batch = 0
				}
				ipChan <- nIp
				batch++
				count++
			}
		}

		close(ipChan)
		for processed < count {
			select {
			case bRes, more := <-procChan:
				if more {
					processed += uint64(bRes.Processed)
					unreached += uint64(bRes.Unreached)
				} else {
					break
				}
			default:
			}
		}
		close(procChan)

	} else {
		log.Fatalf("%s\n", err)
	}
}

func BulkPingIps(ipChan chan net.IP, procChan chan PingBulkResult, pingMaxTtlMs time.Duration, bulkSize uint, limit uint64) {

	var (
		mu    sync.Mutex
		addrs []net.IP
	)

	addrs = make([]net.IP, 0, bulkSize)

	p := fastping.NewPinger()
	p.MaxRTT = pingMaxTtlMs
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
		p.RemoveIPAddr(addr)
	}

	var (
		totalUnreached uint64
		batch          uint
	)
	totalUnreached = 0
	batch = 0

	for {
		select {
		case ip, more := <-ipChan:

			if more {
				addrs = append(addrs, ip)
				p.AddIP(ip.String())
				batch++

				if batch == bulkSize {
					err := p.Run()
					if err != nil {
						log.Fatalf("%s\n", err)
					}
					batch = 0

					sort.Slice(addrs, func(i, j int) bool {
						return (bytes.Compare(addrs[i], addrs[j]) < 0)
					})

					var (
						unreached uint
					)

					unreached = 0
					for _, addr := range addrs {
						if limit > 0 {
							if totalUnreached < limit {
								fmt.Printf("%s\n", addr)
							}
						} else {
							fmt.Printf("%s\n", addr)
						}
						p.RemoveIP(addr.String())
						unreached++
						totalUnreached++
					}

					addrs = addrs[:0]
					procChan <- PingBulkResult{bulkSize, unreached}
				}

			} else {
				var (
					processed, unreached uint
				)

				processed = uint(len(addrs))
				err := p.Run()
				if err != nil {
					log.Fatalf("%s\n", err)
				}
				unreached = 0
				for _, addr := range addrs {
					if limit == 0 || totalUnreached < limit {
						fmt.Printf("%s\n", addr)
					}
					unreached++
					totalUnreached++
				}
				procChan <- PingBulkResult{processed, unreached}
				break
			}
		default:
		}
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
