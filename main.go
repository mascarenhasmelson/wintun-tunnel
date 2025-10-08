package main

import (
	"log"
	"net/netip"
	"github.com/mascarenhasmelson/wintun-tunnel/winipcfg"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/tun"
)

func main() {
	//luid
	id := &windows.GUID{
		0xdeadbabe,
		0xcafe,
		0xbeef,
		[8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef},
	}

	ifname := "Test"
	dev, err := tun.CreateTUNWithRequestedGUID(ifname, id, 0)
	if err != nil {
		panic(err)
	}
	defer dev.Close()

	nativeTunDevice := dev.(*tun.NativeTun)

	link := winipcfg.LUID(nativeTunDevice.LUID())

	ip, err := netip.ParsePrefix("100.64.1.1/24") //cgnat ip
	if err != nil {
		panic(err)
	}
	err = link.SetIPAddresses([]netip.Prefix{ip})
	if err != nil {
		panic(err)
	}

	n := 2048
	buf := make([]byte, n)
	//read packets
	for {
		n = 2048

		n, err = dev.Read(buf, 0)
		if err != nil {
			panic(err)
		}
		const ProtocolICMP = 1
		header, err := ipv4.ParseHeader(buf[:n])
		if err != nil {
			continue
		}
		//comparing ping
		if header.Protocol == ProtocolICMP {
			log.Println("source IP:", header.Src, " destination IP:", header.Dst)
			msg, _ := icmp.ParseMessage(ProtocolICMP, buf[header.Len:])
			log.Println(" icmp message echo:", msg.Type)
		}
	}
}
