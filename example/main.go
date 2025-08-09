package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"simpletun/winipcfg"
	"strconv"
	"sync"
	"time"
	"unsafe"

	// "github.com/wintun/go/wintun"

	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/tun"
	//"golang.zx2c4.com/wireguard/tun/wintun"
)

// PortableSockaddr4 represents a 4-byte IP and 2-byte port.
type PortableSockaddr4 struct {
	Host uint32
	Port uint16
	Pad  [2]byte
}

const (
	// Buffer size for TUN interface.
	BufferSize = 10000
	// Keepalive interval and timeout.
	KeepaliveInterval = 3 * time.Second  // Reduced for faster recovery
	Timeout           = 60 * time.Second // Tolerates ICMP traffic
)

// Azure temp public IP
var (
	serverAddr = flag.String("server", "172.203.221.128", "Remote server IP or hostname")
	serverPort = flag.Int("port", 2001, "Remote server UDP port")
)

// func deleteExistingAdapter(name string) {
// 	pool, err := wintun.MakePool(name)
// 	if err != nil {
// 		log.Fatalf("Failed to create pool: %v", err)
// 	}

// 	log.Println("Checking for existing adapter")
// 	adapter, err := pool.OpenAdapter(name)
// 	if err == nil {
// 		log.Printf("Deleting existing adapter %v", adapter.LUID())
// 		_, err = adapter.Delete(true) // `true` = force delete
// 		if err != nil {
// 			log.Fatalf("Failed to delete existing adapter: %v", err)
// 		}
// 		log.Println("Adapter deleted successfully")
// 	} else {
// 		log.Println("No existing adapter to delete")
// 	}
// }

// addRoute adds a route using the Windows route command.
func addRoute(dst, gw, ifname string) error {
	_, dstNet, err := net.ParseCIDR(dst)
	if err != nil {
		return fmt.Errorf("failed to parse CIDR %s: %w", dst, err)
	}
	i, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifname, err)
	}
	params := []string{
		"add",
		dstNet.IP.String(),
		"mask",
		net.IP(dstNet.Mask).String(),
		gw,
		"if",
		strconv.Itoa(i.Index),
	}
	fmt.Printf("Adding route: route %s\n", params)
	cmd := exec.Command("route", params...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add route: %w, output: %s", err, output)
	}
	fmt.Println("Route added successfully")
	return nil
}

// CreateInterface sets up a TUN interface with the specified IP address.
func CreateInterface() (tun.Device, error) {
	id := &windows.GUID{
		0x0000000,
		0xFFFF,
		0xFFFF,
		[8]byte{0xFF, 0xe9, 0x76, 0xe5, 0x8c, 0x74, 0x06, 0x3e},
	}
	ifname := "Test"
	fmt.Printf("Creating Wintun interface: %s\n", ifname)
	dev, err := tun.CreateTUNWithRequestedGUID(ifname, id, 0)
	if err != nil {

		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}
	// defer deleteExistingAdapter(ifname)
	fmt.Println("Wintun interface created successfully")

	nativeTunDevice := dev.(*tun.NativeTun)
	link := winipcfg.LUID(nativeTunDevice.LUID())

	fmt.Println("Setting interface to up")
	cmd := exec.Command("netsh", "interface", "set", "interface", ifname, "admin=enable")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Warning: failed to set interface up via netsh: %v, output: %s (continuing)\n", err, output)
	} else {
		fmt.Println("Interface set to up successfully")
	}
	//CGNAT subnet group
	ip, err := netip.ParsePrefix("100.64.1.2/24")
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to parse IP prefix: %w", err)
	}
	fmt.Printf("Setting IP address: %s\n", ip.String())
	err = link.SetIPAddresses([]netip.Prefix{ip})
	if err != nil {
		dev.Close()
		return nil, fmt.Errorf("failed to set IP addresses: %w", err)
	}
	fmt.Println("IP address set successfully")

	cmd = exec.Command("netsh", "interface", "ipv4", "show", "route")
	output, _ = cmd.CombinedOutput()
	fmt.Printf("Current routes:\n%s\n", output)

	fmt.Printf("Adding route to 100.64.1.1/32\n")
	err = addRoute("100.64.1.1/32", "0.0.0.0", ifname)
	if err != nil {
		fmt.Printf("Warning: failed to add route: %v (continuing without route)\n", err)
		// Continue without route for testing
	} else {
		fmt.Println("Route added successfully")
	}

	cmd = exec.Command("netsh", "interface", "ipv4", "show", "route")
	output, _ = cmd.CombinedOutput()
	fmt.Printf("Routes after addition:\n%s\n", output)

	fmt.Println("Interface configuration completed")
	return dev, nil
}

// addrEqual compares two UDP addresses for equality.
func addrEqual(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return false
	}
	return a.IP.Equal(b.IP) && a.Port == b.Port
}

type DataPacket struct {
	Data []byte
	Addr *net.UDPAddr
}

func main() {
	flag.Parse()

	// icmp check
	fmt.Println("Enabling ICMP in Windows Firewall")
	cmd := exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Allow ICMP", "dir=in", "action=allow", "protocol=icmpv4")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Warning: failed to enable ICMP: %v, output: %s\n", err, output)
	} else {
		fmt.Println("ICMP enabled successfully")
	}

	fmt.Printf("Resolving server address: %s\n", *serverAddr)
	ips, err := net.LookupIP(*serverAddr)
	if err != nil {
		fmt.Printf("Failed to resolve server address %s: %v\n", *serverAddr, err)
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		return
	}
	var serverIP net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			serverIP = ip
			break
		}
	}
	if serverIP == nil {
		fmt.Printf("No IPv4 address found for server %s\n", *serverAddr)
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		return
	}
	fmt.Printf("Resolved server IP: %s\n", serverIP)

	// Create TUN interface with retries (unchanged).
	var dev tun.Device
	for attempt := 1; attempt <= 3; attempt++ {
		fmt.Printf("Attempt %d/3: Creating TUN interface\n", attempt)
		dev, err = CreateInterface()
		if err == nil {
			break
		}
		fmt.Printf("Error creating interface: %v\n", err)
		if attempt < 3 {
			fmt.Println("Retrying after 2 seconds...")
			time.Sleep(2 * time.Second)
		}
	}
	if err != nil {
		fmt.Printf("Failed to create TUN interface after 3 attempts: %v\n", err)
		fmt.Println("Press Enter to exit...")
		fmt.Scanln()
		return
	}
	defer dev.Close()
	fmt.Println("TUN interface ready")

	// Log interface details (unchanged).
	cmd = exec.Command("netsh", "interface", "ipv4", "show", "interfaces")
	output, _ = cmd.CombinedOutput()
	fmt.Printf("Network interfaces:\n%s\n", output)

	// Server address for handshake.
	sinServer := &net.UDPAddr{IP: serverIP, Port: *serverPort}

	// Main loop for handshake and tunneling.
	for {
		// Create UDP socket with larger receive buffer.
		fmt.Println("Creating UDP socket for handshake")
		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err != nil {
			fmt.Printf("Failed to create UDP socket: %v\n", err)
			time.Sleep(1 * time.Second)
			continue
		}
		// Set larger receive buffer.
		err = conn.SetReadBuffer(1024 * 1024) // 1MB
		if err != nil {
			fmt.Printf("Warning: failed to set socket receive buffer: %v\n", err)
		}

		// Handshake to resolve remote address (unchanged).
		var sinRemote *net.UDPAddr
		fmt.Printf("Pinging handshake server %s:%d\n", serverIP, *serverPort)
		buf := make([]byte, BufferSize)
		for sinRemote == nil {
			start := time.Now()

			_, err = conn.WriteToUDP([]byte("A"), sinServer)
			if err != nil {
				fmt.Printf("Failed to send handshake: %v\n", err)
				time.Sleep(1 * time.Second)
				continue
			}

			// Check for response with short deadline.
			for {
				conn.SetReadDeadline(time.Now().Add(10 * time.Millisecond))
				n, addr, err := conn.ReadFromUDP(buf)
				if err == nil && n > 0 {
					fmt.Printf("Received %d bytes from %s:%d: %x\n", n, addr.IP, addr.Port, buf[:n])
					if n >= int(unsafe.Sizeof(PortableSockaddr4{})) && addrEqual(&net.UDPAddr{IP: sinServer.IP, Port: sinServer.Port}, addr) {
						host := binary.BigEndian.Uint32(buf[0:4])
						port := binary.BigEndian.Uint16(buf[4:6])
						if port > 65535 {
							fmt.Printf("Invalid port %d, skipping response\n", port)
						} else {
							ip := make(net.IP, 4)
							binary.BigEndian.PutUint32(ip, host)
							sinRemote = &net.UDPAddr{IP: ip, Port: int(port)}
							fmt.Printf("Resolved remote peer address: %s:%d\n", ip, port)
							if n > int(unsafe.Sizeof(PortableSockaddr4{})) {
								fmt.Printf("Extra bytes in handshake response: %x\n", buf[6:n])
							}
						}
					} else {
						fmt.Printf("Invalid response size %d or source %s:%d, expected at least %d from server\n", n, addr.IP, addr.Port, unsafe.Sizeof(PortableSockaddr4{}))
					}
				}
				if sinRemote != nil || time.Since(start) >= 1*time.Second {
					break
				}
			}

			// Ensure 1-second interval between pings.
			if sinRemote == nil {
				elapsed := time.Since(start)
				if elapsed < 1*time.Second {
					time.Sleep(1*time.Second - elapsed)
				}
			}
		}

		// testing peer connectivity
		fmt.Printf("Testing connectivity to peer %s:%d\n", sinRemote.IP, sinRemote.Port)
		n, err := conn.WriteToUDP([]byte("TEST"), sinRemote)
		if err != nil {
			fmt.Printf("Failed to send test packet to peer %s:%d: %v\n", sinRemote.IP, sinRemote.Port, err)
		} else {
			fmt.Printf("Successfully sent %d bytes test packet to peer %s:%d\n", n, sinRemote.IP, sinRemote.Port)
		}

		// start tunneling
		fmt.Printf("Starting tunnel to peer %s:%d\n", sinRemote.IP, sinRemote.Port)
		err = startTunnel(context.Background(), dev, conn, sinRemote)
		if err != nil {
			fmt.Printf("Tunnel failed: %v\n", err)
			conn.Close()
			fmt.Println("Attempting to restart tunnel")
			time.Sleep(1 * time.Second)
			continue
		}
		conn.Close()
	}
}

// startTunnel manages the tunneling process using goroutines.
func startTunnel(ctx context.Context, dev tun.Device, conn *net.UDPConn, peerAddr *net.UDPAddr) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// channels for data passing.
	tunToUDP := make(chan []byte, 100)     // TUN -> UDP
	udpToTUN := make(chan DataPacket, 100) // UDP -> TUN
	keepalive := make(chan struct{}, 1)    // Signal keepalive sent
	errors := make(chan error, 10)         // Collect errors from goroutines

	// wait group to ensure all goroutines complete.
	var wg sync.WaitGroup

	// last received and sent times for timeout tracking.
	var lastRcvd, lastSent, lastTest time.Time
	lastRcvd = time.Now()
	lastSent = time.Now()
	lastTest = time.Now()

	// read from TUN device.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, BufferSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, err := dev.Read(buf, 0)
				if err != nil {
					select {
					case errors <- fmt.Errorf("TUN read error: %w", err):
					case <-ctx.Done():
					}
					return
				}
				if n > 0 {

					data := make([]byte, n)
					copy(data, buf[:n])
					fmt.Printf("Read %d bytes from TUN", n)
					if n >= 20 && buf[0]>>4 == 4 && buf[9] == 1 { // IPv4 icmp check for connectivity with peer
						if buf[20] == 8 {
							fmt.Printf(" (ICMP echo request)\n")
						} else if buf[20] == 0 {
							fmt.Printf(" (ICMP echo reply)\n")
						} else {
							fmt.Printf(" (ICMP type %d)\n", buf[20])
						}
					} else {
						fmt.Println()
					}
					select {
					case tunToUDP <- data:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	// reading from UDP socket.
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, BufferSize)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, addr, err := conn.ReadFromUDP(buf)
				if err != nil {
					if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
						continue
					}
					select {
					case errors <- fmt.Errorf("UDP read error: %w", err):
					case <-ctx.Done():
					}
					return
				}
				if n > 0 {
					fmt.Printf("Received %d bytes from %s:%d: %x\n", n, addr.IP, addr.Port, buf[:n])
					data := make([]byte, n)
					copy(data, buf[:n])
					select {
					case udpToTUN <- DataPacket{Data: data, Addr: addr}:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	// writing to UDP socket.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case data := <-tunToUDP:
				n, err := conn.WriteToUDP(data, peerAddr)
				if err != nil {
					select {
					case errors <- fmt.Errorf("UDP write error: %w", err):
					case <-ctx.Done():
					}
					return
				}
				if n == len(data) {
					lastSent = time.Now()
					fmt.Printf("Sent %d bytes to peer %s:%d\n", n, peerAddr.IP, peerAddr.Port)
					select {
					case keepalive <- struct{}{}:
					default:
					}
				} else {
					fmt.Printf("Sent %d bytes, expected %d\n", n, len(data))
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// write to TUN device and process UDP packets.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case pkt := <-udpToTUN:
				if addrEqual(pkt.Addr, peerAddr) {
					lastRcvd = time.Now()
					if len(pkt.Data) == 1 && pkt.Data[0] == 0x00 {
						fmt.Printf("Received keepalive from peer %s:%d\n", pkt.Addr.IP, pkt.Addr.Port)
					} else if len(pkt.Data) >= 20 && pkt.Data[0]>>4 == 4 { // IPv4 packet
						proto := pkt.Data[9]
						if proto == 1 && pkt.Data[20] == 8 { // icmp echo req
							fmt.Printf("Received ICMP echo request from peer %s:%d, size %d\n", pkt.Addr.IP, pkt.Addr.Port, len(pkt.Data))
						} else if proto == 1 && pkt.Data[20] == 0 { // icmp echo reply
							fmt.Printf("Received ICMP echo reply from peer %s:%d, size %d\n", pkt.Addr.IP, pkt.Addr.Port, len(pkt.Data))
						} else {
							fmt.Printf("Received data packet from peer %s:%d, size %d, protocol %d\n", pkt.Addr.IP, pkt.Addr.Port, len(pkt.Data), proto)
						}
						if len(pkt.Data) > 1 {
							_, err := dev.Write(pkt.Data, 0)
							if err != nil {
								select {
								case errors <- fmt.Errorf("TUN write error: %w", err):
								case <-ctx.Done():
								}
								return
							}
						}
					} else {
						fmt.Printf("Received non-IPv4 packet from peer %s:%d, size %d\n", pkt.Addr.IP, pkt.Addr.Port, len(pkt.Data))
					}
				} else {
					fmt.Printf("Received packet from unexpected source %s:%d, size %d: %x\n", pkt.Addr.IP, pkt.Addr.Port, len(pkt.Data), pkt.Data)
					if len(pkt.Data) > 1 {
						_, err := dev.Write(pkt.Data, 0)
						if err != nil {
							select {
							case errors <- fmt.Errorf("TUN write error: %w", err):
							case <-ctx.Done():
							}
							return
						}
						lastRcvd = time.Now()
					}
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	// heartbeat code
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				now := time.Now()
				// sending heartbeat
				if now.Sub(lastSent) > KeepaliveInterval {
					fmt.Printf("Sending keepalive packet to peer %s:%d\n", peerAddr.IP, peerAddr.Port)
					n, err := conn.WriteToUDP([]byte{0x00}, peerAddr)
					if err != nil {
						select {
						case errors <- fmt.Errorf("keepalive send error: %w", err):
						case <-ctx.Done():
						}
						return
					}
					if n == 1 {
						fmt.Printf("Successfully sent %d bytes for keepalive to peer %s:%d\n", n, peerAddr.IP, peerAddr.Port)
						lastSent = now
						select {
						case keepalive <- struct{}{}:
						default:
						}
					} else {
						fmt.Printf("Sent %d bytes for keepalive, expected 1\n", n)
					}
				}
				// sending periodic test heartbeat.
				if now.Sub(lastTest) > 10*time.Second {
					fmt.Printf("Sending test packet to peer %s:%d\n", peerAddr.IP, peerAddr.Port)
					n, err := conn.WriteToUDP([]byte("TEST"), peerAddr)
					if err != nil {
						fmt.Printf("Failed to send test packet to peer %s:%d: %v\n", peerAddr.IP, peerAddr.Port, err)
					} else {
						fmt.Printf("Successfully sent %d bytes test packet to peer %s:%d\n", n, peerAddr.IP, peerAddr.Port)
					}
					lastTest = now
				}
				// timeout more than designated time.
				if now.Sub(lastRcvd) > Timeout {
					select {
					case errors <- fmt.Errorf("timeout: no packets received for %v", Timeout):
					case <-ctx.Done():
					}
					return
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	select {
	case err := <-errors:
		cancel()
		wg.Wait()
		return err
	case <-ctx.Done():
		wg.Wait()
		return ctx.Err()
	}
}
