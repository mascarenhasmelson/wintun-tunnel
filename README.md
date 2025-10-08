# Wintun Tunnel on Windows

This project demonstrates how to build a simple VPN-like tunnel using the [Wintun](https://www.wintun.net/) virtual network interface on Windows. 


##  Features

- Creates a virtual network adapter using Wintun
- Assigns an IP address and routing rules
- Reads IP packets
- Demonstrates ping and ICMP packet handling

---

##  Prerequisites

- Go installed (https://golang.org/dl/)
- `wintun.dll` (Download from [WireGuard/wintun](https://github.com/WireGuard/wintun))
- Windows OS with Administrator privileges

---

##  How to Run

### 1. Clone the repository
```
git clone https://github.com/mascarenhasmelson/wintun-tunnel.git
cd wintun-tunnel