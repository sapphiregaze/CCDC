# Custom router with NFTables/IPTables/netmap

## **1. Basic System and Network Management**

### **Networking Configuration**
- Configure interfaces using `ip`:
  ```bash
  ip link set <interface> up            # Bring interface up
  ip addr add <IP/CIDR> dev <interface> # Assign an IP address
  ip route add <network> via <gateway> # Add a route
  ```

- Use `ifconfig` (optional):
  ```bash
  ifconfig <interface> up
  ifconfig <interface> <IP> netmask <netmask>
  ```

- Check active routes:
  ```bash
  ip route show
  ```

- DNS configuration:
  Edit `/etc/resolv.conf`:
  ```bash
  nameserver <DNS_IP>
  ```

## **2. nftables Commands**

### **Setup Basics**
- Enable and start the **nftables** service:
  ```bash
  apk add nftables
  rc-service nftables start
  rc-update add nftables
  ```

- List active nftables rules:
  ```bash
  nft list ruleset
  ```

### **Manage Rules**
- Add a table:
  ```bash
  nft add table ip filter
  ```

- Add a chain:
  ```bash
  nft add chain ip filter input { type filter hook input priority 0 \; }
  ```

- Add rules to a chain:
  ```bash
  nft add rule ip filter input ip saddr <source_ip> drop
  nft add rule ip filter input ip protocol tcp dport 80 accept
  ```

- Save and restore rules:
  ```bash
  nft list ruleset > /etc/nftables.conf
  nft -f /etc/nftables.conf
  ```

## **3. iptables Commands**

(If using **iptables** instead of or alongside **nftables**)

### **Setup Basics**
- Enable and start the **iptables** service:
  ```bash
  rc-service iptables start
  rc-update add iptables
  ```

- Check current rules:
  ```bash
  iptables -L -v -n
  ```

### **Manage Rules**
- Add rules:
  ```bash
  iptables -A INPUT -p tcp --dport 22 -j ACCEPT
  iptables -A FORWARD -i <LAN_IFACE> -o <WAN_IFACE> -j ACCEPT
  iptables -t nat -A POSTROUTING -o <WAN_IFACE> -j MASQUERADE
  ```

- Delete rules:
  ```bash
  iptables -D INPUT -p tcp --dport 22 -j ACCEPT
  ```

- Save and restore rules:
  ```bash
  iptables-save > /etc/iptables/rules.v4
  iptables-restore < /etc/iptables/rules.v4
  ```

## **4. netmap Commands**

### **Compile and Load netmap**
1. Clone and build netmap:
   ```bash
   git clone https://github.com/luigirizzo/netmap.git
   cd netmap
   ./configure --kernel-dir=/usr/src/linux
   make
   sudo make install
   ```

2. Load the `netmap` module:
   ```bash
   modprobe netmap
   ```

3. Check if the module is loaded:
   ```bash
   lsmod | grep netmap
   ```

### **netmap Utilities**
- **pkt-gen** (traffic generator):
  - Send packets on an interface:
    ```bash
    pkt-gen -i <interface> -f tx
    ```
  - Receive packets on an interface:
    ```bash
    pkt-gen -i <interface> -f rx
    ```

- **Bridge Mode**:
  - Run a netmap bridge between two interfaces:
    ```bash
    ./examples/bridge -i <interface1> -i <interface2>
    ```

## **5. Enable IP Forwarding**

### **Temporarily Enable Forwarding**
```bash
echo 1 > /proc/sys/net/ipv4/ip_forward
```

### **Permanently Enable Forwarding**
Edit `/etc/sysctl.conf`:
```bash
net.ipv4.ip_forward = 1
```
Apply changes:
```bash
sysctl -p
```

## **6. DHCP and NAT Setup (probably unneccessary this time) **

### **DHCP**
Install and configure `dnsmasq` as a DHCP server:
```bash
apk add dnsmasq
```

Edit `/etc/dnsmasq.conf`:
```conf
interface=<LAN_INTERFACE>
dhcp-range=192.168.1.100,192.168.1.200,12h
```

Start and enable the service:
```bash
rc-service dnsmasq start
rc-update add dnsmasq
```

### **NAT**
Set up NAT with **iptables**:
```bash
iptables -t nat -A POSTROUTING -o <WAN_INTERFACE> -j MASQUERADE
```

## **7. Monitor and Debug**

### **Network Monitoring**
- Check active connections:
  ```bash
  ss -tuln
  ```

- Capture traffic with **tcpdump**:
  ```bash
  tcpdump -i <interface> port 80
  ```

### **nftables Debugging**
- Trace a rule:
  ```bash
  nft monitor trace
  ```

## Example

```bash

nft flush ruleset

nft add table ip filter
nft add chain ip filter input { type filter hook input priority 0 \; }
nft add chain ip filter forward { type filter hook forward priority 0 \; }
nft add chain ip filter output { type filter hook output priority 0 \; }

# Default policy
nft add rule ip filter input drop
nft add rule ip filter forward drop
nft add rule ip filter output accept

# Allow loopback traffic
nft add rule ip filter input iif lo accept

# Allow established connections
nft add rule ip filter input ct state established,related accept

# Allow SSH
nft add rule ip filter input tcp dport 22 accept

# Allow LAN traffic
nft add rule ip filter forward iif <LAN_INTERFACE> oif <WAN_INTERFACE> accept
nft add rule ip filter forward iif <WAN_INTERFACE> oif <LAN_INTERFACE> ct state established,related accept

# Enable NAT
nft add table ip nat
nft add chain ip nat postrouting { type nat hook postrouting priority 100 \; }
nft add rule ip nat postrouting oif <WAN_INTERFACE> masquerade
```

## IPTables Example NAT setup (subnet based)

```bash

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configure NAT for outbound traffic (SNAT)
echo "Setting up SNAT..."
iptables -t nat -A POSTROUTING -o eth0 -s 192.168.220.0/24 -j SNAT --to-source 10.100.XX.2 #router ip is XX.2

# Configure DNAT for inbound traffic (entire subnet)
echo "Setting up DNAT..."
iptables -t nat -A PREROUTING -i eth0 -d 10.100.XX.0/24 -j DNAT --to-destination 192.168.220.0/24

# Allow forwarding between subnets
echo "Configuring forwarding rules..."
iptables -A FORWARD -i eth0 -o eth1 -s 10.100.XX.0/24 -d 192.168.220.0/24 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth1 -o eth0 -s 192.168.220.0/24 -d 10.100.XX.0/24 -m state --state ESTABLISHED,RELATED -j ACCEPT

# Save iptables rules (optional)
echo "Saving iptables rules..."
iptables-save > /etc/iptables/rules.v4
```

## IPTables Example NAT setup (single mappings)

```bash
# DNAT
iptables -t nat -A PREROUTING -i eth0 -d 10.100.100.11 -j DNAT --to-destination 192.168.220.11
iptables -t nat -A PREROUTING -i eth0 -d 10.100.100.12 -j DNAT --to-destination 192.168.220.12

#Forwarding
iptables -A FORWARD -i eth0 -o eth1 -d 192.168.220.11 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -d 192.168.220.12 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#Port-Based
iptables -A FORWARD -i eth0 -o eth1 -p tcp -d 192.168.220.10 --dport 80 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i eth0 -o eth1 -p tcp -d 192.168.220.10 --dport 443 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# Save rules
iptables-save > /etc/iptables/rules.v4
```

## Flushing IPTables rules

```bash
iptables -F
iptables -t nat -F
iptables -X
iptables -t nat -X
```

## Flushing NFTables rules

```bash
nft flush ruleset
```

## NFTables Example NAT Setup (subnet based)

```bash
# Define NAT and filter tables
echo "Creating nftables tables and chains..."
nft add table ip nat
nft add chain ip nat prerouting { type nat hook prerouting priority 0; }
nft add chain ip nat postrouting { type nat hook postrouting priority 100; }

nft add table ip filter
nft add chain ip filter input { type filter hook input priority 0; policy drop; }
nft add chain ip filter forward { type filter hook forward priority 0; policy drop; }
nft add chain ip filter output { type filter hook output priority 0; policy accept; }

echo "Adding NAT rules..."
# DNAT: External subnet 10.100.XX.0/24 to Internal subnet 192.168.220.0/24
nft add rule ip nat prerouting iif "eth0" ip daddr 10.100.XX.0/24 dnat to 192.168.220.0/24

# SNAT: Internal subnet 192.168.220.0/24 to External subnet 10.100.XX.0/24
nft add rule ip nat postrouting oif "eth0" ip saddr 192.168.220.0/24 snat to 10.100.XX.0/24

# Forwarding rules
echo "Adding forwarding rules..."
# Allow forwarding from 10.100.XX.0/24 to 192.168.220.0/24
nft add rule ip filter forward iif "eth0" oif "eth1" ip saddr 10.100.XX.0/24 ip daddr 192.168.220.0/24 ct state new,established,related accept

# Allow forwarding from 192.168.220.0/24 to 10.100.XX.0/24
nft add rule ip filter forward iif "eth1" oif "eth0" ip saddr 192.168.220.0/24 ip daddr 10.100.XX.0/24 ct state established,related accept

# Input rules (optional)
echo "Setting up input rules..."
nft add rule ip filter input iif lo accept
nft add rule ip filter input ct state established,related accept
nft add rule ip filter input iif "eth0" drop

# Save ruleset
echo "Saving nftables rules..."
nft list ruleset > /etc/nftables.conf

echo "nftables NAT and forwarding setup complete!"
```
