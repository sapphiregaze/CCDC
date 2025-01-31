package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os/exec"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	SHELL        = "bash"
	DEFAULT_CIDR = "192.168.0.0/24"
	USERNAME     = ""
	PASSWORD     = ""
)

func main() {
	// Scan a provided network range or the default local network
	networkRange := DEFAULT_CIDR
	fmt.Printf("Scanning network: %s\n", networkRange)
	onlineHosts := scanNetwork(networkRange)

	fmt.Println("--- Online Hosts ---")
	for _, host := range onlineHosts {
		fmt.Println(host)
	}

	// Try establishing SSH connections and executing commands
	fmt.Println("\n--- SSH Execution Results ---")
	var wg sync.WaitGroup
	for _, host := range onlineHosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			executeRemoteCommand(host, USERNAME, PASSWORD, "ls")
		}(host)
	}
	wg.Wait()
}

// Execute shell commands
func shellout(command string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(SHELL, "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

// Scan a network range for online hosts
func scanNetwork(networkRange string) []string {
	ipList := generateIPList(networkRange)
	var onlineHosts []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, ip := range ipList {
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			if isHostOnline(ip) {
				mu.Lock()
				onlineHosts = append(onlineHosts, ip)
				mu.Unlock()
			}
		}(ip)
	}

	wg.Wait()
	return onlineHosts
}

// Generate a list of IP addresses from the CIDR
func generateIPList(networkRange string) []string {
	ip, ipnet, err := net.ParseCIDR(networkRange)
	if err != nil {
		log.Fatalf("Invalid CIDR: %v", err)
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	return ips
}

// Increment an IP address
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Check if a host is online using ping
func isHostOnline(ip string) bool {
	out, _, err := shellout(fmt.Sprintf("ping -c 1 -W 1 %s", ip))
	return err == nil && len(out) > 0
}

// Execute a remote SSH command
func executeRemoteCommand(host, username, password, command string) {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second, // Add timeout for robustness
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", host), config)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to %s: %v\n", host, err)
		return
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		log.Printf("[ERROR] Failed to create session for %s: %v\n", host, err)
		return
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Run the command with a timeout
	done := make(chan error, 1)
	go func() {
		done <- session.Run(command)
	}()

	select {
	case err := <-done:
		if err != nil {
			log.Printf("[ERROR] Failed to execute command on %s: %v\nStderr: %s\n", host, err, stderr.String())
		} else {
			log.Printf("[SUCCESS] Command executed on %s:\n%s", host, stdout.String())
		}
	case <-time.After(10 * time.Second): // Adjust the timeout as needed
		log.Printf("[ERROR] Command timed out on %s\n", host)
	}
}
