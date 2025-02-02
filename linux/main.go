package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	SHELL        = "bash"
	DEFAULT_CIDR = "192.168.0.0/24"
)

func main() {
	fmt.Print("Enter CIDR (default is 192.168.0.0/24): ")
	cidr := readInput(DEFAULT_CIDR)

	fmt.Print("Enter Username: ")
	username := readInput("")

	fmt.Print("Enter Password: ")
	password := readInput("")

	fmt.Printf("Scanning network: %s\n", cidr)
	onlineHosts := scanNetwork(cidr)

	fmt.Println("--- Online Hosts ---")
	for _, host := range onlineHosts {
		fmt.Println(host)
	}

	fmt.Println("\n--- SSH Execution Results ---")
	var (
		wg             sync.WaitGroup
		mu             sync.Mutex
		succeededHosts []string
	)

	for _, host := range onlineHosts {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()

			if err := copyFileToRemote(host, username, password, "./install_python.sh", "./"); err != nil {
				fmt.Println("Error copying file to", host, ":", err)
				return
			}

			executeRemoteCommand(host, username, password, "bash install_python.sh")

			keyPath := os.ExpandEnv("$HOME/.ssh/id_ed25519.pub")
			if err := addPublicKeyToRemote(keyPath, host, username, password, 22); err != nil {
				fmt.Println("Error adding public key to", host, ":", err)
				return
			}

			// Add host to succeededHosts if all steps succeed
			mu.Lock()
			succeededHosts = append(succeededHosts, host)
			mu.Unlock()
		}(host)
	}

	wg.Wait()

	fmt.Println("\nSucceeded Hosts:", succeededHosts)
}

func shellout(command string) (string, string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(SHELL, "-c", command)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func readInput(defaultValue string) string {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	input := scanner.Text()

	if strings.TrimSpace(input) == "" {
		return defaultValue
	}
	return input
}

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

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func isHostOnline(ip string) bool {
	out, _, err := shellout(fmt.Sprintf("ping -c 1 -W 1 %s", ip))
	return err == nil && len(out) > 0
}

func executeRemoteCommand(host, username, password, command string) {
	session := initSession(host, username, password)
	if session == nil {
		return
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

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
	case <-time.After(10 * time.Second):
		log.Printf("[ERROR] Command timed out on %s\n", host)
	}
}

func initSession(host, username, password string) *ssh.Session {
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:22", host), config)
	if err != nil {
		log.Printf("[ERROR] Failed to connect to %s: %v\n", host, err)
		return nil
	}

	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		log.Printf("[ERROR] Failed to create session for %s: %v\n", host, err)
		return nil
	}

	return session
}

func addPublicKeyToRemote(keyPath, host, user, password string, port int) error {
	publicKey, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", host, port), config)
	if err != nil {
		return fmt.Errorf("failed to dial: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create session: %v", err)
	}
	defer session.Close()

	cmd := fmt.Sprintf("mkdir -p ~/.ssh && chmod 700 ~/.ssh && echo '%s' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys", string(publicKey))

	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to add key: %v", err)
	}

	return nil
}

func copyFileToRemote(host, username, password, localFile, remotePath string) error {
	session := initSession(host, username, password)
	if session == nil {
		return fmt.Errorf("failed to create SSH session")
	}
	defer session.Close()

	file, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("failed to open local file: %v", err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat local file: %v", err)
	}

	remoteFileName := filepath.Base(localFile)

	go func() {
		w, _ := session.StdinPipe()
		defer w.Close()
		fmt.Fprintf(w, "C0644 %d %s\n", fileInfo.Size(), remoteFileName)
		io.Copy(w, file)
		fmt.Fprint(w, "\x00")
	}()

	cmd := fmt.Sprintf("scp -t %s", remotePath)
	if err := session.Run(cmd); err != nil {
		return fmt.Errorf("failed to run SCP command: %v", err)
	}

	return nil
}
