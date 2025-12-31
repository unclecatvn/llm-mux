package util

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

var ipServices = []string{
	"https://api.ipify.org",
	"https://ifconfig.me/ip",
	"https://icanhazip.com",
	"https://ipinfo.io/ip",
}

func getPublicIP() (string, error) {
	for _, service := range ipServices {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, "GET", service, nil)
		if err != nil {
			slog.Debug(fmt.Sprintf("Failed to create request to %s: %v", service, err))
			continue
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			slog.Debug(fmt.Sprintf("Failed to get public IP from %s: %v", service, err))
			continue
		}
		defer func() {
			if closeErr := resp.Body.Close(); closeErr != nil {
				slog.Warn(fmt.Sprintf("Failed to close response body from %s: %v", service, closeErr))
			}
		}()

		if resp.StatusCode != http.StatusOK {
			slog.Debug(fmt.Sprintf("bad status code from %s: %d", service, resp.StatusCode))
			continue
		}

		ip, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Debug(fmt.Sprintf("Failed to read response body from %s: %v", service, err))
			continue
		}
		return strings.TrimSpace(string(ip)), nil
	}
	return "", fmt.Errorf("all IP services failed")
}

func getOutboundIP() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer func() {
		if closeErr := conn.Close(); closeErr != nil {
			slog.Warn(fmt.Sprintf("Failed to close UDP connection: %v", closeErr))
		}
	}()

	localAddr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", fmt.Errorf("could not assert UDP address type")
	}

	return localAddr.IP.String(), nil
}

func GetIPAddress() string {
	publicIP, err := getPublicIP()
	if err == nil {
		slog.Debug(fmt.Sprintf("Public IP detected: %s", publicIP))
		return publicIP
	}
	slog.Warn(fmt.Sprintf("Failed to get public IP, falling back to outbound IP: %v", err))
	outboundIP, err := getOutboundIP()
	if err == nil {
		slog.Debug(fmt.Sprintf("Outbound IP detected: %s", outboundIP))
		return outboundIP
	}
	slog.Error(fmt.Sprintf("Failed to get any IP address: %v", err))
	return "127.0.0.1"
}

func PrintSSHTunnelInstructions(port int) {
	ipAddress := GetIPAddress()
	border := "================================================================================"
	fmt.Println("To authenticate from a remote machine, an SSH tunnel may be required.")
	fmt.Println(border)
	fmt.Println("  Run one of the following commands on your local machine (NOT the server):")
	fmt.Println()
	fmt.Printf("  # Standard SSH command (assumes SSH port 22):\n")
	fmt.Printf("  ssh -L %d:127.0.0.1:%d root@%s -p 22\n", port, port, ipAddress)
	fmt.Println()
	fmt.Printf("  # If using an SSH key (assumes SSH port 22):\n")
	fmt.Printf("  ssh -i <path_to_your_key> -L %d:127.0.0.1:%d root@%s -p 22\n", port, port, ipAddress)
	fmt.Println()
	fmt.Println("  NOTE: If your server's SSH port is not 22, please modify the '-p 22' part accordingly.")
	fmt.Println(border)
}
