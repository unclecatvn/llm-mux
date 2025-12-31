package util

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"

	"github.com/nghyane/llm-mux/internal/config"
	"golang.org/x/net/proxy"
)

func SetProxy(cfg *config.SDKConfig, httpClient *http.Client) *http.Client {
	var transport *http.Transport
	proxyURL, errParse := url.Parse(cfg.ProxyURL)
	if errParse == nil {
		switch proxyURL.Scheme {
		case "socks5":
			var proxyAuth *proxy.Auth
			if proxyURL.User != nil {
				username := proxyURL.User.Username()
				password, _ := proxyURL.User.Password()
				proxyAuth = &proxy.Auth{User: username, Password: password}
			}
			dialer, errSOCKS5 := proxy.SOCKS5("tcp", proxyURL.Host, proxyAuth, proxy.Direct)
			if errSOCKS5 != nil {
				slog.Error(fmt.Sprintf("create SOCKS5 dialer failed: %v", errSOCKS5))
				return httpClient
			}
			transport = &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.Dial(network, addr)
				},
			}
		case "http", "https":
			transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
		}
	}
	if transport != nil {
		httpClient.Transport = transport
	}
	return httpClient
}
