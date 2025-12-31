package service

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nghyane/llm-mux/internal/provider"
	log "github.com/nghyane/llm-mux/internal/logging"
	"golang.org/x/net/proxy"
)

// Optimized transport settings for API gateway workloads.
// These are duplicated from internal/runtime/executor/transport.go
// because SDK packages cannot import internal packages.
const (
	maxIdleConns          = 1000
	maxIdleConnsPerHost   = 100 // Default is 2, too low for API gateways
	maxConnsPerHost       = 200
	idleConnTimeout       = 90 * time.Second
	tlsHandshakeTimeout   = 10 * time.Second
	expectContinueTimeout = 1 * time.Second
)

// proxyTransport creates a transport with HTTP/HTTPS proxy.
func proxyTransport(proxyURL *url.URL) *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyURL(proxyURL),
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// socks5Transport creates a transport with SOCKS5 dialer.
func socks5Transport(dialFunc func(network, addr string) (net.Conn, error)) *http.Transport {
	return &http.Transport{
		DialContext: func(_ context.Context, network, addr string) (net.Conn, error) {
			return dialFunc(network, addr)
		},
		MaxIdleConns:          maxIdleConns,
		MaxIdleConnsPerHost:   maxIdleConnsPerHost,
		MaxConnsPerHost:       maxConnsPerHost,
		IdleConnTimeout:       idleConnTimeout,
		TLSHandshakeTimeout:   tlsHandshakeTimeout,
		ExpectContinueTimeout: expectContinueTimeout,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// defaultRoundTripperProvider returns a per-auth HTTP RoundTripper based on
// the Auth.ProxyURL value. It caches transports per proxy URL string.
type defaultRoundTripperProvider struct {
	mu    sync.RWMutex
	cache map[string]http.RoundTripper
}

func newDefaultRoundTripperProvider() *defaultRoundTripperProvider {
	return &defaultRoundTripperProvider{cache: make(map[string]http.RoundTripper)}
}

// RoundTripperFor implements provider.RoundTripperProvider.
func (p *defaultRoundTripperProvider) RoundTripperFor(auth *provider.Auth) http.RoundTripper {
	if auth == nil {
		return nil
	}
	proxyStr := strings.TrimSpace(auth.ProxyURL)
	if proxyStr == "" {
		return nil
	}
	p.mu.RLock()
	rt := p.cache[proxyStr]
	p.mu.RUnlock()
	if rt != nil {
		return rt
	}
	// Parse the proxy URL to determine the scheme.
	proxyURL, errParse := url.Parse(proxyStr)
	if errParse != nil {
		log.Errorf("parse proxy URL failed: %v", errParse)
		return nil
	}
	var transport *http.Transport
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
			log.Errorf("create SOCKS5 dialer failed: %v", errSOCKS5)
			return nil
		}
		transport = socks5Transport(dialer.Dial)
	case "http", "https":
		transport = proxyTransport(proxyURL)
	default:
		log.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
		return nil
	}
	p.mu.Lock()
	p.cache[proxyStr] = transport
	p.mu.Unlock()
	return transport
}
