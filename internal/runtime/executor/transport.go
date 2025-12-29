// Package executor provides HTTP transport configuration for high-performance scenarios.
package executor

import (
	"context"
	"crypto/tls"
	"golang.org/x/net/http2"
	"net"
	"net/http"
	"net/url"
	"time"
)

// TransportConfig contains tuned settings for high-performance HTTP transport.
// These values are optimized for API gateway workloads with many concurrent connections.
var TransportConfig = struct {
	MaxIdleConns          int
	MaxIdleConnsPerHost   int
	MaxConnsPerHost       int
	IdleConnTimeout       time.Duration
	TLSHandshakeTimeout   time.Duration
	ExpectContinueTimeout time.Duration
	ResponseHeaderTimeout time.Duration
	DialTimeout           time.Duration
	KeepAlive             time.Duration
}{
	MaxIdleConns:          1000,
	MaxIdleConnsPerHost:   100, // Default is 2, too low for API gateways
	MaxConnsPerHost:       200,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	ResponseHeaderTimeout: 60 * time.Second,
	DialTimeout:           30 * time.Second,
	KeepAlive:             30 * time.Second,
}

// configureHTTP2 configures HTTP/2 settings for the transport.
func configureHTTP2(transport *http.Transport) {
	h2Transport, err := http2.ConfigureTransports(transport)
	if err != nil {
		return // fallback to default HTTP/2
	}
	h2Transport.ReadIdleTimeout = 30 * time.Second
	h2Transport.PingTimeout = 15 * time.Second
	h2Transport.StrictMaxConcurrentStreams = true
}

// newDialer creates a configured net.Dialer for transport connections.
func newDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   TransportConfig.DialTimeout,
		KeepAlive: TransportConfig.KeepAlive,
	}
}

// baseTransport creates a base HTTP transport with common configuration.
func baseTransport() *http.Transport {
	t := &http.Transport{
		MaxIdleConns:          TransportConfig.MaxIdleConns,
		MaxIdleConnsPerHost:   TransportConfig.MaxIdleConnsPerHost,
		MaxConnsPerHost:       TransportConfig.MaxConnsPerHost,
		IdleConnTimeout:       TransportConfig.IdleConnTimeout,
		TLSHandshakeTimeout:   TransportConfig.TLSHandshakeTimeout,
		ExpectContinueTimeout: TransportConfig.ExpectContinueTimeout,
		ResponseHeaderTimeout: TransportConfig.ResponseHeaderTimeout,
		ForceAttemptHTTP2:     true,
		DisableCompression:    false,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	configureHTTP2(t)
	return t
}

// SharedTransport is the default HTTP transport for direct connections.
// Used when no proxy is configured and no context RoundTripper is provided.
var SharedTransport = baseTransport()

func init() {
	SharedTransport.DialContext = newDialer().DialContext
}

// ProxyTransport creates an HTTP transport with proxy configuration.
func ProxyTransport(proxyURL *url.URL) *http.Transport {
	t := baseTransport()
	t.Proxy = http.ProxyURL(proxyURL)
	return t
}

// SOCKS5Transport creates an HTTP transport with SOCKS5 dialer.
func SOCKS5Transport(dialFunc func(network, addr string) (net.Conn, error)) *http.Transport {
	t := baseTransport()
	t.DialContext = func(_ context.Context, network, addr string) (net.Conn, error) {
		return dialFunc(network, addr)
	}
	return t
}
