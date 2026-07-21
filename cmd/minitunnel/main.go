// Command minitunnel is a stripped-down build of cloudflared combined with a
// WebSocket proxy (VLESS / Trojan / Shadowsocks). It runs a local WS proxy
// server and optionally exposes it through a Cloudflare tunnel so the proxy is
// reachable over HTTPS via the edge.
//
// If TUNNEL_TOKEN is empty the tunnel is not started and the WS server listens
// directly (e.g. behind your own reverse proxy). If TUNNEL_TOKEN is set, the
// edge traffic is proxied to the local WS server.
//
// Configuration is provided entirely through environment variables:
//
//	TUNNEL_TOKEN  - (optional) Cloudflare tunnel token, base64 JSON. Empty = direct mode.
//	PORT          - (optional) local WS server port, defaults to 8080
//	UUID          - (optional) proxy UUID, defaults to b64c9a01-3f09-4dea-a0f1-dc85e5a3ac19
//	WSPATH        - (optional) WebSocket path, defaults to api/v1/user?token=<UUID[:8]>&lang=en
//	TUNNEL_URL    - (optional, tunnel mode only) origin URL, defaults to http://localhost:<PORT>
//	TUNNEL_ORIGIN - (optional) alias for TUNNEL_URL
//
// When a token is set this is the equivalent of:
//	cloudflared tunnel --edge-ip-version auto --protocol http2 run --token <token>
// with --edge-ip-version=auto and --protocol=http2 hard-coded.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/bramstera/minitu/cmd/minitunnel/ws"
	"github.com/cloudflare/cloudflared/config"
	"github.com/cloudflare/cloudflared/connection"
	"github.com/cloudflare/cloudflared/edgediscovery"
	"github.com/cloudflare/cloudflared/edgediscovery/allregions"
	"github.com/cloudflare/cloudflared/features"
	"github.com/cloudflare/cloudflared/ingress"
	"github.com/cloudflare/cloudflared/orchestration"
	cfsignal "github.com/cloudflare/cloudflared/signal"
	"github.com/cloudflare/cloudflared/supervisor"
	"github.com/cloudflare/cloudflared/tlsconfig"
	"github.com/cloudflare/cloudflared/tunnelrpc/pogs"
	"github.com/cloudflare/cloudflared/validation"
)

// === Configuration (edit here or override via environment) ==================
//
// Each setting reads an environment variable, falling back to the second
// argument as the default. To hard-code a value, just put it in the quotes.
var (
	// TUNNEL_TOKEN: Cloudflare tunnel token (base64 JSON). Empty = direct mode.
	TunnelToken = getenvDefault("TUNNEL_TOKEN", "")
	// PORT: local WS server port.
	Port = getenvInt("PORT", 8080)
	// UUID: proxy UUID.
	UUID = getenvDefault("UUID", "b64c9a01-3f09-4dea-a0f1-dc85e5a3ac19")
)

// ============================================================================

// Version reported to the edge.
var Version = "2024.10.0"

type proxyConfig struct {
	UUID       string
	WSPath     string // full path including query (for logging)
	WSPathOnly string // path without query
	WSQuery    string // query string without leading '?'
	Port       int
}

func loadProxyConfig() proxyConfig {
	wsPath := strings.TrimSpace(os.Getenv("WSPATH"))
	if wsPath == "" {
		short := strings.ReplaceAll(UUID, "-", "")
		if len(short) > 8 {
			short = short[:8]
		}
		wsPath = "api/v1/user?token=" + short + "&lang=en"
	}
	wsPath = strings.TrimPrefix(wsPath, "/")

	wsPathOnly, wsQuery := wsPath, ""
	if idx := strings.Index(wsPath, "?"); idx >= 0 {
		wsPathOnly = wsPath[:idx]
		wsQuery = wsPath[idx+1:]
	}

	return proxyConfig{
		UUID:       UUID,
		WSPath:     wsPath,
		WSPathOnly: wsPathOnly,
		WSQuery:    wsQuery,
		Port:       Port,
	}
}

func getenvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func main() {
	log := newLogger()

	// cloudflared sets this to work around a quic-go bug; harmless for http2.
	_ = os.Setenv("QUIC_GO_DISABLE_ECN", "1")

	pcfg := loadProxyConfig()

	// Graceful shutdown on SIGINT/SIGTERM.
	graceShutdownC := make(chan struct{})
	osSigC := make(chan os.Signal, 1)
	signal.Notify(osSigC, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-osSigC
		log.Info().Msg("Shutdown signal received")
		close(graceShutdownC)
	}()

	useTunnel := strings.TrimSpace(TunnelToken) != ""
	listenAddr := fmt.Sprintf(":%d", pcfg.Port)

	// Start the local WebSocket proxy server. In tunnel mode it only needs to
	// be reachable from localhost; in direct mode it listens on all interfaces.
	server := newProxyServer(pcfg)
	go func() {
		log.Info().Str("listen", listenAddr).Bool("tunnel", useTunnel).
		Str("wsPath", "/"+pcfg.WSPath).Msg("WS proxy server starting")
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal().Err(err).Msg("WS proxy server error")
		}
	}()

	if !useTunnel {
		log.Info().Msg("TUNNEL_TOKEN empty: running in direct mode (no Cloudflare tunnel)")
		<-graceShutdownC
		shutdown(server, log)
		return
	}

	// Tunnel mode: run cloudflared, proxying edge traffic to the local WS server.
	originURL := strings.TrimSpace(os.Getenv("TUNNEL_ORIGIN"))
	if originURL == "" {
		originURL = strings.TrimSpace(os.Getenv("TUNNEL_URL"))
	}
	if originURL == "" {
		originURL = fmt.Sprintf("http://localhost:%d", pcfg.Port)
	}

	if err := runTunnel(log, TunnelToken, originURL, graceShutdownC); err != nil {
		log.Error().Err(err).Msg("tunnel exited")
	}
	shutdown(server, log)
}

func shutdown(server *http.Server, log *zerolog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Error().Err(err).Msg("WS proxy server shutdown error")
	}
}

// newProxyServer builds the HTTP server that serves the WS proxy. The root
// path returns a simple status string; the configured WS path upgrades the
// connection and dispatches it to the protocol handlers.
func newProxyServer(pcfg proxyConfig) *http.Server {
	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "Bot is running.")
	})

	mux.HandleFunc("/"+pcfg.WSPathOnly, func(w http.ResponseWriter, r *http.Request) {
		if pcfg.WSQuery != "" && r.URL.RawQuery != pcfg.WSQuery {
			http.NotFound(w, r)
			return
		}
		ws.HandleWebSocket(w, r, pcfg.WSPath, pcfg.UUID)
	})

	return &http.Server{
		Addr:         fmt.Sprintf(":%d", pcfg.Port),
		Handler:      mux,
		ReadTimeout:  0, // WS connections are long-lived
		WriteTimeout: 0,
	}
}

func runTunnel(log *zerolog.Logger, tokenStr, originURL string, graceShutdownC chan struct{}) error {
	creds, err := parseToken(tokenStr)
	if err != nil {
		return fmt.Errorf("invalid TUNNEL_TOKEN: %w", err)
	}
	log.Info().Str("tunnelID", creds.TunnelID.String()).Msg("Starting tunnel")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Tie tunnel lifetime to the process shutdown signal.
	go func() {
		<-graceShutdownC
		cancel()
	}()

	clientID, err := uuid.NewRandom()
	if err != nil {
		return fmt.Errorf("generate connector UUID: %w", err)
	}
	log.Info().Str("connectorID", clientID.String()).Msg("Generated Connector ID")

	observer := connection.NewObserver(log, log)

	// Build ingress rules: a single catch-all rule proxying to originURL.
	// httpService (the origin backing an http(s):// service) supports HTTP, HTTPS
	// and WebSocket (ws/wss) traffic.
	in, err := buildIngress(originURL, log)
	if err != nil {
		return err
	}

	clientFeatures := features.Dedup(append([]string{}, features.DefaultFeatures...))

	namedTunnel := &connection.TunnelProperties{
		Credentials: *creds,
		Client: pogs.ClientInfo{
			ClientID: clientID[:],
			Features: clientFeatures,
			Version:  Version,
			Arch:     runtime.GOOS + "_" + runtime.GOARCH,
		},
	}

	protocolSelector, err := connection.NewProtocolSelector(
		connection.HTTP2.String(), // hard-coded --protocol http2
		creds.AccountTag,
		true, // token provided
		false,
		edgediscovery.ProtocolPercentage,
		connection.ResolveTTL,
		log,
	)
	if err != nil {
		return fmt.Errorf("create protocol selector: %w", err)
	}
	log.Info().Str("protocol", protocolSelector.Current().String()).Msg("Initial protocol")

	edgeTLSConfigs := make(map[connection.Protocol]*tls.Config, len(connection.ProtocolList))
	for _, p := range connection.ProtocolList {
		tlsSettings := p.TLSSettings()
		if tlsSettings == nil {
			return fmt.Errorf("%s has unknown TLS settings", p)
		}
		cfg, err := createEdgeTLSConfig(tlsSettings.ServerName)
		if err != nil {
			return fmt.Errorf("create edge TLS config: %w", err)
		}
		if len(tlsSettings.NextProtos) > 0 {
			cfg.NextProtos = tlsSettings.NextProtos
		}
		edgeTLSConfigs[p] = cfg
	}

	featureSelector, err := features.NewFeatureSelector(ctx, creds.AccountTag, features.StaticFeatures{}, log)
	if err != nil {
		return fmt.Errorf("create feature selector: %w", err)
	}

	tunnelConfig := &supervisor.TunnelConfig{
		OSArch:             runtime.GOOS + "_" + runtime.GOARCH,
		ClientID:           clientID.String(),
		EdgeIPVersion:      allregions.Auto, // hard-coded --edge-ip-version auto
		HAConnections:      4,               // cloudflared default
		Log:                log,
		LogTransport:       log,
		Observer:           observer,
		ReportedVersion:    Version,
		Retries:            5,
		NamedTunnel:        namedTunnel,
		ProtocolSelector:   protocolSelector,
		EdgeTLSConfigs:     edgeTLSConfigs,
		FeatureSelector:    featureSelector,
		MaxEdgeAddrRetries: 3,
		RPCTimeout:         5 * time.Second,
	}

	orchestratorConfig := &orchestration.Config{
		Ingress:     &in,
		WarpRouting: ingress.NewWarpRoutingConfig(&config.WarpRoutingConfig{}),
	}
	orchestrator, err := orchestration.NewOrchestrator(ctx, orchestratorConfig, nil, nil, log)
	if err != nil {
		return fmt.Errorf("create orchestrator: %w", err)
	}

	connectedSignal := cfsignal.New(make(chan struct{}))
	reconnectCh := make(chan supervisor.ReconnectSignal, tunnelConfig.HAConnections)

	return supervisor.StartTunnelDaemon(ctx, tunnelConfig, orchestrator, connectedSignal, reconnectCh, graceShutdownC)
}

// parseToken decodes the base64-JSON tunnel token into Credentials.
func parseToken(tokenStr string) (*connection.Credentials, error) {
	content, err := base64.StdEncoding.DecodeString(tokenStr)
	if err != nil {
		// Some tokens are URL-safe base64.
		content, err = base64.URLEncoding.DecodeString(tokenStr)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
	}
	var t connection.TunnelToken
	if err := json.Unmarshal(content, &t); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	c := t.Credentials()
	return &c, nil
}

// buildIngress constructs a single catch-all ingress rule pointing at originURL.
func buildIngress(originURL string, log *zerolog.Logger) (ingress.Ingress, error) {
	if _, err := validation.ValidateUrl(originURL); err != nil {
		return ingress.Ingress{}, fmt.Errorf("invalid origin URL %q: %w", originURL, err)
	}
	conf := &config.Configuration{
		Ingress: []config.UnvalidatedIngressRule{
			{
				Service: originURL, // catch-all rule: no hostname/path filter
			},
		},
	}
	return ingress.ParseIngress(conf)
}

// createEdgeTLSConfig builds the TLS config used to dial the Cloudflare edge.
func createEdgeTLSConfig(serverName string) (*tls.Config, error) {
	cfg, err := tlsconfig.GetConfig(&tlsconfig.TLSParameters{ServerName: serverName})
	if err != nil {
		return nil, err
	}
	if cfg.RootCAs == nil {
		rootCAPool, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("system cert pool: %w", err)
		}
		cfRootCA, err := tlsconfig.GetCloudflareRootCA()
		if err != nil {
			return nil, fmt.Errorf("cloudflare root CA: %w", err)
		}
		for _, cert := range cfRootCA {
			rootCAPool.AddCert(cert)
		}
		cfg.RootCAs = rootCAPool
	}
	return cfg, nil
}

func newLogger() *zerolog.Logger {
	out := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}
	l := zerolog.New(out).With().Timestamp().Logger()
	return &l
}
