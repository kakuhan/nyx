// Package main — Nyx Android APK (headless, no GL dependency)
//
// Uses NativeActivity to keep the process alive and run the SOCKS5 proxy.
// No GUI required — proxy runs in background.
// User configures Wi-Fi proxy to 127.0.0.1:1080 after starting the app.
//
// Build with: gomobile build -target=android ./cmd/apk/
package main

import (
	"encoding/json"
	"log"
	"os"
	"strings"

	"golang.org/x/mobile/app"
	"golang.org/x/mobile/event/lifecycle"

	"nyx/internal/clientapp"
)

var (
	stopCh = make(chan struct{})
)

func main() {
	app.Main(func(a app.App) {
		started := false
		for e := range a.Events() {
			switch e := a.Filter(e).(type) {
			case lifecycle.Event:
				if e.Crosses(lifecycle.StageVisible) == lifecycle.CrossOn && !started {
					started = true
					go runNyx()
				}
				if e.Crosses(lifecycle.StageDead) == lifecycle.CrossOn {
					close(stopCh)
				}
			}
		}
	})
}

func runNyx() {
	cfg := findOrCreateConfig()
	if cfg == nil {
		log.Println("[Nyx] No valid config — create /sdcard/nyx-client.json and restart")
		return
	}

	log.Printf("[Nyx] SOCKS5 proxy starting on %s → %s", cfg.Socks5Listen, cfg.Server)
	log.Printf("[Nyx] Set Wi-Fi proxy to: SOCKS5 %s", cfg.Socks5Listen)

	// Run proxy — blocks until shutdown or error
	err := clientapp.RunWithConfig(*cfg)
	if err != nil {
		log.Printf("[Nyx] Error: %v", err)
	}
	log.Println("[Nyx] Proxy stopped")
}

func findOrCreateConfig() *clientapp.Config {
	// Priority order:
	//   1. /data/local/tmp/nyx-client.json  (adb push target, works on all Android versions)
	//   2. /sdcard/nyx-client.json          (user-accessible, needs storage permission on 11+)
	paths := []string{
		"/data/local/tmp/nyx-client.json",
		"/sdcard/nyx-client.json",
	}

	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var cfg clientapp.Config
		if err := json.Unmarshal(data, &cfg); err != nil {
			log.Printf("[Nyx] %s parse error: %v", p, err)
			continue
		}
		if cfg.Server == "" || strings.Contains(cfg.Server, "YOUR_SERVER") {
			continue
		}
		if cfg.ShortID == "" || strings.Contains(cfg.ShortID, "CHANGE_ME") {
			continue
		}
		if cfg.Socks5Listen == "" {
			cfg.Socks5Listen = "127.0.0.1:1080"
		}
		log.Printf("[Nyx] Using config from %s → %s", p, cfg.Server)
		return &cfg
	}

	// No config found — write a working template to /data/local/tmp/
	// (adb push works here without scoped storage issues on Android 11+).
	// The template contains the production server config, so a simple
	// `adb push nyx-client.json /data/local/tmp/` is all that's needed
	// for first-time setup on a new device.
	target := "/data/local/tmp/nyx-client.json"
	tmpl := `{
  "server": "usuk.4160365.xyz:8443",
  "short_id": "a1b2c3d4e5f6a7b8",
  "target_domain": "www.bilibili.com",
  "socks5_listen": "127.0.0.1:1080",
  "idle_timeout": 300
}`
	if err := os.WriteFile(target, []byte(tmpl), 0644); err != nil {
		log.Printf("[Nyx] Cannot write template to %s: %v", target, err)
	} else {
		log.Printf("[Nyx] Template config written → %s", target)
	}

	// Try to use the template we just wrote (no restart needed).
	// Only accept it if validation passes (no placeholder strings).
	data, _ := os.ReadFile(target)
	if data != nil {
		var cfg clientapp.Config
		if err := json.Unmarshal(data, &cfg); err == nil {
			if cfg.Server != "" && !strings.Contains(cfg.Server, "YOUR_SERVER") &&
				cfg.ShortID != "" && !strings.Contains(cfg.ShortID, "CHANGE_ME") {
				if cfg.Socks5Listen == "" {
					cfg.Socks5Listen = "127.0.0.1:1080"
				}
				log.Printf("[Nyx] Auto-starting with template config → %s", cfg.Server)
				return &cfg
			}
		}
	}

	log.Println("[Nyx] No valid config — push nyx-client.json to /data/local/tmp/ and restart")
	return nil
}
