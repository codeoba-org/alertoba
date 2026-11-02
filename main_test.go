package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

var testKey = bytes.Repeat([]byte{7}, 32)

// upstream fakes Discord and Alertzy. All outbound HTTP is routed to it.
type upstream struct {
	mu      sync.Mutex
	status  int    // Discord response status
	path    string // last request path
	body    string // last request body
	server  *httptest.Server
	baseURL *url.URL
}

func newUpstream(t *testing.T) *upstream {
	u := &upstream{status: http.StatusNoContent}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		defer u.mu.Unlock()
		u.path, u.body = r.URL.Path, string(b)
		if r.URL.Path == "/send" { // Alertzy
			if strings.Contains(u.body, "accountKey=badkey") {
				io.WriteString(w, `{"response":"fail","sentTo":[],"error":{"badkey":"Invalid Account Key"}}`)
				return
			}
			io.WriteString(w, `{"response":"success","sentTo":["goodkey"]}`)
			return
		}
		w.WriteHeader(u.status)
	}))
	t.Cleanup(u.server.Close)
	u.baseURL, _ = url.Parse(u.server.URL)
	return u
}

func (u *upstream) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = u.baseURL.Scheme, u.baseURL.Host
	return http.DefaultTransport.RoundTrip(r)
}

func (u *upstream) last() (path, body string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.path, u.body
}

func newTestApp(t *testing.T) (*app, *upstream, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := openDB(dbPath, testKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	up := newUpstream(t)
	a := &app{
		db:     db,
		tmpl:   template.Must(template.New("").Parse(templates)),
		client: &http.Client{Timeout: sendTimeout, Transport: up},
	}
	return a, up, dbPath
}

// browser is a logged-out dashboard client.
type browser struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func newBrowser(t *testing.T, a *app) *browser {
	srv := httptest.NewServer(a.routes())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	return &browser{t: t, base: srv.URL, c: &http.Client{Jar: jar}}
}

func (b *browser) do(method, path string, form url.Values, htmx bool) (int, string, http.Header) {
	b.t.Helper()
	req, _ := http.NewRequest(method, b.base+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if htmx {
		req.Header.Set("HX-Request", "true")
		req.Header.Set("X-CSRF-Token", b.csrf)
	}
	resp, err := b.c.Do(req)
	if err != nil {
		b.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body), resp.Header
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// loginAndSetPassword performs the first login and the forced password change.
func (b *browser) loginAndSetPassword() {
	b.t.Helper()
	code, body, _ := b.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"admin"}}, false)
	if code != 200 || !strings.Contains(body, "default password") {
		b.t.Fatalf("first login should land on the forced password page, got %d", code)
	}
	b.csrf = csrfRe.FindStringSubmatch(body)[1]
	code, body, _ = b.do("POST", "/password", url.Values{
		"csrf": {b.csrf}, "current": {"admin"}, "new": {"new-password-1"}, "confirm": {"new-password-1"},
	}, false)
	if code != 200 || !strings.Contains(body, "API key") {
		b.t.Fatalf("password change should land on the dashboard, got %d", code)
	}
}

func (b *browser) generateAPIKey() string {
	b.t.Helper()
	_, body, _ := b.do("POST", "/apikey", nil, true)
	m := regexp.MustCompile(`<pre>([A-Z0-9]+)</pre>`).FindStringSubmatch(body)
	if m == nil {
		b.t.Fatalf("no API key in response: %s", body)
	}
	return m[1]
}

func notify(t *testing.T, base, id, key, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest("POST", base+"/api/notify/"+id, strings.NewReader(body))
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func TestParseDBKey(t *testing.T) {
	for _, bad := range []string{"", "not base64!", base64.StdEncoding.EncodeToString([]byte("short"))} {
		if _, err := parseDBKey(bad); err == nil {
			t.Errorf("parseDBKey(%q) should fail", bad)
		}
	}
	if _, err := parseDBKey(base64.StdEncoding.EncodeToString(testKey)); err != nil {
		t.Errorf("valid key rejected: %v", err)
	}
}

func TestValidateMessage(t *testing.T) {
	cases := []struct {
		title, message string
		ok             bool
	}{
		{"Disk full", "sda1 at 95%", true},
		{"", "message", false},
		{"title", "  ", false},
		{"two\nlines", "message", false},
		{strings.Repeat("x", maxTitle+1), "message", false},
		{"title", strings.Repeat("x", maxMessage+1), false},
	}
	for _, c := range cases {
		if err := validateMessage(c.title, c.message); (err == nil) != c.ok {
			t.Errorf("validateMessage(%q, %q) = %v, want ok=%v", c.title, c.message, err, c.ok)
		}
	}
}

func TestLoginAndPassword(t *testing.T) {
	a, _, _ := newTestApp(t)
	b := newBrowser(t, a)

	if code, body, _ := b.do("GET", "/", nil, false); code != 200 || !strings.Contains(body, `action="/login"`) {
		t.Fatalf("logged-out dashboard should show login page, got %d", code)
	}
	if code, _, _ := b.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"wrong"}}, false); code != 401 {
		t.Fatalf("wrong password: got %d, want 401", code)
	}

	code, body, _ := b.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"admin"}}, false)
	if code != 200 || !strings.Contains(body, "default password") {
		t.Fatalf("first login should force a password change, got %d", code)
	}
	b.csrf = csrfRe.FindStringSubmatch(body)[1]

	if _, body, _ := b.do("GET", "/", nil, false); !strings.Contains(body, "default password") {
		t.Fatal("dashboard reachable before the password change")
	}
	if _, _, h := b.do("POST", "/apikey", nil, true); h.Get("HX-Redirect") != "/password" {
		t.Fatal("htmx requests should be redirected to /password before the change")
	}
	change := func(csrf, cur, next string) (int, string) {
		code, body, _ := b.do("POST", "/password", url.Values{"csrf": {csrf}, "current": {cur}, "new": {next}, "confirm": {next}}, false)
		return code, body
	}
	if code, _ := change("", "admin", "new-password-1"); code != 403 {
		t.Fatalf("password change without CSRF token: got %d, want 403", code)
	}
	if _, body := change(b.csrf, "wrong", "new-password-1"); !strings.Contains(body, "Current password is wrong") {
		t.Fatal("wrong current password accepted")
	}
	if _, body := change(b.csrf, "admin", "short"); !strings.Contains(body, "at least 8") {
		t.Fatal("short password accepted")
	}
	if code, body := change(b.csrf, "admin", "new-password-1"); code != 200 || !strings.Contains(body, "API key") {
		t.Fatalf("valid password change failed: %d", code)
	}

	// The new password works, the old one doesn't.
	b2 := newBrowser(t, a)
	if code, _, _ := b2.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"admin"}}, false); code != 401 {
		t.Fatal("old password still works")
	}
	if _, body, _ := b2.do("POST", "/login", url.Values{"username": {"admin"}, "password": {"new-password-1"}}, false); !strings.Contains(body, "API key") {
		t.Fatal("new password does not work")
	}
}

func TestChannelsAndAPI(t *testing.T) {
	a, up, _ := newTestApp(t)
	b := newBrowser(t, a)
	b.loginAndSetPassword()

	if code, _ := notify(t, b.base, "1", "", `{}`); code != 401 {
		t.Fatalf("missing key: got %d, want 401", code)
	}
	if code, _ := notify(t, b.base, "1", "anything", `{}`); code != 401 {
		t.Fatalf("no key generated yet: got %d, want 401", code)
	}
	oldKey := b.generateAPIKey()
	key := b.generateAPIKey()
	if code, _ := notify(t, b.base, "1", oldKey, `{"title":"a","message":"b"}`); code != 401 {
		t.Fatal("regenerated key should revoke the old one")
	}

	// Channel validation errors are retargeted into the form.
	code, _, h := b.do("POST", "/channels", url.Values{"name": {"x"}, "type": {"discord"}, "webhook_url": {"https://evil.example/api/webhooks/1/x"}}, true)
	if code != 422 || h.Get("HX-Retarget") != "#form-error" {
		t.Fatalf("non-Discord webhook URL should be rejected, got %d", code)
	}

	hook := "https://discord.com/api/webhooks/123/SECRETTOKEN"
	code, body, _ := b.do("POST", "/channels", url.Values{"name": {"Ops <team>"}, "type": {"discord"}, "webhook_url": {hook}}, true)
	if code != 200 || !strings.Contains(body, "Ops &lt;team&gt;") || strings.Contains(body, "SECRETTOKEN") {
		t.Fatalf("create Discord channel: %d %s", code, body)
	}
	b.do("POST", "/channels", url.Values{"name": {"Phone"}, "type": {"alertzy"}, "account_key": {"goodkey"}}, true)

	// Secrets never reach the browser, and a blank secret keeps the stored one.
	if _, body, _ := b.do("GET", "/channels/1/edit", nil, true); strings.Contains(body, "SECRETTOKEN") || !strings.Contains(body, "leave blank to keep") {
		t.Fatal("edit form leaks the webhook URL")
	}
	b.do("PUT", "/channels/1", url.Values{"name": {"Ops"}, "webhook_url": {""}}, true)
	if ch, _ := a.getChannel(1); ch.Name != "Ops" || ch.Config.WebhookURL != hook {
		t.Fatalf("update should rename and keep the secret, got %+v", ch)
	}

	// Discord
	if code, out := notify(t, b.base, "1", key, `{"title":"Disk full","message":"sda1 at 95%"}`); code != 200 || out["ok"] != true {
		t.Fatalf("notify Discord: %d %v", code, out)
	}
	if path, body := up.last(); path != "/api/webhooks/123/SECRETTOKEN" || !strings.Contains(body, `"title":"Disk full"`) {
		t.Fatalf("Discord request: %s %s", path, body)
	}
	up.status = http.StatusNotFound
	code, out := notify(t, b.base, "1", key, `{"title":"x","message":"y"}`)
	if code != 502 || strings.Contains(out["error"].(string), "SECRETTOKEN") {
		t.Fatalf("Discord failure should be 502 without the webhook URL, got %d %v", code, out)
	}
	up.status = http.StatusNoContent

	// Request validation
	for _, body := range []string{`not json`, `{"title":"","message":"y"}`, `{"title":"a\nBcc: x","message":"y"}`} {
		if code, _ := notify(t, b.base, "1", key, body); code != 400 {
			t.Errorf("body %q: got %d, want 400", body, code)
		}
	}
	if code, _ := notify(t, b.base, "99", key, `{"title":"a","message":"b"}`); code != 404 {
		t.Errorf("unknown channel: got %d, want 404", code)
	}

	// Alertzy
	if code, out := notify(t, b.base, "2", key, `{"title":"Hi","message":"there"}`); code != 200 {
		t.Fatalf("notify Alertzy: %d %v", code, out)
	}
	if _, body := up.last(); !strings.Contains(body, "accountKey=goodkey") {
		t.Fatalf("Alertzy request body: %s", body)
	}
	a.db.Exec(`UPDATE channels SET config = '{"account_key":"badkey"}' WHERE id = 2`)
	if code, out := notify(t, b.base, "2", key, `{"title":"Hi","message":"there"}`); code != 502 || out["error"] != "alertzy: Invalid Account Key" {
		t.Fatalf("Alertzy failure: %d %v", code, out)
	}

	// The log shows sends and failures; the test button records "test".
	b.do("POST", "/channels/2/test", nil, true)
	_, body, _ = b.do("GET", "/log", nil, true)
	for _, want := range []string{"Disk full", "Invalid Account Key", "Alertoba test"} {
		if !strings.Contains(body, want) {
			t.Errorf("log missing %q", want)
		}
	}

	// Delete requires CSRF.
	if code, _, _ := b.do("DELETE", "/channels/1", nil, false); code != 403 {
		t.Errorf("delete without CSRF: got %d, want 403", code)
	}
	b.do("DELETE", "/channels/1", nil, true)
	if _, err := a.getChannel(1); err == nil {
		t.Error("channel not deleted")
	}
}

func TestPruneOldSends(t *testing.T) {
	a, _, _ := newTestApp(t)
	now := time.Now()
	a.db.Exec(`INSERT INTO sends(channel_id, channel_name, title, source, error, created_at) VALUES
		(1, 'c', 'old', 'api', '', ?), (1, 'c', 'new', 'api', '', ?)`,
		now.Add(-8*24*time.Hour).Unix(), now.Add(-6*24*time.Hour).Unix())
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // run one pass and return
	a.pruneLoop(ctx)
	var titles []string
	rows, _ := a.db.Query(`SELECT title FROM sends`)
	for rows.Next() {
		var s string
		rows.Scan(&s)
		titles = append(titles, s)
	}
	rows.Close()
	if len(titles) != 1 || titles[0] != "new" {
		t.Fatalf("after prune got %v, want [new]", titles)
	}
}

func TestSMTP(t *testing.T) {
	addr, received := fakeSMTP(t)
	host, port, _ := net.SplitHostPort(addr)
	a, _, _ := newTestApp(t)
	b := newBrowser(t, a)
	b.loginAndSetPassword()

	code, body, _ := b.do("POST", "/channels", url.Values{
		"name": {"Mail"}, "type": {"smtp"}, "host": {host}, "port": {port}, "tls": {"tls"},
		"username": {"user"}, "password": {"pass word"},
		"from": {"Alerts <alerts@example.com>"}, "to": {"ops@example.com, Me <me@example.com>"},
	}, true)
	if code != 200 {
		t.Fatalf("create SMTP channel: %d %s", code, body)
	}
	if _, body, _ := b.do("POST", "/channels/1/test", nil, true); !strings.Contains(body, "Sent") {
		t.Fatalf("SMTP test send failed: %s", body)
	}
	got := <-received
	for _, want := range []string{
		"AUTH PLAIN", "MAIL FROM:<alerts@example.com>", "RCPT TO:<ops@example.com>", "RCPT TO:<me@example.com>",
		"Subject: Alertoba test", "Content-Transfer-Encoding: quoted-printable",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("SMTP session missing %q:\n%s", want, got)
		}
	}
}

// fakeSMTP runs a one-shot implicit-TLS SMTP server and returns the session transcript.
func fakeSMTP(t *testing.T) (string, <-chan string) {
	t.Helper()
	certSrv := httptest.NewTLSServer(nil)
	cert := certSrv.TLS.Certificates
	pool := x509.NewCertPool()
	pool.AddCert(certSrv.Certificate())
	certSrv.Close()
	smtpRootCAs = pool
	t.Cleanup(func() { smtpRootCAs = nil })

	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: cert})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	out := make(chan string, 1)
	go func() {
		var log strings.Builder
		defer func() { out <- log.String() }()
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		reply := func(s string) { io.WriteString(conn, s+"\r\n") }
		reply("220 fake")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			log.WriteString(line)
			switch cmd := strings.ToUpper(line); {
			case strings.HasPrefix(cmd, "EHLO"):
				reply("250-fake")
				reply("250 AUTH PLAIN")
			case strings.HasPrefix(cmd, "AUTH"):
				reply("235 ok")
			case strings.HasPrefix(cmd, "DATA"):
				reply("354 go")
				for {
					l, err := r.ReadString('\n')
					if err != nil || l == ".\r\n" {
						break
					}
					log.WriteString(l)
				}
				reply("250 queued")
			case strings.HasPrefix(cmd, "QUIT"):
				reply("221 bye")
				return
			default:
				reply("250 ok")
			}
		}
	}()
	return ln.Addr().String(), out
}

func TestDatabaseEncrypted(t *testing.T) {
	a, _, dbPath := newTestApp(t)
	a.db.Exec(`INSERT INTO channels(name, type, config) VALUES ('Secret channel', 'discord', '{"webhook_url":"https://discord.com/api/webhooks/1/SECRETTOKEN"}')`)
	a.db.Close()

	raw, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"SQLite format 3", "SECRETTOKEN", "Secret channel", "password_hash"} {
		if bytes.Contains(raw, []byte(s)) {
			t.Errorf("database file contains plaintext %q", s)
		}
	}
	if fi, _ := os.Stat(dbPath); fi.Mode().Perm() != 0o600 {
		t.Errorf("database file mode %v, want 0600", fi.Mode().Perm())
	}
	if _, err := openDB(dbPath, bytes.Repeat([]byte{8}, 32)); err == nil {
		t.Fatal("database opened with the wrong key")
	}
	db, err := openDB(dbPath, testKey)
	if err != nil {
		t.Fatalf("reopen with the right key: %v", err)
	}
	db.Close()
}
