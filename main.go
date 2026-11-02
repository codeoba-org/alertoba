// Alertoba is a single-file alert relay. An admin configures notification
// channels (Discord webhook, Alertzy, SMTP email) in an htmx dashboard, and
// clients trigger them with:
//
//	POST /api/notify/{channel_id}
//	Authorization: Bearer <api key>
//	{"title": "...", "message": "..."}
//
// Environment:
//
//	PORT     listen port (default 8080)
//	DB_PATH  SQLite file (default ./alertoba.db)
//	DB_KEY   required; 32 random bytes, base64 (openssl rand -base64 32).
//	         The whole database file is encrypted with it. Losing it loses the data.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/mail"
	"net/smtp"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/ncruces/go-sqlite3/driver"
	_ "github.com/ncruces/go-sqlite3/vfs/adiantum"
	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------- config

const (
	sessionCookie = "alertoba_session"
	sessionTTL    = 12 * time.Hour
	logRetention  = 7 * 24 * time.Hour
	sendTimeout   = 10 * time.Second
	maxTitle      = 256
	maxMessage    = 4000
	testTitle     = "Alertoba test"
	testMessage   = "Test notification from Alertoba. If you can read this, the channel works."
)

type app struct {
	db     *sql.DB
	tmpl   *template.Template
	client *http.Client
}

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if err := run(); err != nil {
		slog.Error("alertoba stopped", "err", err)
		os.Exit(1)
	}
}

func run() error {
	port := envOr("PORT", "8080")
	dbPath := envOr("DB_PATH", "./alertoba.db")
	key, err := parseDBKey(os.Getenv("DB_KEY"))
	if err != nil {
		return err
	}
	db, err := openDB(dbPath, key)
	if err != nil {
		return err
	}
	defer db.Close()

	a := &app{
		db:     db,
		tmpl:   template.Must(template.New("").Parse(templates)),
		client: &http.Client{Timeout: sendTimeout},
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go a.pruneLoop(ctx)

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           a.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	slog.Info("alertoba listening", "addr", srv.Addr, "db", dbPath)

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func parseDBKey(s string) ([]byte, error) {
	if s == "" {
		return nil, errors.New("DB_KEY is required; generate one with: openssl rand -base64 32")
	}
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(key) != 32 {
		return nil, errors.New("DB_KEY must be 32 bytes, base64 encoded; generate one with: openssl rand -base64 32")
	}
	return key, nil
}

// ---------------------------------------------------------------- database

const schema = `
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	csrf       TEXT NOT NULL,
	expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS channels (
	id     INTEGER PRIMARY KEY,
	name   TEXT NOT NULL,
	type   TEXT NOT NULL,
	config TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sends (
	id           INTEGER PRIMARY KEY,
	channel_id   INTEGER NOT NULL,
	channel_name TEXT NOT NULL,
	title        TEXT NOT NULL,
	source       TEXT NOT NULL,
	error        TEXT NOT NULL,
	created_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS sends_created_at ON sends(created_at);
`

func openDB(path string, key []byte) (*sql.DB, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	// Create the file ourselves so it is owner-only from the start.
	f, err := os.OpenFile(abs, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open database file: %w", err)
	}
	f.Close()
	if err := os.Chmod(abs, 0o600); err != nil {
		return nil, fmt.Errorf("restrict database file permissions: %w", err)
	}

	q := url.Values{}
	q.Set("vfs", "adiantum") // encrypts every page of the file (and its journals)
	q.Set("hexkey", hex.EncodeToString(key))
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "temp_store(memory)")
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(abs), RawQuery: q.Encode()}).String()

	db, err := driver.Open(dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("open database (is DB_KEY correct?): %w", err)
	}
	if err := seedAdmin(db); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func seedAdmin(db *sql.DB) error {
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM settings WHERE key = 'password_hash'`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("admin"), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO settings(key, value) VALUES ('password_hash', ?), ('must_change_password', '1')`, string(hash))
	if err == nil {
		slog.Warn("created default login admin/admin; you must change it on first login")
	}
	return err
}

func (a *app) setting(key string) (string, error) {
	var v string
	err := a.db.QueryRow(`SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return v, err
}

func setSetting(ex interface {
	Exec(string, ...any) (sql.Result, error)
}, key, value string) error {
	_, err := ex.Exec(`INSERT INTO settings(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

func (a *app) pruneLoop(ctx context.Context) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		now := time.Now()
		if _, err := a.db.Exec(`DELETE FROM sends WHERE created_at < ?`, now.Add(-logRetention).Unix()); err != nil {
			slog.Error("prune send log", "err", err)
		}
		if _, err := a.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, now.Unix()); err != nil {
			slog.Error("prune sessions", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// ---------------------------------------------------------------- auth

type session struct {
	tokenHash string
	csrf      string
}

func hashToken(t string) string {
	sum := sha256.Sum256([]byte(t))
	return hex.EncodeToString(sum[:])
}

func (a *app) session(r *http.Request) (*session, bool) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return nil, false
	}
	s := &session{tokenHash: hashToken(c.Value)}
	err = a.db.QueryRow(`SELECT csrf FROM sessions WHERE token_hash = ? AND expires_at > ?`,
		s.tokenHash, time.Now().Unix()).Scan(&s.csrf)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Error("load session", "err", err)
		}
		return nil, false
	}
	return s, true
}

// auth wraps dashboard handlers: requires a session, checks the CSRF token on
// state-changing requests, and forces the password change while it is pending.
func (a *app) auth(h func(http.ResponseWriter, *http.Request, *session)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := a.session(r)
		if !ok {
			redirect(w, r, "/login")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			tok := r.Header.Get("X-CSRF-Token")
			if tok == "" {
				tok = r.PostFormValue("csrf")
			}
			if subtle.ConstantTimeCompare([]byte(tok), []byte(s.csrf)) != 1 {
				http.Error(w, "invalid CSRF token", http.StatusForbidden)
				return
			}
		}
		if r.URL.Path != "/password" && r.URL.Path != "/logout" {
			mustChange, err := a.setting("must_change_password")
			if err != nil {
				serverError(w, err)
				return
			}
			if mustChange == "1" {
				redirect(w, r, "/password")
				return
			}
		}
		h(w, r, s)
	})
}

func (a *app) checkAPIKey(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || tok == "" {
		return false
	}
	stored, err := a.setting("api_key_hash")
	if err != nil || stored == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(hashToken(tok)), []byte(stored)) == 1
}

func isHTTPS(r *http.Request) bool {
	return r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https"
}

// ---------------------------------------------------------------- channels

type channel struct {
	ID     int64
	Name   string
	Type   string
	Config channelConfig
}

// channelConfig holds the connection details for every channel type; only
// the fields for the channel's own type are set.
type channelConfig struct {
	WebhookURL string `json:"webhook_url,omitempty"` // discord (secret)
	AccountKey string `json:"account_key,omitempty"` // alertzy (secret)
	Host       string `json:"host,omitempty"`        // smtp
	Port       int    `json:"port,omitempty"`
	TLS        string `json:"tls,omitempty"` // "starttls" or "tls"
	Username   string `json:"username,omitempty"`
	Password   string `json:"password,omitempty"` // secret
	From       string `json:"from,omitempty"`
	To         string `json:"to,omitempty"` // comma-separated
}

// public returns the config without secrets, for rendering in the browser.
func (c channelConfig) public() channelConfig {
	c.WebhookURL, c.AccountKey, c.Password = "", "", ""
	return c
}

func (a *app) getChannel(id int64) (channel, error) {
	ch := channel{ID: id}
	var raw string
	err := a.db.QueryRow(`SELECT name, type, config FROM channels WHERE id = ?`, id).Scan(&ch.Name, &ch.Type, &raw)
	if err != nil {
		return ch, err
	}
	return ch, json.Unmarshal([]byte(raw), &ch.Config)
}

func (a *app) listChannels() ([]channel, error) {
	rows, err := a.db.Query(`SELECT id, name, type FROM channels ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []channel
	for rows.Next() {
		var ch channel
		if err := rows.Scan(&ch.ID, &ch.Name, &ch.Type); err != nil {
			return nil, err
		}
		out = append(out, ch)
	}
	return out, rows.Err()
}

// parseChannelForm validates the submitted form. Blank secret fields keep
// the value from old, so editing never requires re-entering secrets.
func parseChannelForm(r *http.Request, typ string, old channelConfig) (string, channelConfig, error) {
	var c channelConfig
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" || utf8.RuneCountInString(name) > 100 {
		return "", c, errors.New("Name is required (max 100 characters).")
	}
	keep := func(v, oldV string) string {
		if v == "" {
			return oldV
		}
		return v
	}

	switch typ {
	case "discord":
		c.WebhookURL = keep(strings.TrimSpace(r.FormValue("webhook_url")), old.WebhookURL)
		u, err := url.Parse(c.WebhookURL)
		host := ""
		if err == nil {
			host = u.Hostname()
		}
		validHost := host == "discord.com" || host == "discordapp.com" || strings.HasSuffix(host, ".discord.com")
		if err != nil || u.Scheme != "https" || !validHost || !strings.HasPrefix(u.Path, "/api/webhooks/") {
			return "", c, errors.New("Webhook URL must look like https://discord.com/api/webhooks/…")
		}
	case "alertzy":
		c.AccountKey = keep(strings.TrimSpace(r.FormValue("account_key")), old.AccountKey)
		if c.AccountKey == "" || strings.ContainsAny(c.AccountKey, " \t\r\n") {
			return "", c, errors.New("Account key is required.")
		}
	case "smtp":
		c.Host = strings.TrimSpace(r.FormValue("host"))
		c.Username = strings.TrimSpace(r.FormValue("username"))
		c.Password = keep(r.FormValue("password"), old.Password)
		c.TLS = r.FormValue("tls")
		c.From = strings.TrimSpace(r.FormValue("from"))
		c.To = strings.TrimSpace(r.FormValue("to"))
		port, err := strconv.Atoi(r.FormValue("port"))
		c.Port = port
		switch {
		case c.Host == "":
			return "", c, errors.New("SMTP host is required.")
		case err != nil || port < 1 || port > 65535:
			return "", c, errors.New("Port must be between 1 and 65535.")
		case c.TLS != "starttls" && c.TLS != "tls":
			return "", c, errors.New("Choose STARTTLS or TLS.")
		case c.Username != "" && c.Password == "":
			return "", c, errors.New("Password is required when a username is set.")
		}
		if _, err := mail.ParseAddress(c.From); err != nil {
			return "", c, errors.New("From must be a valid email address.")
		}
		if _, err := mail.ParseAddressList(c.To); err != nil {
			return "", c, errors.New("To must be one or more email addresses, separated by commas.")
		}
	default:
		return "", c, errors.New("Unknown channel type.")
	}
	return name, c, nil
}

// ---------------------------------------------------------------- sending

func validateMessage(title, message string) error {
	switch {
	case strings.TrimSpace(title) == "" || strings.TrimSpace(message) == "":
		return errors.New("title and message are required")
	case strings.ContainsAny(title, "\r\n"):
		return errors.New("title must be a single line")
	case utf8.RuneCountInString(title) > maxTitle:
		return fmt.Errorf("title must be at most %d characters", maxTitle)
	case utf8.RuneCountInString(message) > maxMessage:
		return fmt.Errorf("message must be at most %d characters", maxMessage)
	}
	return nil
}

// deliver sends a notification and records the outcome in the send log.
func (a *app) deliver(ctx context.Context, ch channel, title, message, source string) error {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()

	var err error
	switch ch.Type {
	case "discord":
		err = a.sendDiscord(ctx, ch.Config, title, message)
	case "alertzy":
		err = a.sendAlertzy(ctx, ch.Config, title, message)
	case "smtp":
		err = sendSMTP(ctx, ch.Config, title, message)
	default:
		err = fmt.Errorf("unknown channel type %q", ch.Type)
	}

	errText := ""
	if err != nil {
		errText = err.Error()
		slog.Warn("notification failed", "channel", ch.ID, "source", source, "err", errText)
	} else {
		slog.Info("notification sent", "channel", ch.ID, "source", source)
	}
	if _, dbErr := a.db.Exec(`INSERT INTO sends(channel_id, channel_name, title, source, error, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`, ch.ID, ch.Name, title, source, errText, time.Now().Unix()); dbErr != nil {
		slog.Error("record send", "err", dbErr)
	}
	return err
}

// postError drops the request URL from client errors: webhook URLs are secrets.
func postError(service string, err error) error {
	if ue, ok := errors.AsType[*url.Error](err); ok {
		err = ue.Err
	}
	return fmt.Errorf("%s: %w", service, err)
}

func (a *app) sendDiscord(ctx context.Context, c channelConfig, title, message string) error {
	body, err := json.Marshal(map[string]any{
		"embeds": []map[string]string{{"title": title, "description": message}},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return errors.New("discord: invalid webhook URL")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.client.Do(req)
	if err != nil {
		return postError("discord", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		return fmt.Errorf("discord: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (a *app) sendAlertzy(ctx context.Context, c channelConfig, title, message string) error {
	form := url.Values{"accountKey": {c.AccountKey}, "title": {title}, "message": {message}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://alertzy.app/send", strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := a.client.Do(req)
	if err != nil {
		return postError("alertzy", err)
	}
	defer resp.Body.Close()
	var out struct {
		Response string            `json:"response"`
		Error    map[string]string `json:"error"` // keyed by account key; never echo the keys
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<10)).Decode(&out); err != nil {
		return fmt.Errorf("alertzy: unexpected response (HTTP %d)", resp.StatusCode)
	}
	if out.Response == "success" {
		return nil
	}
	var msgs []string
	for _, m := range out.Error {
		msgs = append(msgs, m)
	}
	if len(msgs) == 0 {
		msgs = append(msgs, "response "+out.Response)
	}
	return fmt.Errorf("alertzy: %s", strings.Join(msgs, "; "))
}

// smtpRootCAs is nil (system roots) except in tests, which trust a fake server.
var smtpRootCAs *x509.CertPool

func sendSMTP(ctx context.Context, c channelConfig, title, message string) error {
	from, err := mail.ParseAddress(c.From)
	if err != nil {
		return fmt.Errorf("smtp: from address: %w", err)
	}
	to, err := mail.ParseAddressList(c.To)
	if err != nil {
		return fmt.Errorf("smtp: to addresses: %w", err)
	}

	addr := net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
	tlsCfg := &tls.Config{ServerName: c.Host, RootCAs: smtpRootCAs}
	var conn net.Conn
	if c.TLS == "tls" {
		conn, err = (&tls.Dialer{Config: tlsCfg}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}
	cl, err := smtp.NewClient(conn, c.Host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("smtp: %w", err)
	}
	defer cl.Close()

	if c.TLS == "starttls" {
		if ok, _ := cl.Extension("STARTTLS"); !ok {
			return errors.New("smtp: server does not support STARTTLS")
		}
		if err := cl.StartTLS(tlsCfg); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}
	if c.Username != "" {
		if err := cl.Auth(smtp.PlainAuth("", c.Username, c.Password, c.Host)); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}
	if err := cl.Mail(from.Address); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	toHeader := make([]string, len(to))
	for i, rcpt := range to {
		if err := cl.Rcpt(rcpt.Address); err != nil {
			return fmt.Errorf("smtp: recipient %s: %w", rcpt.Address, err)
		}
		toHeader[i] = rcpt.String()
	}

	var msg bytes.Buffer
	domain := from.Address[strings.LastIndex(from.Address, "@")+1:]
	fmt.Fprintf(&msg, "From: %s\r\n", from.String())
	fmt.Fprintf(&msg, "To: %s\r\n", strings.Join(toHeader, ", "))
	fmt.Fprintf(&msg, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", title))
	fmt.Fprintf(&msg, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&msg, "Message-ID: <%s@%s>\r\n", rand.Text(), domain)
	msg.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	qp := quotedprintable.NewWriter(&msg)
	qp.Write([]byte(message))
	qp.Close()

	wc, err := cl.Data()
	if err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if _, err := wc.Write(msg.Bytes()); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp: %w", err)
	}
	return cl.Quit()
}

// ---------------------------------------------------------------- http

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/notify/{id}", a.notify)

	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.login)
	mux.Handle("POST /logout", a.auth(a.logout))
	mux.Handle("GET /password", a.auth(a.passwordPage))
	mux.Handle("POST /password", a.auth(a.changePassword))

	mux.Handle("GET /{$}", a.auth(a.dashboard))
	mux.Handle("POST /apikey", a.auth(a.regenerateAPIKey))
	mux.Handle("GET /log", a.auth(a.sendLog))
	mux.Handle("GET /channel-fields", a.auth(a.channelFields))
	mux.Handle("GET /channels/new", a.auth(a.newChannelForm))
	mux.Handle("POST /channels", a.auth(a.createChannel))
	mux.Handle("GET /channels/{id}/edit", a.auth(a.editChannelForm))
	mux.Handle("PUT /channels/{id}", a.auth(a.updateChannel))
	mux.Handle("DELETE /channels/{id}", a.auth(a.deleteChannel))
	mux.Handle("POST /channels/{id}/test", a.auth(a.testChannel))
	return securityHeaders(mux)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src https://cdn.jsdelivr.net; "+
			"style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// redirect works for both plain requests and htmx requests.
func redirect(w http.ResponseWriter, r *http.Request, to string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", to)
		w.WriteHeader(http.StatusOK)
		return
	}
	http.Redirect(w, r, to, http.StatusSeeOther)
}

func serverError(w http.ResponseWriter, err error) {
	slog.Error("request failed", "err", err)
	http.Error(w, "internal server error", http.StatusInternalServerError)
}

func (a *app) render(w http.ResponseWriter, status int, name string, data any) {
	var buf bytes.Buffer
	if err := a.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		serverError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	buf.WriteTo(w)
}

// formError shows a validation message inside the channel form.
func formError(w http.ResponseWriter, msg string) {
	w.Header().Set("HX-Retarget", "#form-error")
	w.Header().Set("HX-Reswap", "innerHTML")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	io.WriteString(w, html.EscapeString(msg))
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil
}

// ---- API

func (a *app) notify(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, msg string) { writeJSON(w, status, map[string]any{"ok": false, "error": msg}) }
	if !a.checkAPIKey(r) {
		fail(http.StatusUnauthorized, "invalid or missing API key")
		return
	}
	id, ok := pathID(r)
	if !ok {
		fail(http.StatusNotFound, "channel not found")
		return
	}
	ch, err := a.getChannel(id)
	if errors.Is(err, sql.ErrNoRows) {
		fail(http.StatusNotFound, "channel not found")
		return
	} else if err != nil {
		slog.Error("load channel", "err", err)
		fail(http.StatusInternalServerError, "internal server error")
		return
	}

	var body struct {
		Title   string `json:"title"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		fail(http.StatusBadRequest, "body must be JSON: {\"title\": \"...\", \"message\": \"...\"}")
		return
	}
	if err := validateMessage(body.Title, body.Message); err != nil {
		fail(http.StatusBadRequest, err.Error())
		return
	}
	if err := a.deliver(r.Context(), ch, body.Title, body.Message, "api"); err != nil {
		fail(http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// ---- login and password

type authPage struct {
	CSRF       string
	MustChange bool
	Error      string
}

func (a *app) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.session(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	a.render(w, http.StatusOK, "login", authPage{})
}

func (a *app) login(w http.ResponseWriter, r *http.Request) {
	hash, err := a.setting("password_hash")
	if err != nil {
		serverError(w, err)
		return
	}
	pwErr := bcrypt.CompareHashAndPassword([]byte(hash), []byte(r.PostFormValue("password")))
	if r.PostFormValue("username") != "admin" || pwErr != nil {
		time.Sleep(time.Second) // slow down guessing
		a.render(w, http.StatusUnauthorized, "login", authPage{Error: "Wrong username or password."})
		return
	}

	token := rand.Text()
	if _, err := a.db.Exec(`INSERT INTO sessions(token_hash, csrf, expires_at) VALUES (?, ?, ?)`,
		hashToken(token), rand.Text(), time.Now().Add(sessionTTL).Unix()); err != nil {
		serverError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: token, Path: "/", MaxAge: int(sessionTTL.Seconds()),
		HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *app) logout(w http.ResponseWriter, r *http.Request, s *session) {
	if _, err := a.db.Exec(`DELETE FROM sessions WHERE token_hash = ?`, s.tokenHash); err != nil {
		serverError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: isHTTPS(r), SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *app) passwordPage(w http.ResponseWriter, r *http.Request, s *session) {
	mustChange, err := a.setting("must_change_password")
	if err != nil {
		serverError(w, err)
		return
	}
	a.render(w, http.StatusOK, "password", authPage{CSRF: s.csrf, MustChange: mustChange == "1"})
}

func (a *app) changePassword(w http.ResponseWriter, r *http.Request, s *session) {
	mustChange, err := a.setting("must_change_password")
	if err != nil {
		serverError(w, err)
		return
	}
	page := authPage{CSRF: s.csrf, MustChange: mustChange == "1"}
	cur, next, confirm := r.PostFormValue("current"), r.PostFormValue("new"), r.PostFormValue("confirm")

	hash, err := a.setting("password_hash")
	if err != nil {
		serverError(w, err)
		return
	}
	switch {
	case bcrypt.CompareHashAndPassword([]byte(hash), []byte(cur)) != nil:
		page.Error = "Current password is wrong."
	case len(next) < 8:
		page.Error = "New password must be at least 8 characters."
	case len(next) > 72:
		page.Error = "New password must be at most 72 bytes."
	case next != confirm:
		page.Error = "New passwords don't match."
	case next == cur:
		page.Error = "New password must be different from the current one."
	}
	if page.Error != "" {
		a.render(w, http.StatusBadRequest, "password", page)
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(next), bcrypt.DefaultCost)
	if err != nil {
		serverError(w, err)
		return
	}
	tx, err := a.db.Begin()
	if err != nil {
		serverError(w, err)
		return
	}
	defer tx.Rollback()
	if err := setSetting(tx, "password_hash", string(newHash)); err != nil {
		serverError(w, err)
		return
	}
	if err := setSetting(tx, "must_change_password", "0"); err != nil {
		serverError(w, err)
		return
	}
	// Sign out every other session.
	if _, err := tx.Exec(`DELETE FROM sessions WHERE token_hash != ?`, s.tokenHash); err != nil {
		serverError(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		serverError(w, err)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// ---- dashboard

type apiKeyView struct {
	Exists  bool
	Key     string // only set right after generating
	BaseURL string
}

type formView struct {
	ID   int64 // 0 for a new channel
	Name string
	Type string
	C    channelConfig // secrets removed
}

type sendView struct {
	Time      string
	ChannelID int64
	Channel   string
	Title     string
	Source    string
	Error     string
}

type channelsView struct {
	Channels []channel
	Form     formView
}

func (a *app) dashboard(w http.ResponseWriter, r *http.Request, s *session) {
	channels, err := a.listChannels()
	if err != nil {
		serverError(w, err)
		return
	}
	sends, err := a.recentSends()
	if err != nil {
		serverError(w, err)
		return
	}
	keyHash, err := a.setting("api_key_hash")
	if err != nil {
		serverError(w, err)
		return
	}
	a.render(w, http.StatusOK, "dashboard", map[string]any{
		"CSRF":     s.csrf,
		"APIKey":   apiKeyView{Exists: keyHash != ""},
		"Channels": channelsView{Channels: channels, Form: formView{Type: "discord"}},
		"Sends":    sends,
	})
}

func (a *app) regenerateAPIKey(w http.ResponseWriter, r *http.Request, s *session) {
	key := rand.Text()
	if err := setSetting(a.db, "api_key_hash", hashToken(key)); err != nil {
		serverError(w, err)
		return
	}
	slog.Info("API key regenerated")
	scheme := "http"
	if isHTTPS(r) {
		scheme = "https"
	}
	a.render(w, http.StatusOK, "apikey", apiKeyView{Exists: true, Key: key, BaseURL: scheme + "://" + r.Host})
}

func (a *app) recentSends() ([]sendView, error) {
	rows, err := a.db.Query(`SELECT created_at, channel_id, channel_name, title, source, error
		FROM sends WHERE created_at >= ? ORDER BY created_at DESC, id DESC LIMIT 500`, time.Now().Add(-logRetention).Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []sendView
	for rows.Next() {
		var v sendView
		var at int64
		if err := rows.Scan(&at, &v.ChannelID, &v.Channel, &v.Title, &v.Source, &v.Error); err != nil {
			return nil, err
		}
		v.Time = time.Unix(at, 0).Format("2006-01-02 15:04:05")
		out = append(out, v)
	}
	return out, rows.Err()
}

func (a *app) sendLog(w http.ResponseWriter, r *http.Request, s *session) {
	sends, err := a.recentSends()
	if err != nil {
		serverError(w, err)
		return
	}
	a.render(w, http.StatusOK, "log", sends)
}

// renderChannels re-renders the channel list and resets the form to "new".
func (a *app) renderChannels(w http.ResponseWriter) {
	channels, err := a.listChannels()
	if err != nil {
		serverError(w, err)
		return
	}
	a.render(w, http.StatusOK, "channelsUpdate", channelsView{Channels: channels, Form: formView{Type: "discord"}})
}

func (a *app) channelFields(w http.ResponseWriter, r *http.Request, s *session) {
	a.render(w, http.StatusOK, "fields", formView{Type: r.URL.Query().Get("type")})
}

func (a *app) newChannelForm(w http.ResponseWriter, r *http.Request, s *session) {
	a.render(w, http.StatusOK, "channelForm", formView{Type: "discord"})
}

func (a *app) editChannelForm(w http.ResponseWriter, r *http.Request, s *session) {
	ch, ok := a.channelFromPath(w, r)
	if !ok {
		return
	}
	a.render(w, http.StatusOK, "channelForm", formView{ID: ch.ID, Name: ch.Name, Type: ch.Type, C: ch.Config.public()})
}

func (a *app) channelFromPath(w http.ResponseWriter, r *http.Request) (channel, bool) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return channel{}, false
	}
	ch, err := a.getChannel(id)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return ch, false
	} else if err != nil {
		serverError(w, err)
		return ch, false
	}
	return ch, true
}

func (a *app) createChannel(w http.ResponseWriter, r *http.Request, s *session) {
	typ := r.FormValue("type")
	name, cfg, err := parseChannelForm(r, typ, channelConfig{})
	if err != nil {
		formError(w, err.Error())
		return
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		serverError(w, err)
		return
	}
	if _, err := a.db.Exec(`INSERT INTO channels(name, type, config) VALUES (?, ?, ?)`, name, typ, string(raw)); err != nil {
		serverError(w, err)
		return
	}
	a.renderChannels(w)
}

func (a *app) updateChannel(w http.ResponseWriter, r *http.Request, s *session) {
	ch, ok := a.channelFromPath(w, r)
	if !ok {
		return
	}
	name, cfg, err := parseChannelForm(r, ch.Type, ch.Config)
	if err != nil {
		formError(w, err.Error())
		return
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		serverError(w, err)
		return
	}
	if _, err := a.db.Exec(`UPDATE channels SET name = ?, config = ? WHERE id = ?`, name, string(raw), ch.ID); err != nil {
		serverError(w, err)
		return
	}
	a.renderChannels(w)
}

func (a *app) deleteChannel(w http.ResponseWriter, r *http.Request, s *session) {
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if _, err := a.db.Exec(`DELETE FROM channels WHERE id = ?`, id); err != nil {
		serverError(w, err)
		return
	}
	a.renderChannels(w)
}

func (a *app) testChannel(w http.ResponseWriter, r *http.Request, s *session) {
	ch, ok := a.channelFromPath(w, r)
	if !ok {
		return
	}
	err := a.deliver(r.Context(), ch, testTitle, testMessage, "test")
	w.Header().Set("HX-Trigger", "logChanged")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err != nil {
		io.WriteString(w, `<span class="err">`+html.EscapeString(err.Error())+`</span>`)
		return
	}
	io.WriteString(w, `<span class="ok">Sent ✓</span>`)
}

// ---------------------------------------------------------------- templates

const templates = `
{{define "head"}}<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="htmx-config" content='{"includeIndicatorStyles":false,"responseHandling":[{"code":"204","swap":false},{"code":"[23]..","swap":true},{"code":"422","swap":true},{"code":"[45]..","swap":false,"error":true}]}'>
<title>Alertoba</title>
<script src="https://cdn.jsdelivr.net/npm/htmx.org@2.0.4/dist/htmx.min.js" integrity="sha384-HGfztofotfshcF7+8n44JQL2oJmowVChPTg48S+jvZoztPfvwD79OC/LTtG6dMp+" crossorigin="anonymous"></script>
<style>
:root{--bg:#f6f6f7;--fg:#1c1c1f;--muted:#6a6a72;--card:#fff;--line:#e1e1e6;--accent:#2f5bd3;--ok:#1a7f37;--err:#c62828;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#131315;--fg:#ececf0;--muted:#9b9ba4;--card:#1c1c20;--line:#303036;--accent:#7b9cff;--ok:#4cc26b;--err:#ff6b6b}}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 system-ui,-apple-system,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:960px;margin:0 auto;padding:24px 16px}
main.narrow{max-width:400px;padding-top:10vh}
header{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
header h1{margin:0;font-size:22px;flex:1}
a{color:var(--accent)}
section{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px 20px;margin:16px 0}
h2{font-size:17px;margin:0 0 12px}
h3{font-size:15px;margin:20px 0 4px}
label{display:block;margin:10px 0;font-weight:500;font-size:14px}
input,select{display:block;width:100%;margin-top:4px;padding:8px 10px;font:inherit;font-weight:400;color:inherit;background:var(--bg);border:1px solid var(--line);border-radius:6px}
button{font:inherit;font-size:14px;padding:6px 12px;border-radius:6px;border:1px solid var(--line);background:var(--card);color:inherit;cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button:focus-visible,input:focus-visible,select:focus-visible{outline:2px solid var(--accent);outline-offset:1px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:500}
td.actions button{margin:0 4px 4px 0}
pre{background:var(--bg);border:1px solid var(--line);padding:10px;border-radius:6px;white-space:pre-wrap;word-break:break-all;font-size:13px}
.ok{color:var(--ok)}.err{color:var(--err)}
.muted,.hint{color:var(--muted);font-size:13px}
.result{display:block;margin-top:4px;white-space:normal;font-size:13px}
form.inline{display:inline;margin:0}
.htmx-request{opacity:.6}
</style>
</head>{{end}}

{{define "login"}}{{template "head"}}
<body><main class="narrow">
<h1>Alertoba</h1>
<section>
<form method="post" action="/login">
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<label>Username <input name="username" autocomplete="username" required autofocus></label>
<label>Password <input name="password" type="password" autocomplete="current-password" required></label>
<button type="submit" class="primary">Log in</button>
</form>
</section>
</main></body></html>{{end}}

{{define "password"}}{{template "head"}}
<body><main class="narrow">
<h1>Change password</h1>
<section>
{{if .MustChange}}<p>You're using the default password. Choose a new one to continue.</p>{{end}}
<form method="post" action="/password">
<input type="hidden" name="csrf" value="{{.CSRF}}">
{{if .Error}}<p class="err" role="alert">{{.Error}}</p>{{end}}
<label>Current password <input name="current" type="password" autocomplete="current-password" required autofocus></label>
<label>New password <input name="new" type="password" autocomplete="new-password" minlength="8" maxlength="72" required></label>
<label>Repeat new password <input name="confirm" type="password" autocomplete="new-password" minlength="8" maxlength="72" required></label>
<button type="submit" class="primary">Save password</button>
{{if not .MustChange}} <a href="/">Cancel</a>{{end}}
</form>
</section>
</main></body></html>{{end}}

{{define "dashboard"}}{{template "head"}}
<body hx-headers='{"X-CSRF-Token": "{{.CSRF}}"}'><main>
<header>
<h1>Alertoba</h1>
<a href="/password">Change password</a>
<form class="inline" method="post" action="/logout"><input type="hidden" name="csrf" value="{{.CSRF}}"><button type="submit">Log out</button></form>
</header>

<section>
<h2>API key</h2>
<div id="apikey">{{template "apikey" .APIKey}}</div>
</section>

<section>
<h2>Channels</h2>
<div id="channels">{{template "channels" .Channels.Channels}}</div>
<div id="channel-form">{{template "channelForm" .Channels.Form}}</div>
</section>

<section>
<h2>Sent in the last 7 days</h2>
<div id="log" hx-get="/log" hx-trigger="logChanged from:body, every 30s">{{template "log" .Sends}}</div>
</section>
</main></body></html>{{end}}

{{define "apikey"}}
{{if .Key}}
<p class="ok">New key created. Copy it now: it won't be shown again.</p>
<pre>{{.Key}}</pre>
<p class="hint">Example:</p>
<pre>curl -X POST {{.BaseURL}}/api/notify/CHANNEL_ID \
  -H "Authorization: Bearer {{.Key}}" \
  -H "Content-Type: application/json" \
  -d '{"title": "Disk almost full", "message": "/dev/sda1 is at 95%"}'</pre>
{{else if .Exists}}<p>An API key is set. Regenerate it if it leaked; the old key stops working immediately.</p>
{{else}}<p>No API key yet. Generate one to start sending notifications.</p>{{end}}
<button hx-post="/apikey" hx-target="#apikey"{{if .Exists}} hx-confirm="Generate a new key? The current key stops working immediately."{{end}}>{{if .Exists}}Regenerate key{{else}}Generate key{{end}}</button>
{{end}}

{{define "channels"}}
{{if .}}<div class="scroll"><table>
<thead><tr><th>ID</th><th>Name</th><th>Type</th><th></th></tr></thead>
<tbody>{{range .}}<tr>
<td>{{.ID}}</td><td>{{.Name}}</td><td>{{.Type}}</td>
<td class="actions">
<button hx-post="/channels/{{.ID}}/test" hx-target="#test-{{.ID}}">Send test</button>
<button hx-get="/channels/{{.ID}}/edit" hx-target="#channel-form">Edit</button>
<button hx-delete="/channels/{{.ID}}" hx-target="#channels" hx-confirm="Delete channel “{{.Name}}”?">Delete</button>
<span id="test-{{.ID}}" class="result" aria-live="polite"></span>
</td></tr>{{end}}</tbody>
</table></div>
{{else}}<p class="muted">No channels yet. Add one below.</p>{{end}}
{{end}}

{{define "channelsUpdate"}}{{template "channels" .Channels}}
<div id="channel-form" hx-swap-oob="true">{{template "channelForm" .Form}}</div>{{end}}

{{define "channelForm"}}
<form {{if .ID}}hx-put="/channels/{{.ID}}"{{else}}hx-post="/channels"{{end}} hx-target="#channels">
<h3>{{if .ID}}Edit channel #{{.ID}} ({{.Type}}){{else}}Add channel{{end}}</h3>
<div id="form-error" class="err" role="alert"></div>
<label>Name <input name="name" value="{{.Name}}" maxlength="100" required></label>
{{if not .ID}}<label>Type
<select name="type" hx-get="/channel-fields" hx-target="#type-fields">
<option value="discord">Discord webhook</option>
<option value="alertzy">Alertzy</option>
<option value="smtp">SMTP email</option>
</select></label>{{end}}
<div id="type-fields">{{template "fields" .}}</div>
<button type="submit" class="primary">{{if .ID}}Save{{else}}Add channel{{end}}</button>
{{if .ID}}<button type="button" hx-get="/channels/new" hx-target="#channel-form">Cancel</button>{{end}}
</form>
{{end}}

{{define "fields"}}
{{if eq .Type "discord"}}
<label>Webhook URL <input name="webhook_url" type="password" autocomplete="off" {{if .ID}}placeholder="•••••• (leave blank to keep)"{{else}}placeholder="https://discord.com/api/webhooks/…" required{{end}}></label>
{{else if eq .Type "alertzy"}}
<label>Account key <input name="account_key" type="password" autocomplete="off" {{if .ID}}placeholder="•••••• (leave blank to keep)"{{else}}required{{end}}></label>
{{else if eq .Type "smtp"}}
<label>Host <input name="host" value="{{.C.Host}}" placeholder="smtp.example.com" required></label>
<label>Port <input name="port" type="number" min="1" max="65535" value="{{if .C.Port}}{{.C.Port}}{{else}}587{{end}}" required></label>
<label>Security <select name="tls">
<option value="starttls"{{if ne .C.TLS "tls"}} selected{{end}}>STARTTLS (usually port 587)</option>
<option value="tls"{{if eq .C.TLS "tls"}} selected{{end}}>TLS (usually port 465)</option>
</select></label>
<label>Username <input name="username" value="{{.C.Username}}" autocomplete="off"></label>
<label>Password <input name="password" type="password" autocomplete="new-password"{{if .ID}} placeholder="•••••• (leave blank to keep)"{{end}}></label>
<p class="hint">Use an app password or send-only credentials (Mailgun, SES, Postmark…), not your main mailbox password.</p>
<label>From <input name="from" value="{{.C.From}}" placeholder="Alerts &lt;alerts@example.com&gt;" required></label>
<label>To <input name="to" value="{{.C.To}}" placeholder="ops@example.com, me@example.com" required></label>
{{else}}<p class="err">Unknown channel type.</p>{{end}}
{{end}}

{{define "log"}}
{{if .}}<div class="scroll"><table>
<thead><tr><th>Time</th><th>Channel</th><th>Title</th><th>Source</th><th>Result</th></tr></thead>
<tbody>{{range .}}<tr>
<td>{{.Time}}</td><td>{{.Channel}} <span class="muted">#{{.ChannelID}}</span></td><td>{{.Title}}</td><td>{{.Source}}</td>
<td>{{if .Error}}<span class="err">{{.Error}}</span>{{else}}<span class="ok">Sent</span>{{end}}</td>
</tr>{{end}}</tbody>
</table></div>
{{else}}<p class="muted">Nothing sent in the last 7 days.</p>{{end}}
{{end}}
`
