// Command testpassword is a small CLI client for the pwned-password lookup API.
//
// It performs exactly one lookup per invocation:
//
//	testpassword --sha1 <40-hex>              look up a SHA1 hash directly
//	testpassword --ntlm <32-hex>              look up an NTLM hash directly
//	testpassword --prompt                    read a password without terminal echo
//	testpassword                             read TESTPASSWORD_PASSWORD
//
// Password inputs are hashed server-side to the selected formats
// (default: both sha1 and ntlm). Select a subset with --formats.
// Explicit inputs override TESTPASSWORD_PASSWORD. The legacy --password flag
// remains available, but exposes plaintext in process arguments.
//
// Exit codes: 0 = all requested checks complete with no match, 1 = a confirmed
// match in any requested format, 2 = error or inconclusive check.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"
)

const passwordEnv = "TESTPASSWORD_PASSWORD"
const insecureEnv = "TESTPASSWORD_TLS_INSECURE"

type lookupResult struct {
	Format       string `json:"format"`
	Hash         string `json:"hash"`
	Pwned        bool   `json:"pwned"`
	Count        int64  `json:"count"`
	DataLoaded   bool   `json:"data_loaded"`
	DataComplete bool   `json:"data_complete"`
}

type checkRequest struct {
	Password string   `json:"password"`
	Formats  []string `json:"formats"`
}

type checkResponse struct {
	Results      map[string]lookupResult `json:"results"`
	resultErrors map[string]error
}

type apiError struct {
	Detail string `json:"detail"`
}

func main() {
	var (
		sha1Flag     = flag.String("sha1", "", "SHA1 hash (40 hex) to look up directly")
		ntlmFlag     = flag.String("ntlm", "", "NTLM hash (32 hex) to look up directly")
		passwordFlag = flag.String("password", "", "legacy plaintext input (exposed in process arguments); prefer --prompt or TESTPASSWORD_PASSWORD")
		promptFlag   = flag.Bool("prompt", false, "read a password from the terminal without echo")
		formatsFlag  = flag.String("formats", "both", "password hash formats: sha1, ntlm, or both (comma-separated)")
		apiFlag      = flag.String("api", "http://127.0.0.1:8000", "API base URL")
		insecureFlag = flag.Bool("insecure", false, "skip HTTPS certificate and hostname verification (or set TESTPASSWORD_TLS_INSECURE=true)")
		timeoutFlag  = flag.Duration("timeout", 10*time.Second, "HTTP request timeout")
	)
	flag.Parse()
	if flag.NArg() != 0 {
		fatal(fmt.Errorf("unexpected positional arguments; use --prompt or %s for password input", passwordEnv))
	}

	provided := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	inputs := 0
	if provided["sha1"] {
		inputs++
	}
	if provided["ntlm"] {
		inputs++
	}
	if provided["password"] {
		inputs++
	}
	if *promptFlag {
		inputs++
	}
	password := *passwordFlag
	if inputs == 0 {
		var present bool
		password, present = os.LookupEnv(passwordEnv)
		if present {
			inputs++
		}
	}
	if inputs != 1 {
		fmt.Fprintln(os.Stderr, "error: provide one of --sha1, --ntlm, --prompt, or --password; otherwise set "+passwordEnv)
		flag.Usage()
		os.Exit(2)
	}

	insecure := *insecureFlag
	if !provided["insecure"] {
		if value := os.Getenv(insecureEnv); value != "" {
			var err error
			insecure, err = strconv.ParseBool(value)
			if err != nil {
				fatal(fmt.Errorf("%s must be true or false", insecureEnv))
			}
		}
	}
	client := newHTTPClient(*timeoutFlag, insecure)
	base := strings.TrimRight(*apiFlag, "/")
	var results []lookupResult
	var resultErrors []error

	switch {
	case provided["sha1"]:
		r, err := doLookup(client, base, "sha1", *sha1Flag)
		if err != nil {
			fatal(err)
		}
		results = append(results, r)
	case provided["ntlm"]:
		r, err := doLookup(client, base, "ntlm", *ntlmFlag)
		if err != nil {
			fatal(err)
		}
		results = append(results, r)
	default:
		fmts, err := parseFormats(*formatsFlag)
		if err != nil {
			fatal(err)
		}
		if *promptFlag {
			password, err = promptPassword()
			if err != nil {
				fatal(err)
			}
		}
		resp, err := doCheck(client, base, password, fmts)
		if err != nil {
			fatal(err)
		}
		for _, f := range fmts {
			if err := resp.resultErrors[f]; err != nil {
				resultErrors = append(resultErrors, err)
			} else {
				results = append(results, resp.Results[f])
			}
		}
	}

	compromised := false
	for _, r := range results {
		printResult(r, "")
		if r.Pwned {
			compromised = true
		} else if !r.DataLoaded {
			resultErrors = append(resultErrors, fmt.Errorf("%s dataset not loaded", r.Format))
		} else if !r.DataComplete {
			resultErrors = append(resultErrors, fmt.Errorf("%s dataset incomplete", r.Format))
		}
	}
	if compromised {
		if len(resultErrors) > 0 {
			fmt.Fprintln(os.Stderr, "warning: other requested checks were inconclusive:", errors.Join(resultErrors...))
		}
		os.Exit(1)
	}
	if len(resultErrors) > 0 {
		fatal(fmt.Errorf("lookup inconclusive: %w", errors.Join(resultErrors...)))
	}
	os.Exit(0)
}

// Certificate verification is enabled unless explicitly disabled by the user.
func newHTTPClient(timeout time.Duration, insecure bool) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure, // Explicit --insecure / environment opt-in.
	}
	return &http.Client{Timeout: timeout, Transport: transport}
}

func promptPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("--prompt requires a terminal; set %s for automation", passwordEnv)
	}
	state, err := term.GetState(fd)
	if err != nil {
		return "", fmt.Errorf("reading terminal state: %w", err)
	}

	// ReadPassword restores terminal settings on return. Also restore them when
	// interrupted, so Ctrl-C or SIGTERM cannot leave the user's echo disabled.
	signals := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer func() {
		signal.Stop(signals)
		close(done)
	}()
	go func() {
		select {
		case <-signals:
			_ = term.Restore(fd, state)
			fmt.Fprintln(os.Stderr, "\nerror: password prompt interrupted")
			os.Exit(2)
		case <-done:
		}
	}()

	fmt.Fprint(os.Stderr, "Password: ")
	password, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	value := string(password)
	clear(password)
	return value, nil
}

func printResult(r lookupResult, indent string) {
	status := "not pwned"
	if r.Pwned {
		status = fmt.Sprintf("PWNED (seen %s times)", withCommas(r.Count))
	} else if !r.DataLoaded {
		status = fmt.Sprintf("inconclusive  [%s dataset not loaded]", r.Format)
	} else if !r.DataComplete {
		status = fmt.Sprintf("inconclusive  [%s dataset incomplete]", r.Format)
	}
	pad := indent + strings.Repeat(" ", 6)
	fmt.Printf("%s%-4s  %s\n%s%s\n", indent, strings.ToUpper(r.Format), r.Hash, pad, status)
}

func parseFormats(s string) ([]string, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "both" {
		return []string{"sha1", "ntlm"}, nil
	}
	var out []string
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if f != "sha1" && f != "ntlm" {
			return nil, fmt.Errorf("invalid format %q (use sha1, ntlm, or both)", f)
		}
		if !contains(out, f) {
			out = append(out, f)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no formats specified")
	}
	return out, nil
}

func doLookup(client *http.Client, base, format, hash string) (lookupResult, error) {
	resp, err := client.Get(fmt.Sprintf("%s/lookup/%s/%s", base, format, hash))
	if err != nil {
		return lookupResult{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return lookupResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return lookupResult{}, apiStatusError(resp.StatusCode, body)
	}
	return decodeLookupResult(body, format, hash)
}

func doCheck(client *http.Client, base, password string, formats []string) (checkResponse, error) {
	payload, _ := json.Marshal(checkRequest{Password: password, Formats: formats})
	resp, err := client.Post(base+"/check", "application/json", bytes.NewReader(payload))
	if err != nil {
		return checkResponse{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return checkResponse{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return checkResponse{}, apiStatusError(resp.StatusCode, body)
	}
	var envelope struct {
		Results map[string]json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return checkResponse{}, fmt.Errorf("decoding response: %w", err)
	}
	cr := checkResponse{Results: make(map[string]lookupResult), resultErrors: make(map[string]error)}
	// Validate each requested format separately. A broken or missing result must
	// not hide a confirmed match in another format, regardless of their order.
	for _, format := range formats {
		body, ok := envelope.Results[format]
		if !ok {
			cr.resultErrors[format] = fmt.Errorf("missing %s result in API response", format)
			continue
		}
		r, err := decodeLookupResult(body, format, "")
		if err != nil {
			cr.resultErrors[format] = err
		} else {
			cr.Results[format] = r
		}
	}
	return cr, nil
}

func decodeLookupResult(body []byte, format, expectedHash string) (lookupResult, error) {
	invalid := func(reason string) (lookupResult, error) {
		return lookupResult{}, fmt.Errorf("invalid %s result in API response: %s", format, reason)
	}
	// Zero values alone cannot distinguish an explicit negative from omitted
	// fields or JSON null. Require the complete result contract before using it.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return invalid("expected a result object")
	}
	for _, key := range []string{"format", "hash", "pwned", "count", "data_loaded", "data_complete"} {
		value, ok := fields[key]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return invalid("missing or null " + key)
		}
	}
	var r lookupResult
	if err := json.Unmarshal(body, &r); err != nil {
		return invalid("incorrect field types")
	}
	if r.Format != format {
		return invalid("format does not match the request")
	}
	hashLength := 40
	if format == "ntlm" {
		hashLength = 32
	}
	if _, err := hex.DecodeString(r.Hash); err != nil || len(r.Hash) != hashLength {
		return invalid("malformed hash")
	}
	if expectedHash != "" && !strings.EqualFold(r.Hash, strings.TrimSpace(expectedHash)) {
		return invalid("hash does not match the request")
	}
	if r.Count < 0 || r.Pwned != (r.Count > 0) {
		return invalid("inconsistent breach count and status")
	}
	return r, nil
}

func apiStatusError(code int, body []byte) error {
	var e apiError
	if json.Unmarshal(body, &e) == nil && e.Detail != "" {
		return fmt.Errorf("API error %d: %s", code, e.Detail)
	}
	return fmt.Errorf("API error %d: %s", code, strings.TrimSpace(string(body)))
}

func withCommas(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	if rem := len(s) % 3; rem != 0 {
		b.WriteString(s[:rem])
	}
	for i := len(s) % 3; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteString(",")
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(2)
}
