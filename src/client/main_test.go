package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Run the real main in a subprocess to exercise flag parsing and exit codes.
func TestCLIHelper(t *testing.T) {
	if os.Getenv("TESTPASSWORD_CLI_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"testpassword"}, os.Args[i+1:]...)
			break
		}
	}
	flag.CommandLine = flag.NewFlagSet("testpassword", flag.ExitOnError)
	main()
}

func TestPasswordInputs(t *testing.T) {
	for _, tc := range []struct {
		name         string
		args         []string
		env          *string
		wantPassword *string
		wantPath     string
		wantExit     int
	}{
		{"environment", nil, strptr("  env-secret\n"), strptr("  env-secret\n"), "/check", 1},
		{"empty environment", nil, strptr(""), strptr(""), "/check", 1},
		{"legacy overrides environment", []string{"--password", "legacy-secret"}, strptr("env-secret"), strptr("legacy-secret"), "/check", 1},
		{"empty legacy password", []string{"--password", ""}, nil, strptr(""), "/check", 1},
		{"hash overrides environment", []string{"--sha1", strings.Repeat("A", 40)}, strptr("env-secret"), nil, "/lookup/sha1/" + strings.Repeat("A", 40), 1},
		{"missing input", nil, nil, nil, "", 2},
		{"conflicting inputs", []string{"--prompt", "--password", "legacy-secret"}, nil, nil, "", 2},
		{"prompt requires terminal", []string{"--prompt"}, strptr("env-secret"), nil, "", 2},
		{"unexpected positional secret", []string{"positional-secret"}, strptr("env-secret"), nil, "", 2},
		{"invalid formats", []string{"--formats", "invalid"}, strptr("env-secret"), nil, "", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			type request struct {
				path string
				body checkRequest
			}
			requests := make(chan request, 4)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body checkRequest
				if r.Method == http.MethodPost {
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Errorf("invalid request: %v", err)
					}
				}
				requests <- request{r.URL.Path, body}
				result := lookupResult{Format: "sha1", Hash: strings.Repeat("A", 40), Pwned: true, Count: 10, DataLoaded: true, DataComplete: true}
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodPost {
					_ = json.NewEncoder(w).Encode(checkResponse{Results: map[string]lookupResult{"sha1": result}})
				} else {
					_ = json.NewEncoder(w).Encode(result)
				}
			}))
			defer server.Close()

			args := []string{"-test.run=^TestCLIHelper$", "--", "--api", server.URL, "--formats", "sha1"}
			cmd := exec.Command(os.Args[0], append(args, tc.args...)...)
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, passwordEnv+"=") && !strings.HasPrefix(value, "TESTPASSWORD_CLI_HELPER=") {
					cmd.Env = append(cmd.Env, value)
				}
			}
			cmd.Env = append(cmd.Env, "TESTPASSWORD_CLI_HELPER=1")
			if tc.env != nil {
				cmd.Env = append(cmd.Env, passwordEnv+"="+*tc.env)
			}
			output, _ := cmd.CombinedOutput()
			if cmd.ProcessState == nil {
				t.Fatal("CLI did not start")
			}
			if got := cmd.ProcessState.ExitCode(); got != tc.wantExit {
				t.Fatalf("exit %d, want %d; output: %s", got, tc.wantExit, output)
			}
			for _, secret := range []string{"env-secret", "legacy-secret", "positional-secret"} {
				if bytes.Contains(output, []byte(secret)) {
					t.Fatal("plaintext password appeared in CLI output")
				}
			}
			if tc.wantPath == "" {
				if len(requests) != 0 {
					t.Fatal("unexpected API request")
				}
				return
			}
			select {
			case req := <-requests:
				if req.path != tc.wantPath {
					t.Errorf("request path %q, want %q", req.path, tc.wantPath)
				}
				if tc.wantPassword != nil && req.body.Password != *tc.wantPassword {
					t.Error("password was not passed through exactly")
				}
			default:
				t.Fatal("missing API request")
			}
		})
	}
}

func strptr(s string) *string { return &s }

func runResultCLI(t *testing.T, response string, args ...string) (int, string) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, response)
	}))
	defer server.Close()
	commandArgs := []string{"-test.run=^TestCLIHelper$", "--", "--api", server.URL}
	cmd := exec.Command(os.Args[0], append(commandArgs, args...)...)
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, passwordEnv+"=") && !strings.HasPrefix(value, "TESTPASSWORD_CLI_HELPER=") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "TESTPASSWORD_CLI_HELPER=1", passwordEnv+"=review-secret")
	output, _ := cmd.CombinedOutput()
	if cmd.ProcessState == nil {
		t.Fatal("CLI did not start")
	}
	return cmd.ProcessState.ExitCode(), string(output)
}

func resultJSON(format string, changes map[string]any) string {
	hashLength := 40
	if format == "ntlm" {
		hashLength = 32
	}
	result := map[string]any{
		"format": format, "hash": strings.Repeat("A", hashLength),
		"pwned": false, "count": 0, "data_loaded": true, "data_complete": true,
	}
	for k, v := range changes {
		result[k] = v
	}
	data, _ := json.Marshal(result)
	return string(data)
}

func TestSingleResultExitCodes(t *testing.T) {
	for _, mode := range []string{"sha1", "ntlm", "password"} {
		format := mode
		if mode == "password" {
			format = "sha1"
		}
		for _, tc := range []struct {
			name       string
			changes    map[string]any
			wantExit   int
			wantOutput string
		}{
			{"complete negative", nil, 0, "not pwned"},
			{"complete match", map[string]any{"pwned": true, "count": 5}, 1, "PWNED"},
			{"missing dataset", map[string]any{"data_loaded": false, "data_complete": false}, 2, "inconclusive"},
			{"incomplete dataset", map[string]any{"data_complete": false}, 2, "inconclusive"},
			{"match in incomplete dataset", map[string]any{"pwned": true, "count": 5, "data_complete": false}, 1, "PWNED"},
			{"null status", map[string]any{"pwned": nil}, 2, "invalid"},
			{"null count", map[string]any{"count": nil}, 2, "invalid"},
			{"null dataset state", map[string]any{"data_complete": nil}, 2, "invalid"},
			{"wrong status type", map[string]any{"pwned": "false"}, 2, "invalid"},
			{"negative count", map[string]any{"count": -1}, 2, "invalid"},
			{"contradictory negative", map[string]any{"count": 5}, 2, "invalid"},
			{"contradictory positive", map[string]any{"pwned": true}, 2, "invalid"},
			{"wrong format", map[string]any{"format": "other"}, 2, "invalid"},
			{"malformed hash", map[string]any{"hash": "xyz"}, 2, "invalid"},
		} {
			t.Run(mode+"/"+tc.name, func(t *testing.T) {
				body := resultJSON(format, tc.changes)
				args := []string{"--" + format, strings.Repeat("A", 40)}
				if format == "ntlm" {
					args[1] = strings.Repeat("A", 32)
				}
				if mode == "password" {
					body = `{"results":{"sha1":` + body + `}}`
					args = []string{"--formats", "sha1"}
				}
				code, output := runResultCLI(t, body, args...)
				if code != tc.wantExit || !strings.Contains(output, tc.wantOutput) {
					t.Fatalf("exit %d, output %q; want exit %d containing %q", code, output, tc.wantExit, tc.wantOutput)
				}
				if tc.wantExit == 2 && strings.Contains(output, "not pwned") {
					t.Fatal("inconclusive result reported as not pwned")
				}
			})
		}
	}
}

func TestMultipleResultExitCodes(t *testing.T) {
	negative := resultJSON("sha1", nil)
	positive := resultJSON("sha1", map[string]any{"pwned": true, "count": 5})
	ntlmNegative := resultJSON("ntlm", nil)
	ntlmPositive := resultJSON("ntlm", map[string]any{"pwned": true, "count": 5})
	incomplete := resultJSON("ntlm", map[string]any{"data_complete": false})
	for _, tc := range []struct {
		name     string
		body     string
		wantExit int
	}{
		{"all complete negative", `{"results":{"sha1":` + negative + `,"ntlm":` + ntlmNegative + `}}`, 0},
		{"negative with missing result", `{"results":{"sha1":` + negative + `}}`, 2},
		{"negative with incomplete dataset", `{"results":{"sha1":` + negative + `,"ntlm":` + incomplete + `}}`, 2},
		{"match with incomplete dataset", `{"results":{"sha1":` + positive + `,"ntlm":` + incomplete + `}}`, 1},
		{"match with missing result", `{"results":{"sha1":` + positive + `}}`, 1},
		{"missing first result with match", `{"results":{"ntlm":` + ntlmPositive + `}}`, 1},
		{"match with invalid result", `{"results":{"sha1":` + positive + `,"ntlm":{"pwned":"invalid"}}}`, 1},
		{"invalid first result with match", `{"results":{"sha1":false,"ntlm":` + ntlmPositive + `}}`, 1},
		{"unrequested match ignored", `{"results":{"other":` + positive + `,"sha1":` + negative + `,"ntlm":` + ntlmNegative + `}}`, 0},
		{"empty object", `{}`, 2},
		{"null response", `null`, 2},
		{"empty results", `{"results":{}}`, 2},
		{"null results", `{"results":null}`, 2},
		{"null result", `{"results":{"sha1":null,"ntlm":` + ntlmNegative + `}}`, 2},
		{"malformed JSON", `{"results":`, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, output := runResultCLI(t, tc.body)
			if code != tc.wantExit {
				t.Fatalf("exit %d, want %d; output: %s", code, tc.wantExit, output)
			}
			if tc.wantExit == 1 && !strings.Contains(output, "warning:") {
				t.Fatal("missing warning about another inconclusive check")
			}
		})
	}
}

func TestMissingResultFields(t *testing.T) {
	var fields map[string]json.RawMessage
	_ = json.Unmarshal([]byte(resultJSON("sha1", nil)), &fields)
	for key := range fields {
		t.Run(key, func(t *testing.T) {
			partial := make(map[string]json.RawMessage)
			for k, v := range fields {
				if k != key {
					partial[k] = v
				}
			}
			body, _ := json.Marshal(partial)
			code, output := runResultCLI(t, string(body), "--sha1", strings.Repeat("A", 40))
			if code != 2 || !strings.Contains(output, "missing or null "+key) {
				t.Fatalf("exit %d, output %q; expected rejection of missing %s", code, output, key)
			}
		})
	}
	t.Run("wrong hash", func(t *testing.T) {
		code, output := runResultCLI(t, resultJSON("sha1", nil), "--sha1", strings.Repeat("B", 40))
		if code != 2 || !strings.Contains(output, "hash does not match") {
			t.Fatalf("exit %d, output %q; expected rejection of mismatched hash", code, output)
		}
	})
}

func TestSelfSignedTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, resultJSON("sha1", nil))
	}))
	defer server.Close()
	for _, tc := range []struct {
		name     string
		env      string
		args     []string
		wantExit int
	}{
		{"verified default rejects self-signed", "", nil, 2},
		{"environment disables verification", "true", nil, 0},
		{"false keeps verification", "false", nil, 2},
		{"flag disables verification", "", []string{"--insecure"}, 0},
		{"flag restores verification", "true", []string{"--insecure=false"}, 2},
		{"invalid environment fails closed", "invalid", nil, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"-test.run=^TestCLIHelper$", "--", "--api", server.URL, "--sha1", strings.Repeat("A", 40)}
			cmd := exec.Command(os.Args[0], append(args, tc.args...)...)
			for _, value := range os.Environ() {
				if !strings.HasPrefix(value, insecureEnv+"=") && !strings.HasPrefix(value, "TESTPASSWORD_CLI_HELPER=") {
					cmd.Env = append(cmd.Env, value)
				}
			}
			cmd.Env = append(cmd.Env, "TESTPASSWORD_CLI_HELPER=1", insecureEnv+"="+tc.env)
			output, _ := cmd.CombinedOutput()
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != tc.wantExit {
				t.Fatalf("expected exit %d; output: %s", tc.wantExit, output)
			}
		})
	}
}
