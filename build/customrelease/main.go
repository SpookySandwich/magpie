// Command customrelease builds the Windows magpie.com companion launcher and
// generates signed release manifests (SHA256SUMS, SHA256SUMS.sig, latest.json)
// for the custom fork release workflow.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const comMagic = "\x00magpie-com-target"

type releaseManifest struct {
	Version string                   `json:"version"`
	Notes   string                   `json:"notes"`
	URL     string                   `json:"url"`
	Assets  map[string]manifestAsset `json:"assets"`
	Signed  *manifestSigned          `json:"signed,omitempty"`
}

type manifestAsset struct {
	URL    string `json:"url"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	GitHub string `json:"github,omitempty"`
}

type manifestSigned struct {
	Sums string `json:"sums"`
	Sig  string `json:"sig"`
}

func main() {
	if len(os.Args) < 2 {
		fatalf("usage: customrelease <com|manifest> [args]")
	}
	var err error
	switch os.Args[1] {
	case "com":
		err = runCom(os.Args[2:])
	case "manifest":
		err = runManifest(os.Args[2:])
	default:
		fatalf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fatalf("%v", err)
	}
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "customrelease: "+format+"\n", args...)
	os.Exit(1)
}

func runCom(args []string) error {
	if len(args) != 3 {
		return errors.New("usage: customrelease com <launcher.com> <targetExeName> <out.com>")
	}
	launcher, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	name := filepath.Base(strings.ReplaceAll(args[1], `\`, "/"))
	if name == "" || name == "." {
		return fmt.Errorf("invalid target exe name %q", args[1])
	}
	out := make([]byte, 0, len(launcher)+1+len(name)+len(comMagic))
	out = append(out, launcher...)
	out = append(out, 0)
	out = append(out, name...)
	out = append(out, comMagic...)
	if err := os.MkdirAll(filepath.Dir(args[2]), 0o755); err != nil {
		return err
	}
	return os.WriteFile(args[2], out, 0o755)
}

func decodePrivateKey(rawB64 string) (ed25519.PrivateKey, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(rawB64))
	if err != nil {
		return nil, fmt.Errorf("decode CUSTOM_UPDATE_SIGNING_KEY: %w", err)
	}
	switch len(raw) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	default:
		return nil, fmt.Errorf("unexpected private key length %d (expected 32 or 64 bytes)", len(raw))
	}
}

func runManifest(args []string) error {
	fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
	version := fs.String("version", "", "release version without v prefix (e.g. 0.1.8753)")
	repo := fs.String("repo", "", "GitHub owner/repo")
	pubB64 := fs.String("pub", "", "expected base64 public signing key")
	notesPath := fs.String("notes", "", "path to markdown release notes")
	dir := fs.String("dir", "dist", "directory containing built release assets")
	if err := fs.Parse(args); err != nil {
		return err
	}
	ver := strings.TrimPrefix(strings.TrimSpace(*version), "v")
	if ver == "" || *repo == "" || *dir == "" {
		return errors.New("--version, --repo, and --dir are required")
	}
	keyEnv := os.Getenv("CUSTOM_UPDATE_SIGNING_KEY")
	if strings.TrimSpace(keyEnv) == "" {
		return errors.New("CUSTOM_UPDATE_SIGNING_KEY environment variable is empty")
	}
	priv, err := decodePrivateKey(keyEnv)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	if *pubB64 != "" {
		wantPub, err := base64.StdEncoding.DecodeString(strings.TrimSpace(*pubB64))
		if err != nil || len(wantPub) != ed25519.PublicKeySize {
			return fmt.Errorf("invalid --pub key: %w", err)
		}
		if !bytes.Equal(pub, wantPub) {
			return errors.New("CUSTOM_UPDATE_SIGNING_KEY does not match embedded signingKey (--pub)")
		}
	}

	var notes string
	if *notesPath != "" {
		b, err := os.ReadFile(*notesPath)
		if err != nil {
			return err
		}
		notes = strings.TrimSpace(string(b))
	}

	entries, err := os.ReadDir(*dir)
	if err != nil {
		return err
	}
	skip := map[string]bool{
		"SHA256SUMS":     true,
		"SHA256SUMS.sig": true,
		"latest.json":    true,
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && !skip[e.Name()] {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return fmt.Errorf("no release assets found in %s", *dir)
	}

	tag := "v" + ver
	baseURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/", *repo, tag)
	assets := make(map[string]manifestAsset, len(names))
	var sumsBuf strings.Builder
	for _, name := range names {
		data, err := os.ReadFile(filepath.Join(*dir, name))
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		sumHex := hex.EncodeToString(sum[:])
		sumsBuf.WriteString(sumHex + "  " + name + "\n")
		dl := baseURL + url.PathEscape(name)
		assets[name] = manifestAsset{
			URL:    dl,
			Size:   int64(len(data)),
			SHA256: sumHex,
			GitHub: dl,
		}
	}

	sums := sumsBuf.String()
	msg := []byte("magpie release " + ver + "\n" + sums)
	sig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, sig) {
		return errors.New("ed25519 self-verification failed")
	}
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	if err := os.WriteFile(filepath.Join(*dir, "SHA256SUMS"), []byte(sums), 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*dir, "SHA256SUMS.sig"), []byte(sigB64+"\n"), 0o644); err != nil {
		return err
	}

	rel := releaseManifest{
		Version: ver,
		Notes:   notes,
		URL:     fmt.Sprintf("https://github.com/%s/releases/tag/%s", *repo, tag),
		Assets:  assets,
		Signed: &manifestSigned{
			Sums: sums,
			Sig:  sigB64,
		},
	}
	outJSON, err := json.MarshalIndent(rel, "", "  ")
	if err != nil {
		return err
	}
	outJSON = append(outJSON, '\n')
	return os.WriteFile(filepath.Join(*dir, "latest.json"), outJSON, 0o644)
}
