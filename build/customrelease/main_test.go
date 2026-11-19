package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestComAndManifest(t *testing.T) {
	dir := t.TempDir()
	launcher := filepath.Join(dir, "launcher.com")
	if err := os.WriteFile(launcher, []byte("MZ-launcher"), 0o644); err != nil {
		t.Fatal(err)
	}
	dist := filepath.Join(dir, "dist")
	if err := runCom([]string{launcher, "magpie.exe", filepath.Join(dist, "magpie.com")}); err != nil {
		t.Fatal(err)
	}
	comBytes, err := os.ReadFile(filepath.Join(dist, "magpie.com"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasSuffix(comBytes, []byte("\x00magpie.exe\x00magpie-com-target")) {
		t.Fatalf("unexpected magpie.com suffix: %q", comBytes)
	}

	if err := os.WriteFile(filepath.Join(dist, "magpie-windows-amd64.exe"), []byte("MZ-gui"), 0o644); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(dir, "notes.md")
	if err := os.WriteFile(notes, []byte("## Custom build\n- NPU + Eco + Cache\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CUSTOM_UPDATE_SIGNING_KEY", base64.StdEncoding.EncodeToString(priv.Seed()))
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	if err := runManifest([]string{
		"--version", "0.1.8753",
		"--repo", "SpookySandwich/magpie",
		"--pub", pubB64,
		"--notes", notes,
		"--dir", dist,
	}); err != nil {
		t.Fatal(err)
	}

	rawJSON, err := os.ReadFile(filepath.Join(dist, "latest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m releaseManifest
	if err := json.Unmarshal(rawJSON, &m); err != nil {
		t.Fatal(err)
	}
	if m.Version != "0.1.8753" || m.Signed == nil || len(m.Assets) != 2 {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	sig, err := base64.StdEncoding.DecodeString(m.Signed.Sig)
	if err != nil || !ed25519.Verify(pub, []byte("magpie release 0.1.8753\n"+m.Signed.Sums), sig) {
		t.Fatalf("signature verify failed: err=%v", err)
	}
}
