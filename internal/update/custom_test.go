package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestCustomDefaultFeedAndSigningKey(t *testing.T) {
	t.Setenv("MAGPIE_UPDATE_FEED", "")
	const wantFeed = "https://github.com/SpookySandwich/magpie/releases/latest/download/latest.json"
	if got := Feed(); got != wantFeed {
		t.Fatalf("Feed() = %q, want %q", got, wantFeed)
	}
	pub, err := base64.StdEncoding.DecodeString(signingKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("invalid signingKey: len=%d err=%v", len(pub), err)
	}
}

func TestCustomForkReleaseNotRejectedByAttest(t *testing.T) {
	asks := attestServer(t, 404, []byte(`{"message":"Not Found"}`))
	body := []byte("custom-magpie-windows-amd64")
	sum := sha256.Sum256(body)
	sumHex := hex.EncodeToString(sum[:])

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldKey := signingKey
	signingKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { signingKey = oldKey })

	var fileSrv *httptest.Server
	fileSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/SpookySandwich/magpie/releases/download/v0.1.8753/magpie-windows-amd64.exe" {
			w.Write(body)
			return
		}
		if r.URL.Path == "/latest.json" {
			sums := sumHex + "  magpie-windows-amd64.exe\n"
			sig := ed25519.Sign(priv, []byte("magpie release 0.1.8753\n"+sums))
			dlURL := fileSrv.URL + "/SpookySandwich/magpie/releases/download/v0.1.8753/magpie-windows-amd64.exe"
			json.NewEncoder(w).Encode(Release{
				Version: "0.1.8753",
				Notes:   "custom fork build",
				URL:     "https://github.com/SpookySandwich/magpie/releases/tag/v0.1.8753",
				Assets: map[string]Asset{
					"magpie-windows-amd64.exe": {
						URL:    dlURL,
						Size:   int64(len(body)),
						SHA256: sumHex,
						GitHub: "https://github.com/SpookySandwich/magpie/releases/download/v0.1.8753/magpie-windows-amd64.exe",
					},
				},
				Signed: &Signed{
					Sums: sums,
					Sig:  base64.StdEncoding.EncodeToString(sig),
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer fileSrv.Close()

	oldFeed := siteFeed
	siteFeed = fileSrv.URL + "/latest.json"
	t.Cleanup(func() { siteFeed = oldFeed })
	t.Setenv("MAGPIE_UPDATE_FEED", "")

	rel, err := Latest(context.Background())
	if err != nil {
		t.Fatalf("Latest failed: %v", err)
	}
	a, ok := rel.Assets["magpie-windows-amd64.exe"]
	if !ok {
		t.Fatalf("missing magpie-windows-amd64.exe in %+v", rel.Assets)
	}
	if a.attest {
		t.Fatal("custom fork asset should not require upstream attestation")
	}
	dst := filepath.Join(t.TempDir(), "magpie-windows-amd64.exe")
	if err := download(context.Background(), a, dst); err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if got, err := os.ReadFile(dst); err != nil || string(got) != string(body) {
		t.Fatalf("downloaded bytes mismatch: err=%v", err)
	}
	if n := atomic.LoadInt32(asks); n != 0 {
		t.Fatalf("attestation API asked %d times for custom fork asset", n)
	}

	// Non-custom asset at the same version still requires attestation and is refused on 404.
	upstreamRel := signedRelease(t, "0.1.8753", map[string]string{"magpie-windows-amd64.exe": string(body)})
	if err := upstreamRel.verify(); err != nil {
		t.Fatal(err)
	}
	if !upstreamRel.Assets["magpie-windows-amd64.exe"].attest {
		t.Fatal("non-custom asset should still set attest=true")
	}
	if err := attestedFile(context.Background(), upstreamRel.Assets["magpie-windows-amd64.exe"], "magpie-windows-amd64.exe"); !errors.Is(err, errUnattested) {
		t.Fatalf("expected errUnattested for non-custom asset on 404, got %v", err)
	}
}
