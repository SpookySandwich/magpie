package pii

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/redact"
)

func newCacheBackend(t *testing.T, path string, cap int, asked *atomic.Int32) *backend {
	t.Helper()
	b := &backend{
		turn:     make(chan struct{}, 1),
		waiting:  new(atomic.Int32),
		cache:    newLRU(cap),
		disk:     new(diskState),
		path:     func() string { return path },
		heldBack: func() error { return nil },
		classify: func(texts []string) ([][]redact.Found, error) {
			if asked != nil {
				asked.Add(1)
			}
			out := make([][]redact.Found, len(texts))
			for i, s := range texts {
				for at := 0; ; {
					j := strings.Index(s[at:], "Alice")
					if j < 0 {
						break
					}
					out[i] = append(out[i], redact.Found{
						Start: at + j,
						End:   at + j + len("Alice"),
						Label: "private_person",
						Score: float64(float32(0.85)),
					})
					at += j + len("Alice")
				}
			}
			return out, nil
		},
	}
	t.Cleanup(func() {
		stopTestSaves(b)
	})
	return b
}

// stopTestSaves releases the test backend before its model directory goes away.
func stopTestSaves(b *backend) {
	d := b.disk
	d.mu.Lock()
	if d.timer != nil && d.timer.Stop() {
		d.saves.Done()
	}
	d.timer = nil
	d.loaded = ""
	d.mu.Unlock()
	d.saves.Wait()
	pendingCaches.Delete(b)
}

func waitSaved(t *testing.T, b *backend) {
	t.Helper()
	waitFor(t, "the queued cache save to start", func() bool {
		b.disk.mu.Lock()
		defer b.disk.mu.Unlock()
		return b.disk.timer == nil
	})
	b.disk.saves.Wait()
}

func statOpened(t *testing.T, path string) os.FileInfo {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	return fi
}

func fastSaves(t *testing.T, d time.Duration) {
	t.Helper()
	was := saveAfter
	saveAfter = d
	t.Cleanup(func() { saveAfter = was })
}

// Steady turns with a populated cache append only the new answers to the
// existing file rather than rewriting and syncing the whole snapshot on
// every saveAfter tick, and a restart reads back both snapshot and deltas.
func TestIncrementalSavesAppendWithoutRewritingWholeCache(t *testing.T) {
	fastSaves(t, 5*time.Millisecond)
	p := filepath.Join(t.TempDir(), "found.bin")

	var asked atomic.Int32
	b := newCacheBackend(t, p, 2000, &asked)

	seeds := make([]string, 1000)
	for i := range seeds {
		seeds[i] = fmt.Sprintf("seed %04d hi Alice", i)
	}
	wantSeeds, err := b.find(context.Background(), seeds)
	if err != nil {
		t.Fatal(err)
	}
	waitSaved(t, b)

	baseInfo := statOpened(t, p)
	baseSize := baseInfo.Size()
	prevSize := baseSize

	const turns = 25
	added := make([]string, turns)
	wantAdded := make([][]redact.Found, turns)
	for i := range turns {
		added[i] = fmt.Sprintf("turn %02d hi Alice", i)
		got, err := b.find(context.Background(), []string{added[i]})
		if err != nil {
			t.Fatal(err)
		}
		wantAdded[i] = got[0]
		waitSaved(t, b)

		fi := statOpened(t, p)
		if !os.SameFile(baseInfo, fi) {
			t.Fatalf("turn %d replaced the whole cache file instead of appending to it", i)
		}
		if fi.Size() <= prevSize {
			t.Fatalf("turn %d did not grow the cache file: %d -> %d", i, prevSize, fi.Size())
		}
		prevSize = fi.Size()
	}

	deltaBytes := prevSize - baseSize
	if deltaBytes >= baseSize/5 {
		t.Fatalf("25 single-entry turns grew the file by %d bytes (base %d), want compact delta frames", deltaBytes, baseSize)
	}

	var reloadAsked atomic.Int32
	reloaded := newCacheBackend(t, p, 2000, &reloadAsked)
	all := append(slices.Clone(seeds), added...)
	gotAll, err := reloaded.find(context.Background(), all)
	if err != nil {
		t.Fatal(err)
	}
	if n := reloadAsked.Load(); n != 0 {
		t.Fatalf("reloaded cache asked the model %d times, want 0", n)
	}
	wantAll := append(slices.Clone(wantSeeds), wantAdded...)
	if !reflect.DeepEqual(gotAll, wantAll) {
		t.Fatalf("reloaded answers differed from what was saved")
	}
}

// Once enough delta entries follow the base snapshot, flushCache compacts
// the file through a fresh snapshot so evicted entries and old frames do
// not grow the file without bound.
func TestCacheLogCompactsOnceTailGrows(t *testing.T) {
	fastSaves(t, 5*time.Millisecond)
	p := filepath.Join(t.TempDir(), "found.bin")

	const capEntries = 16
	b := newCacheBackend(t, p, capEntries, nil)

	const totalTurns = 40
	texts := make([]string, totalTurns)
	var firstInfo os.FileInfo
	appended, compacted := false, false
	for i := range totalTurns {
		texts[i] = fmt.Sprintf("item %02d hi Alice", i)
		if _, err := b.find(context.Background(), []string{texts[i]}); err != nil {
			t.Fatal(err)
		}
		waitSaved(t, b)
		fi := statOpened(t, p)
		if i == 0 {
			firstInfo = fi
		} else if os.SameFile(firstInfo, fi) {
			appended = true
		} else {
			compacted = true
		}
	}
	if !appended {
		t.Fatal("early turns replaced the cache file instead of appending")
	}
	if !compacted {
		t.Fatal("cache log never compacted as entries turned over")
	}
	if sz := statOpened(t, p).Size(); sz > 4096 {
		t.Fatalf("compacted cache for %d entries is %d bytes, want bounded size", capEntries, sz)
	}

	var asked atomic.Int32
	reloaded := newCacheBackend(t, p, capEntries, &asked)
	recent := texts[totalTurns-capEntries:]
	if _, err := reloaded.find(context.Background(), recent); err != nil {
		t.Fatal(err)
	}
	if n := asked.Load(); n != 0 {
		t.Fatalf("recent entries after compaction asked the model %d times, want 0", n)
	}
	if _, err := reloaded.find(context.Background(), texts[:1]); err != nil {
		t.Fatal(err)
	}
	if n := asked.Load(); n != 1 {
		t.Fatalf("evicted entry asked the model %d times, want 1", n)
	}
}

// When an entry already in the base snapshot gets new spans appended in a
// delta frame, reloading keeps the newer spans rather than the stale base
// entry.
func TestAppendedUpdateOverridesSnapshotEntryOnReload(t *testing.T) {
	fastSaves(t, 5*time.Millisecond)
	p := filepath.Join(t.TempDir(), "found.bin")

	var asked atomic.Int32
	b := newCacheBackend(t, p, 100, &asked)

	// Seed an out-of-bounds span in the base snapshot so Find re-asks and
	// updates the same key via an appended delta frame.
	b.cache.mu.Lock()
	b.cache.put(sumOf("hi Alice"), []redact.Found{{Start: 3, End: 80, Label: "private_person", Score: 0.9}})
	b.cache.mu.Unlock()
	b.disk.mu.Lock()
	b.disk.loaded = p
	b.disk.mu.Unlock()
	if err := b.saveCache(); err != nil {
		t.Fatal(err)
	}
	baseInfo := statOpened(t, p)

	got, err := b.find(context.Background(), []string{"hi Alice"})
	if err != nil {
		t.Fatal(err)
	}
	if asked.Load() != 1 || len(got[0]) != 1 || got[0][0].End != 8 {
		t.Fatalf("updated Find = %v (asked %d), want End=8 once", got, asked.Load())
	}
	waitSaved(t, b)
	if after := statOpened(t, p); !os.SameFile(baseInfo, after) {
		t.Fatal("single updated entry replaced the whole file instead of appending a delta")
	}

	var reloadAsked atomic.Int32
	reloaded := newCacheBackend(t, p, 100, &reloadAsked)
	got2, err := reloaded.find(context.Background(), []string{"hi Alice"})
	if err != nil || !reflect.DeepEqual(got2, got) {
		t.Fatalf("reloaded Find = %v, %v; want %v", got2, err, got)
	}
	if n := reloadAsked.Load(); n != 0 {
		t.Fatalf("reloaded backend asked the model %d times, want 0 (stale base span was kept)", n)
	}
}

// A crash that cuts off or damages the last appended delta frame leaves
// the snapshot and earlier delta frames usable, and the next write
// compacts over the torn tail so later answers are not stranded behind it.
func TestTornAppendedTailKeepsEarlierAnswersAndRewritesCleanly(t *testing.T) {
	fastSaves(t, 5*time.Millisecond)
	p := filepath.Join(t.TempDir(), "found.bin")

	b := newCacheBackend(t, p, 100, nil)
	if _, err := b.find(context.Background(), []string{"first Alice"}); err != nil {
		t.Fatal(err)
	}
	waitSaved(t, b)
	if _, err := b.find(context.Background(), []string{"second Alice"}); err != nil {
		t.Fatal(err)
	}
	waitSaved(t, b)

	intact, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	damagedCRC := slices.Clone(intact)
	damagedCRC[len(damagedCRC)-1] ^= 0xff

	cases := []struct {
		name      string
		raw       []byte
		keptTexts []string
		lostText  string
	}{
		{
			name:      "cut mid-magic",
			raw:       append(slices.Clone(intact), "pfou"...),
			keptTexts: []string{"first Alice", "second Alice"},
		},
		{
			name:      "cut mid-payload",
			raw:       intact[:len(intact)-3],
			keptTexts: []string{"first Alice"},
			lostText:  "second Alice",
		},
		{
			name:      "damaged tail checksum",
			raw:       damagedCRC,
			keptTexts: []string{"first Alice"},
			lostText:  "second Alice",
		},
		{
			name:      "zero-extended tail",
			raw:       append(slices.Clone(intact), make([]byte, 64)...),
			keptTexts: []string{"first Alice", "second Alice"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cp := filepath.Join(t.TempDir(), "found.bin")
			if err := os.WriteFile(cp, tc.raw, 0o644); err != nil {
				t.Fatal(err)
			}

			var asked atomic.Int32
			r1 := newCacheBackend(t, cp, 100, &asked)
			if _, err := r1.find(context.Background(), tc.keptTexts); err != nil {
				t.Fatal(err)
			}
			if n := asked.Load(); n != 0 {
				t.Fatalf("surviving prefix asked the model %d times, want 0", n)
			}
			if tc.lostText != "" {
				got, err := r1.find(context.Background(), []string{tc.lostText})
				if err != nil {
					t.Fatal(err)
				}
				if asked.Load() != 1 || len(got[0]) != 1 || got[0][0].Label != "private_person" {
					t.Fatalf("damaged tail text = %v (asked %d), want re-asked private_person", got, asked.Load())
				}
				waitSaved(t, r1)
			}

			// Next write heals the torn tail by rewriting a clean snapshot.
			if _, err := r1.find(context.Background(), []string{"third Alice"}); err != nil {
				t.Fatal(err)
			}
			waitSaved(t, r1)

			var askedAfterHeal atomic.Int32
			r2 := newCacheBackend(t, cp, 100, &askedAfterHeal)
			check := append(slices.Clone(tc.keptTexts), "third Alice")
			if _, err := r2.find(context.Background(), check); err != nil {
				t.Fatal(err)
			}
			if n := askedAfterHeal.Load(); n != 0 {
				t.Fatalf("after healing torn tail, model was asked %d times, want 0", n)
			}
		})
	}
}

func TestConcurrentFindsAndIncrementalSaves(t *testing.T) {
	fastSaves(t, 2*time.Millisecond)
	p := filepath.Join(t.TempDir(), "found.bin")
	b := newCacheBackend(t, p, 32, nil)

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 15 {
				txt := fmt.Sprintf("worker %d turn %d hi Alice", id%4, i)
				if _, err := b.find(context.Background(), []string{txt}); err != nil {
					t.Errorf("find(%q): %v", txt, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	waitSaved(t, b)

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeCache(raw); err != nil {
		t.Fatalf("concurrently written cache failed decodeCache: %v", err)
	}
}
