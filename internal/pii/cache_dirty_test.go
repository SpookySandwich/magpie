package pii

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yetone/magpie/internal/redact"
)

func spanAt(s int) []redact.Found {
	return []redact.Found{{Start: s, End: s + 5, Label: "private_person", Score: float64(float32(0.9))}}
}

func keyOf(i int) [32]byte { return sumOf(fmt.Sprintf("text %d", i)) }

func dirtyCount(b *backend) int {
	b.cache.mu.Lock()
	defer b.cache.mu.Unlock()
	return len(b.cache.dirty)
}

// A save appends the answers new or changed since the file took them,
// oldest first, none for an answer put again as it was, and nothing at
// all when nothing changed.
func TestSaveAppendsOnlyWhatChanged(t *testing.T) {
	p := filepath.Join(t.TempDir(), "found.bin")
	b := newCacheBackend(t, p, 100, nil)
	b.cache.mu.Lock()
	for i := range 10 {
		b.cache.put(keyOf(i), spanAt(i))
	}
	b.cache.mu.Unlock()
	if err := b.flushCache(); err != nil {
		t.Fatal(err)
	}
	if n := dirtyCount(b); n != 0 {
		t.Fatalf("%d entries still dirty after the snapshot", n)
	}
	base := statOpened(t, p).Size()

	b.cache.mu.Lock()
	b.cache.put(keyOf(3), spanAt(3))   // as it was
	b.cache.put(keyOf(4), spanAt(40))  // changed
	b.cache.put(keyOf(20), spanAt(20)) // new
	b.cache.get(keyOf(4))              // used last
	b.cache.mu.Unlock()
	if n := dirtyCount(b); n != 2 {
		t.Fatalf("dirty = %d, want 2 (the changed and the new)", n)
	}
	if err := b.flushCache(); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(raw)) <= base {
		t.Fatalf("file is %d bytes, was %d: nothing appended", len(raw), base)
	}
	es, appended, _, rewrite, err := decodeLog(raw)
	if err != nil || rewrite {
		t.Fatalf("decodeLog: err=%v rewrite=%v", err, rewrite)
	}
	if appended != 2 {
		t.Fatalf("appended %d entries, want 2", appended)
	}
	if len(es) != 11 {
		t.Fatalf("file holds %d entries, want 11", len(es))
	}
	last := es[len(es)-2:]
	if last[0].k != keyOf(20) || last[1].k != keyOf(4) {
		t.Fatalf("appended out of order: want the new one, then the one used last")
	}
	if !sameSpans(last[1].fs, spanAt(40)) {
		t.Fatalf("the changed entry was written with %v", last[1].fs)
	}

	size := statOpened(t, p).Size()
	if err := b.flushCache(); err != nil {
		t.Fatal(err)
	}
	if got := statOpened(t, p).Size(); got != size {
		t.Fatalf("a save with nothing new wrote %d bytes", got-size)
	}
}

// An entry the cache lets go of isn't written.
func TestEvictedEntryIsNotDirty(t *testing.T) {
	c := newLRU(2)
	for i := range 3 {
		c.put(keyOf(i), spanAt(i))
	}
	if len(c.dirty) != 2 {
		t.Fatalf("dirty = %d, want 2", len(c.dirty))
	}
	if _, ok := c.dirty[keyOf(0)]; ok {
		t.Fatal("the evicted entry is still dirty")
	}
	es, _ := c.takeDirty()
	if len(es) != 2 || es[0].k != keyOf(1) || es[1].k != keyOf(2) {
		t.Fatal("takeDirty didn't hand over the cached entries oldest first")
	}
}

// A save that fails keeps its answers for the next one.
func TestFailedSaveKeepsAnswersForTheNext(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-yet")
	p := filepath.Join(dir, "found.bin")
	b := newCacheBackend(t, p, 100, nil)
	b.cache.mu.Lock()
	for i := range 3 {
		b.cache.put(keyOf(i), spanAt(i))
	}
	b.cache.mu.Unlock()
	if err := b.flushCache(); err == nil {
		t.Fatal("a save into a missing folder succeeded")
	}
	if n := dirtyCount(b); n != 3 {
		t.Fatalf("dirty = %d after the failed save, want 3", n)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := b.flushCache(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	es, err := decodeCache(raw)
	if err != nil || len(es) != 3 {
		t.Fatalf("the next save wrote %d entries (err %v), want 3", len(es), err)
	}
}

// An idle cache needs neither a snapshot nor a model directory on exit.
func TestFlushOfUnusedBackendDoesNoIO(t *testing.T) {
	b := &backend{cache: newLRU(10), disk: new(diskState), path: func() string {
		t.Fatal("shutdown looked up an unused model directory")
		return ""
	}}
	b.flushNow()
}

// What saveAfter still holds is written by flushNow, as magpie ending
// does (Flush), and read back by the next start.
func TestFlushWritesWhatSaveAfterHolds(t *testing.T) {
	fastSaves(t, time.Hour)
	p := filepath.Join(t.TempDir(), "found.bin")
	var asked atomic.Int32
	b := newCacheBackend(t, p, 100, &asked)
	texts := []string{"hi Alice", "Bob and Alice"}
	want, err := b.find(context.Background(), texts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p); err == nil {
		t.Fatal("written before saveAfter")
	}
	b.flushNow()
	b.disk.mu.Lock()
	armed := b.disk.timer != nil
	b.disk.mu.Unlock()
	if armed {
		t.Fatal("the save stayed queued after flushNow")
	}
	b.disk.saves.Wait()

	var askedAgain atomic.Int32
	next := newCacheBackend(t, p, 100, &askedAgain)
	got, err := next.find(context.Background(), texts)
	if err != nil {
		t.Fatal(err)
	}
	if askedAgain.Load() != 0 {
		t.Fatal("the next start asked the model again")
	}
	for i := range want {
		if !sameSpans(got[i], want[i]) {
			t.Fatalf("text %d read back as %v, want %v", i, got[i], want[i])
		}
	}
	// nothing waits: flushNow writes nothing more
	size := statOpened(t, p).Size()
	next.flushNow()
	if s := statOpened(t, p).Size(); s != size {
		t.Fatal("flushNow wrote with nothing to write")
	}
}

// BenchmarkSaveOneNewAnswer is a save after one new answer with 20,000
// cached: what each saveAfter costs during steady turns, compaction
// included as it comes.
func BenchmarkSaveOneNewAnswer(b *testing.B) {
	p := filepath.Join(b.TempDir(), "found.bin")
	bk := &backend{cache: newLRU(20000), disk: new(diskState), path: func() string { return p }}
	bk.cache.mu.Lock()
	for i := range 20000 {
		bk.cache.put(sumOf(fmt.Sprint("seed ", i)), spanAt(i%100))
	}
	bk.cache.mu.Unlock()
	if err := bk.flushCache(); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bk.cache.mu.Lock()
		bk.cache.put(sumOf(fmt.Sprint("new ", i)), spanAt(i%100))
		bk.cache.mu.Unlock()
		if err := bk.flushCache(); err != nil {
			b.Fatal(err)
		}
	}
}
