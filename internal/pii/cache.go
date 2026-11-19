package pii

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/yetone/magpie/internal/redact"
)

// What Find learned is kept on disk too, so that a restart doesn't ask the
// model about every history again: after one, each request's whole
// history was a miss, and on a CPU the requests queued for minutes behind
// each other (#3682). The file holds a text's sha256, and where in it the
// model found what, with the label: never the text. It is named for the
// model it came from, so another model's answers are never read as this
// one's, and lives with the model, in magpie's cache (Remove deletes it).
//
// Once a snapshot is on disk, saveSoon appends only the answers added or
// changed since, in checksummed delta frames without a hardware flush:
// rewriting and flushing the whole 20,000-entry file every saveAfter
// wrote megabytes a second and kept the drive awake during active turns.
// Once enough delta records accumulate, saveCache rewrites a compact
// snapshot through a synced temp file and renames it into place.

// cacheMagic starts the file; a file that doesn't start with it (or
// cacheMagic1), or ends part way through its base snapshot, is read as empty.
const cacheMagic = "pfound02"

// cacheMagic1 starts a file written before a span kept its score, and
// only what was over the model's default threshold. Its spans are read
// as sure (score 1), masked at any threshold as they were before; a
// text not in it is asked about with its scores.
const cacheMagic1 = "pfound01"

// deltaMagic starts a frame of new or updated entries appended after a
// cacheMagic snapshot: magic, payload byte length (uint32), IEEE CRC-32
// (uint32), then payload (count and entries, oldest first).
const deltaMagic = "pfound+2"

const (
	// minDeltaBytes is the smallest valid delta frame (header + count +
	// one zero-span entry).
	minDeltaBytes = len(deltaMagic) + 8 + 4 + 34
	// maxDeltaBytes bounds the appended tail by size as well as entry
	// count before saveCache rewrites the file whole.
	maxDeltaBytes = 4 << 20
)

func cachePath() string { return filepath.Join(dir(), "found-"+modelSHA[:12]+".bin") }

// saveAfter is how long after an answer the file is written: one write
// for a burst of requests.
var saveAfter = 2 * time.Second

// compactLimit is how many appended entries may follow a snapshot before
// flushCache rewrites the file whole.
func compactLimit(maxEntries int) int {
	return min(max(maxEntries/2, 4), 4096)
}

// diskState is a backend's cache file: read once, appended saveAfter
// after an answer, and compacted once its tail grows past compactLimit.
type diskState struct {
	mu     sync.Mutex
	loaded string // the file read into cache, once
	timer  *time.Timer
	saving sync.Mutex
	// saves counts a timer's write from when it is set until it is
	// done, so a test's cleanup can wait for one under way.
	saves sync.WaitGroup

	// Guarded by saving: what file holds on disk right now, so flushCache
	// can append only what changed since.
	file          string
	size          int64
	appended      int
	appendedBytes int64
	saved         map[[32]byte][]redact.Found
}

var disk diskState

// loadCache reads the file into cache, the first time Find is asked.
func (bk *backend) loadCache() {
	disk, cache := bk.disk, bk.cache
	p := bk.path()
	disk.mu.Lock()
	if disk.loaded == p {
		disk.mu.Unlock()
		return
	}
	disk.mu.Unlock()

	disk.saving.Lock()
	defer disk.saving.Unlock()
	disk.mu.Lock()
	if disk.loaded == p {
		disk.mu.Unlock()
		return
	}
	disk.loaded = p
	disk.mu.Unlock()

	disk.file, disk.size, disk.appended, disk.appendedBytes, disk.saved = "", 0, 0, 0, nil
	b, err := os.ReadFile(p)
	if err != nil {
		return
	}
	es, appended, appendedBytes, rewrite, err := decodeLog(b)
	if err != nil {
		return // a file cut short or not ours: nothing is kept, the model asked again
	}
	cache.mu.Lock()
	for _, e := range es {
		if _, ok := cache.m[e.k]; !ok {
			cache.put(e.k, e.fs)
		}
	}
	var saved map[[32]byte][]redact.Found
	if !rewrite {
		saved = make(map[[32]byte][]redact.Found, min(len(es), cache.ll.Len()))
		for _, e := range es {
			if el, ok := cache.m[e.k]; ok && sameSpans(el.Value.(*entry).fs, e.fs) {
				saved[e.k] = slices.Clone(e.fs)
			}
		}
	}
	cache.mu.Unlock()
	if !rewrite {
		disk.file = p
		disk.size = int64(len(b))
		disk.appended = appended
		disk.appendedBytes = appendedBytes
		disk.saved = saved
	}
}

// saveSoon writes new answers saveAfter from now, unless a write is due.
func (bk *backend) saveSoon() {
	disk := bk.disk
	disk.mu.Lock()
	defer disk.mu.Unlock()
	if disk.timer == nil {
		disk.saves.Add(1)
		disk.timer = time.AfterFunc(saveAfter, func() {
			defer disk.saves.Done()
			disk.mu.Lock()
			disk.timer = nil
			disk.mu.Unlock()
			bk.flushCache()
		})
	}
}

// flushCache appends what changed since the last write to p, or rewrites
// p whole when no appendable snapshot is on disk yet or the appended tail
// has reached compactLimit.
func (bk *backend) flushCache() error {
	disk, cache := bk.disk, bk.cache
	disk.saving.Lock()
	defer disk.saving.Unlock()

	p := bk.path()
	if disk.file != p {
		return bk.saveCacheLocked(p)
	}

	cache.mu.Lock()
	limit := compactLimit(cache.max)
	cacheLen := cache.ll.Len()
	hadSaved := len(disk.saved)
	for k := range disk.saved {
		if _, ok := cache.m[k]; !ok {
			delete(disk.saved, k)
		}
	}
	var dirty []entry
	for e := cache.ll.Back(); e != nil; e = e.Prev() {
		en := e.Value.(*entry)
		if was, ok := disk.saved[en.k]; !ok || !sameSpans(was, en.fs) {
			dirty = append(dirty, entry{k: en.k, fs: slices.Clone(en.fs)})
		}
	}
	cache.mu.Unlock()

	if len(dirty) == 0 {
		if cacheLen == 0 && hadSaved > 0 {
			return bk.saveCacheLocked(p)
		}
		return nil
	}
	if disk.appended+len(dirty) > limit {
		return bk.saveCacheLocked(p)
	}
	rec := encodeDelta(dirty)
	if disk.appendedBytes+int64(len(rec)) > maxDeltaBytes {
		return bk.saveCacheLocked(p)
	}

	f, err := os.OpenFile(p, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return bk.saveCacheLocked(p)
	}
	fi, err := f.Stat()
	if err != nil || fi.Size() != disk.size {
		f.Close()
		return bk.saveCacheLocked(p)
	}
	n, err := f.Write(rec)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil || n != len(rec) {
		disk.file, disk.size, disk.appended, disk.appendedBytes, disk.saved = "", 0, 0, 0, nil
		return err
	}
	disk.size += int64(len(rec))
	disk.appendedBytes += int64(len(rec))
	disk.appended += len(dirty)
	for _, d := range dirty {
		disk.saved[d.k] = d.fs
	}
	return nil
}

// saveCache writes what cache holds, oldest first, to a file beside the
// old one and renames it over it: a reader never sees half of it.
func saveCache() error { return pf.saveCache() }

func (bk *backend) saveCache() error {
	bk.disk.saving.Lock()
	defer bk.disk.saving.Unlock()
	return bk.saveCacheLocked(bk.path())
}

func (bk *backend) saveCacheLocked(p string) error {
	disk, cache := bk.disk, bk.cache
	disk.mu.Lock()
	if disk.timer != nil && disk.timer.Stop() {
		disk.timer = nil
		disk.saves.Done()
	}
	disk.mu.Unlock()

	cache.mu.Lock()
	b := encodeCache(cache)
	saved := make(map[[32]byte][]redact.Found, cache.ll.Len())
	for e := cache.ll.Back(); e != nil; e = e.Prev() {
		en := e.Value.(*entry)
		saved[en.k] = slices.Clone(en.fs)
	}
	cache.mu.Unlock()

	f, err := os.CreateTemp(filepath.Dir(p), "found-*.tmp")
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(f.Name(), p)
	}
	if err != nil {
		os.Remove(f.Name())
		return err
	}
	disk.file = p
	disk.size = int64(len(b))
	disk.appended = 0
	disk.appendedBytes = 0
	disk.saved = saved
	return nil
}

// sameSpans reports whether a and b write the same bytes on disk.
func sameSpans(a, b []redact.Found) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		la, lb := a[i].Label, b[i].Label
		if len(la) > 255 {
			la = la[:255]
		}
		if len(lb) > 255 {
			lb = lb[:255]
		}
		if a[i].Start != b[i].Start || a[i].End != b[i].End || float32(a[i].Score) != float32(b[i].Score) || la != lb {
			return false
		}
	}
	return true
}

// encodeCache is c, oldest first: the magic, a count, then each entry's
// hash, its spans' count and each span's start, end, score (a float32)
// and label.
func encodeCache(c *lru) []byte {
	var b bytes.Buffer
	b.WriteString(cacheMagic)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(c.ll.Len()))
	b.Write(n[:])
	for e := c.ll.Back(); e != nil; e = e.Prev() {
		writeEntry(&b, e.Value.(*entry))
	}
	return b.Bytes()
}

func encodeDelta(es []entry) []byte {
	var body bytes.Buffer
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(len(es)))
	body.Write(n[:])
	for i := range es {
		writeEntry(&body, &es[i])
	}
	payload := body.Bytes()
	var out bytes.Buffer
	out.Grow(len(deltaMagic) + 8 + len(payload))
	out.WriteString(deltaMagic)
	var hdr [8]byte
	binary.LittleEndian.PutUint32(hdr[0:4], uint32(len(payload)))
	binary.LittleEndian.PutUint32(hdr[4:8], crc32.ChecksumIEEE(payload))
	out.Write(hdr[:])
	out.Write(payload)
	return out.Bytes()
}

func writeEntry(b *bytes.Buffer, en *entry) {
	b.Write(en.k[:])
	var u2 [2]byte
	binary.LittleEndian.PutUint16(u2[:], uint16(len(en.fs)))
	b.Write(u2[:])
	var sbuf [13]byte
	for _, f := range en.fs {
		label := f.Label
		if len(label) > 255 {
			label = label[:255]
		}
		binary.LittleEndian.PutUint32(sbuf[0:4], uint32(f.Start))
		binary.LittleEndian.PutUint32(sbuf[4:8], uint32(f.End))
		binary.LittleEndian.PutUint32(sbuf[8:12], math.Float32bits(float32(f.Score)))
		sbuf[12] = byte(len(label))
		b.Write(sbuf[:])
		b.WriteString(label)
	}
}

var errBadCache = errors.New("not a cache file")

func decodeCache(b []byte) ([]entry, error) {
	es, _, _, _, err := decodeLog(b)
	return es, err
}

// decodeLog reads the base snapshot and any delta frames appended after
// it. A delta frame cut off or damaged at the very end of the file keeps
// the answers before it and sets rewrite so the next flush compacts over
// the torn tail.
func decodeLog(b []byte) (out []entry, appended int, appendedBytes int64, rewrite bool, err error) {
	scored := bytes.HasPrefix(b, []byte(cacheMagic))
	if !scored && !bytes.HasPrefix(b, []byte(cacheMagic1)) {
		return nil, 0, 0, false, errBadCache
	}
	r := bytes.NewReader(b[len(cacheMagic):])
	out, err = readEntries(r, len(b)-len(cacheMagic), scored)
	if err != nil {
		return nil, 0, 0, false, err
	}
	rem := b[len(b)-r.Len():]
	if len(rem) == 0 {
		return out, 0, 0, !scored, nil
	}
	if !scored {
		return nil, 0, 0, false, errBadCache
	}

	deltas := 0
	for len(rem) > 0 {
		if len(rem) < len(deltaMagic) {
			if bytes.HasPrefix([]byte(deltaMagic), rem) || (deltas > 0 && allZero(rem)) {
				rewrite = true
				break
			}
			return nil, 0, 0, false, errBadCache
		}
		if string(rem[:len(deltaMagic)]) != deltaMagic {
			if (deltas > 0 || len(rem) >= minDeltaBytes) && allZero(rem) {
				rewrite = true
				break
			}
			return nil, 0, 0, false, errBadCache
		}
		if len(rem) < len(deltaMagic)+8 {
			rewrite = true
			break
		}
		size := binary.LittleEndian.Uint32(rem[len(deltaMagic) : len(deltaMagic)+4])
		sum := binary.LittleEndian.Uint32(rem[len(deltaMagic)+4 : len(deltaMagic)+8])
		body := rem[len(deltaMagic)+8:]
		if size == 0 {
			if len(body) == 0 {
				rewrite = true
				break
			}
			return nil, 0, 0, false, errBadCache
		}
		if uint64(size) > uint64(len(body)) {
			rewrite = true
			break
		}
		payload := body[:size]
		rem = body[size:]
		if crc32.ChecksumIEEE(payload) != sum {
			if len(rem) == 0 {
				rewrite = true
				break
			}
			return nil, 0, 0, false, errBadCache
		}
		pr := bytes.NewReader(payload)
		es, err := readEntries(pr, len(payload), true)
		if err != nil || pr.Len() != 0 {
			if len(rem) == 0 {
				rewrite = true
				break
			}
			return nil, 0, 0, false, errBadCache
		}
		out = append(out, es...)
		appended += len(es)
		appendedBytes += int64(len(deltaMagic) + 8 + len(payload))
		deltas++
	}

	if deltas > 0 {
		seen := make(map[[32]byte]struct{}, len(out))
		dedup := make([]entry, 0, len(out))
		for i := len(out) - 1; i >= 0; i-- {
			if _, ok := seen[out[i].k]; ok {
				continue
			}
			seen[out[i].k] = struct{}{}
			dedup = append(dedup, out[i])
		}
		slices.Reverse(dedup)
		out = dedup
	}
	return out, appended, appendedBytes, rewrite, nil
}

func readEntries(r *bytes.Reader, maxBytes int, scored bool) ([]entry, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if uint64(n) > uint64(maxBytes/34) { // each entry is 34 bytes at least
		return nil, errBadCache
	}
	out := make([]entry, 0, n)
	var eh [34]byte
	var sh [12]byte
	for i := uint32(0); i < n; i++ {
		if _, err := io.ReadFull(r, eh[:]); err != nil {
			return nil, err
		}
		var e entry
		copy(e.k[:], eh[:32])
		spans := binary.LittleEndian.Uint16(eh[32:34])
		for j := uint16(0); j < spans; j++ {
			need := 8
			if scored {
				need = 12
			}
			if _, err := io.ReadFull(r, sh[:need]); err != nil {
				return nil, err
			}
			start := binary.LittleEndian.Uint32(sh[0:4])
			end := binary.LittleEndian.Uint32(sh[4:8])
			score := float32(1)
			if scored {
				score = math.Float32frombits(binary.LittleEndian.Uint32(sh[8:12]))
				if !(score >= 0 && score <= 1) {
					return nil, errBadCache
				}
			}
			l, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			label := make([]byte, l)
			if _, err := io.ReadFull(r, label); err != nil {
				return nil, err
			}
			if start >= end {
				return nil, errBadCache
			}
			e.fs = append(e.fs, redact.Found{Start: int(start), End: int(end), Label: string(label), Score: float64(score)})
		}
		out = append(out, e)
	}
	return out, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return len(b) > 0
}
