package pii

import (
	"fmt"
	"reflect"
	"testing"
)

func claimHistory(n int) []string {
	units := make([]string, n)
	for i := range units {
		units[i] = fmt.Sprintf("synthetic history segment %08d", i)
	}
	return units
}

func BenchmarkClaimLongHistory(b *testing.B) {
	units := claimHistory(7000)
	var reading readingSet
	b.ReportAllocs()
	for b.Loop() {
		_, _, _, release := reading.claim(units, guardChunk)
		release()
	}
}

func TestClaimOnlyBuildsTheDispatchedChunk(t *testing.T) {
	units := claimHistory(7000)
	var reading readingSet
	chunks, parts, _, release := reading.claim(units, guardChunk)
	defer release()
	if len(chunks) != 1 || len(parts) != 1 {
		t.Fatalf("built %d chunks for one dispatch", len(chunks))
	}
	want, offsets := joinAt(units, guardChunk)
	if chunks[0] != want[0] || !reflect.DeepEqual(parts[0], offsets[0]) {
		t.Fatal("first chunk or offsets changed")
	}
}
