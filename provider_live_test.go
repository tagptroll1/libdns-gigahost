package gigahost

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// TestLive runs the DNS-01 cycle certmagic does against the real Gigahost
// API: set a TXT, see it listed, delete it. It proves a key has the
// permissions Caddy needs. Skipped unless both variables are set:
//
//	GIGAHOST_API_KEY=flux_live_... GIGAHOST_TEST_ZONE=ybmn.no go test -run TestLive -v
func TestLive(t *testing.T) {
	key, zone := os.Getenv("GIGAHOST_API_KEY"), os.Getenv("GIGAHOST_TEST_ZONE")
	if key == "" || zone == "" {
		t.Skip("GIGAHOST_API_KEY and GIGAHOST_TEST_ZONE not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	p := &Provider{APIKey: key}
	name := "_libdns-gigahost-test"
	value := "libdns-gigahost " + time.Now().UTC().Format(time.RFC3339)
	rec := libdns.TXT{Name: name, Text: value, TTL: 120 * time.Second}

	if _, err := p.SetRecords(ctx, zone+".", []libdns.Record{rec}); err != nil {
		t.Fatalf("set: %v", err)
	}
	t.Cleanup(func() {
		if _, err := p.DeleteRecords(context.Background(), zone+".", []libdns.Record{rec}); err != nil {
			t.Errorf("cleanup delete: %v", err)
		}
	})

	recs, err := p.GetRecords(ctx, zone+".")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	found := false
	for _, r := range recs {
		if rr := r.RR(); rr.Name == name && rr.Type == "TXT" && rr.Data == value {
			found = true
		}
	}
	if !found {
		t.Fatalf("created TXT %s not listed", name)
	}

	deleted, err := p.DeleteRecords(ctx, zone+".", []libdns.Record{rec})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if len(deleted) != 1 {
		t.Fatalf("delete matched %d records, want 1", len(deleted))
	}
}
