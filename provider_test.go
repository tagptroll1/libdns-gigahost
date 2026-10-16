package gigahost

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/libdns/libdns"
)

// --- pickZoneForName --------------------------------------------------------

func TestPickZoneForName(t *testing.T) {
	zones := []dnsZone{
		{ID: "1", Name: "ybmn.no"},
		{ID: "2", Name: "yesbutmaybe.no"},
		{ID: "3", Name: "deep.ybmn.no"}, // contrived sub-zone hosted separately
	}

	cases := []struct {
		name     string
		input    string
		wantName string // empty = expect no match
	}{
		{"exact apex match", "ybmn.no", "ybmn.no"},
		{"single subdomain", "mova.ybmn.no", "ybmn.no"},
		{"deep ACME challenge", "_acme-challenge.mova.ybmn.no", "ybmn.no"},
		{"trailing dot", "mova.ybmn.no.", "ybmn.no"},
		{"uppercase input", "Mova.YBMN.No", "ybmn.no"},
		{"longest-suffix wins", "_acme-challenge.deep.ybmn.no", "deep.ybmn.no"},
		{"other owned zone", "relay.yesbutmaybe.no", "yesbutmaybe.no"},
		{"unrelated domain", "example.com", ""},
		{"bare TLD must not match", "no", ""},
		{"trailing-dot TLD must not match", "no.", ""},
		{"substring is not suffix", "notybmn.no", ""},
		{"empty input", "", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			z, zn := pickZoneForName(zones, tc.input)
			if tc.wantName == "" {
				if z != nil {
					t.Fatalf("expected no match for %q, got %q", tc.input, z.Name)
				}
				if zn != "" {
					t.Fatalf("expected empty zone name for %q, got %q", tc.input, zn)
				}
				return
			}
			if z == nil {
				t.Fatalf("expected match %q for %q, got nil", tc.wantName, tc.input)
			}
			if z.Name != tc.wantName || zn != tc.wantName {
				t.Fatalf("for %q: want %q, got %q / %q", tc.input, tc.wantName, z.Name, zn)
			}
		})
	}
}

// --- fake Gigahost API ------------------------------------------------------

const testKey = "flux_live_test"

// fakeAPI mimics the parts of the Gigahost API we use: GET /dns/zones,
// GET/POST /dns/zones/{id}/records and DELETE /dns/zones/{id}/records/{rid}.
// Response shapes follow lego's recorded fixtures for its gigahostno
// provider: everything wrapped in {"meta": ..., "data": ...}, IDs as strings.
type fakeAPI struct {
	t       *testing.T
	mu      sync.Mutex
	zones   []map[string]any
	records map[string][]dnsRecord // by zone ID
	nextID  int
	created []dnsRecord
	deleted []string // "zoneID/recordID?name=..&type=.."
}

func newFakeAPI(t *testing.T, records map[string][]dnsRecord) *fakeAPI {
	api := &fakeAPI{
		t: t,
		zones: []map[string]any{
			{"zone_id": "1", "zone_name": "ybmn.no", "zone_active": "1"},
			// Numeric ID on purpose: the client must accept either form.
			{"zone_id": 2, "zone_name": "yesbutmaybe.no", "zone_active": "1"},
			{"zone_id": "3", "zone_name": "inactive.no", "zone_active": "0"},
		},
		records: records,
		nextID:  1000,
	}
	if api.records == nil {
		api.records = map[string][]dnsRecord{}
	}
	srv := httptest.NewServer(http.HandlerFunc(api.handle))
	t.Cleanup(srv.Close)
	old := baseURLVar
	baseURLVar = srv.URL + "/api/v0"
	t.Cleanup(func() { baseURLVar = old })
	return api
}

func writeEnvelope(w http.ResponseWriter, status int, msg string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"meta": map[string]any{"status": status, "status_message": http.StatusText(status), "message": msg},
		"data": data,
	})
}

func (a *fakeAPI) handle(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if r.Header.Get("Authorization") != "Bearer "+testKey {
		writeEnvelope(w, http.StatusUnauthorized, "401 Unauthorized", []any{})
		return
	}
	path := strings.TrimPrefix(r.URL.Path, "/api/v0")
	parts := strings.Split(strings.Trim(path, "/"), "/")

	switch {
	case r.Method == http.MethodGet && path == "/dns/zones":
		writeEnvelope(w, http.StatusOK, "200 OK", a.zones)

	case len(parts) == 4 && parts[0] == "dns" && parts[1] == "zones" && parts[3] == "records":
		zid := parts[2]
		switch r.Method {
		case http.MethodGet:
			recs := a.records[zid]
			if recs == nil {
				recs = []dnsRecord{}
			}
			writeEnvelope(w, http.StatusOK, "200 OK", recs)
		case http.MethodPost:
			var rec dnsRecord
			if err := json.NewDecoder(r.Body).Decode(&rec); err != nil {
				a.t.Errorf("bad create body: %v", err)
				writeEnvelope(w, http.StatusBadRequest, "bad body", nil)
				return
			}
			a.created = append(a.created, rec)
			a.nextID++
			rec.ID = flexString(fmt.Sprint(a.nextID))
			a.records[zid] = append(a.records[zid], rec)
			writeEnvelope(w, http.StatusCreated, "Record created successfully.", nil)
		default:
			writeEnvelope(w, http.StatusMethodNotAllowed, "method", nil)
		}

	case len(parts) == 5 && parts[0] == "dns" && parts[1] == "zones" && parts[3] == "records" && r.Method == http.MethodDelete:
		zid, rid := parts[2], parts[4]
		q := r.URL.Query()
		a.deleted = append(a.deleted, fmt.Sprintf("%s/%s?name=%s&type=%s", zid, rid, q.Get("name"), q.Get("type")))
		kept := a.records[zid][:0]
		for _, rec := range a.records[zid] {
			if string(rec.ID) != rid {
				kept = append(kept, rec)
			}
		}
		a.records[zid] = kept
		writeEnvelope(w, http.StatusOK, "Record deleted successfully.", nil)

	default:
		a.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		writeEnvelope(w, http.StatusNotFound, "not found", nil)
	}
}

func txt(name, value string) libdns.Record {
	return libdns.TXT{Name: name, Text: value}
}

// --- AppendRecords ----------------------------------------------------------

func TestAppendRecords_CertmagicShape(t *testing.T) {
	api := newFakeAPI(t, nil)
	p := &Provider{APIKey: testKey}

	in := []libdns.Record{txt("_acme-challenge.mova", "token-1")}
	out, err := p.AppendRecords(context.Background(), "ybmn.no.", in)
	if err != nil {
		t.Fatal(err)
	}
	if len(api.created) != 1 {
		t.Fatalf("want 1 create, got %d", len(api.created))
	}
	got := api.created[0]
	want := dnsRecord{Name: "_acme-challenge.mova", Type: "TXT", Value: "token-1", TTL: defaultTTL}
	if got != want {
		t.Fatalf("create body: want %+v, got %+v", want, got)
	}
	// Returned names must stay relative to the caller's zone, or certmagic
	// double-appends the zone in its propagation check.
	if len(out) != 1 || out[0].RR().Name != "_acme-challenge.mova" {
		t.Fatalf("returned records: %+v", out)
	}
}

func TestAppendRecords_MisleadingZone(t *testing.T) {
	api := newFakeAPI(t, nil)
	p := &Provider{APIKey: testKey}

	// certmagic settled on "no." and passed the name relative to it.
	_, err := p.AppendRecords(context.Background(), "no.", []libdns.Record{txt("_acme-challenge.mova.ybmn", "v")})
	if err != nil {
		t.Fatal(err)
	}
	if len(api.created) != 1 || api.created[0].Name != "_acme-challenge.mova" {
		t.Fatalf("created: %+v", api.created)
	}
}

func TestAppendRecords_NumericZoneIDAndTTL(t *testing.T) {
	api := newFakeAPI(t, nil)
	p := &Provider{APIKey: testKey}

	rec := libdns.TXT{Name: "_acme-challenge.relay", Text: "v", TTL: 300 * time.Second}
	if _, err := p.AppendRecords(context.Background(), "yesbutmaybe.no.", []libdns.Record{rec}); err != nil {
		t.Fatal(err)
	}
	if len(api.records["2"]) != 1 || api.records["2"][0].TTL != 300 {
		t.Fatalf("zone 2 records: %+v", api.records["2"])
	}
}

func TestAppendRecords_InactiveAndUnknownZones(t *testing.T) {
	newFakeAPI(t, nil)
	p := &Provider{APIKey: testKey}

	for _, zone := range []string{"inactive.no.", "example.com."} {
		if _, err := p.AppendRecords(context.Background(), zone, []libdns.Record{txt("_acme-challenge", "v")}); err == nil {
			t.Fatalf("zone %s: expected error", zone)
		}
	}
}

func TestAppendRecords_AuthErrorSurfacesMessage(t *testing.T) {
	newFakeAPI(t, nil)
	p := &Provider{APIKey: "wrong"}

	_, err := p.AppendRecords(context.Background(), "ybmn.no.", []libdns.Record{txt("_acme-challenge", "v")})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("want 401 error, got %v", err)
	}
}

// --- SetRecords -------------------------------------------------------------

func TestSetRecords_ReplacesStaleRRset(t *testing.T) {
	api := newFakeAPI(t, map[string][]dnsRecord{
		"1": {
			{ID: "10", Name: "_acme-challenge.mova", Type: "TXT", Value: "stale", TTL: 120},
			{ID: "11", Name: "_acme-challenge.mova", Type: "TXT", Value: "stale2", TTL: 120},
			{ID: "12", Name: "_acme-challenge.git", Type: "TXT", Value: "other", TTL: 120},
			{ID: "13", Name: "mova", Type: "A", Value: "10.0.20.5", TTL: 3600},
		},
	})
	p := &Provider{APIKey: testKey}

	out, err := p.SetRecords(context.Background(), "ybmn.no.", []libdns.Record{txt("_acme-challenge.mova", "fresh")})
	if err != nil {
		t.Fatal(err)
	}
	wantDeleted := []string{
		"1/10?name=_acme-challenge.mova&type=TXT",
		"1/11?name=_acme-challenge.mova&type=TXT",
	}
	if fmt.Sprint(api.deleted) != fmt.Sprint(wantDeleted) {
		t.Fatalf("deleted: want %v, got %v", wantDeleted, api.deleted)
	}
	if len(api.created) != 1 || api.created[0].Value != "fresh" {
		t.Fatalf("created: %+v", api.created)
	}
	if len(api.records["1"]) != 3 {
		t.Fatalf("other records must survive: %+v", api.records["1"])
	}
	if len(out) != 1 || out[0].RR().Name != "_acme-challenge.mova" {
		t.Fatalf("returned: %+v", out)
	}
}

// --- DeleteRecords ----------------------------------------------------------

func TestDeleteRecords_MatchesValueOnly(t *testing.T) {
	api := newFakeAPI(t, map[string][]dnsRecord{
		"1": {
			{ID: "10", Name: "_acme-challenge.mova", Type: "TXT", Value: "keep", TTL: 120},
			{ID: "11", Name: "_acme-challenge.mova", Type: "TXT", Value: "gone", TTL: 120},
		},
	})
	p := &Provider{APIKey: testKey}

	out, err := p.DeleteRecords(context.Background(), "ybmn.no.", []libdns.Record{
		txt("_acme-challenge.mova", "gone"),
		txt("_acme-challenge.mova", "never-existed"),
	})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(api.deleted) != "[1/11?name=_acme-challenge.mova&type=TXT]" {
		t.Fatalf("deleted: %v", api.deleted)
	}
	if len(out) != 1 {
		t.Fatalf("returned: %+v", out)
	}
}

// --- GetRecords -------------------------------------------------------------

func TestGetRecords_NamesRelativeToCallerZone(t *testing.T) {
	newFakeAPI(t, map[string][]dnsRecord{
		"1": {
			{ID: "1", Name: "@", Type: "A", Value: "10.0.20.5", TTL: 3600},
			{ID: "2", Name: "mova", Type: "A", Value: "10.0.20.5", TTL: 3600},
		},
	})
	p := &Provider{APIKey: testKey}

	recs, err := p.GetRecords(context.Background(), "ybmn.no.")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records", len(recs))
	}
	if n := recs[0].RR().Name; n != "@" {
		t.Errorf("apex name: want @, got %q", n)
	}
	if rr := recs[1].RR(); rr.Name != "mova" || rr.TTL != time.Hour {
		t.Errorf("mova record: %+v", rr)
	}
}
