// client.go
package gigahost

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/libdns/libdns"
)

// baseURLVar is the API root. It's a var (not const) so tests can swap
// it for an httptest server URL. Not part of the public surface.
var baseURLVar = "https://api.gigahost.no/api/v0"

// defaultTTL is used for created records when the caller passes none.
// 120s matches lego's gigahostno provider.
const defaultTTL = 120

type client struct {
	apiKey string
	http   *http.Client
}

func newClient(apiKey string) *client {
	return &client{apiKey: apiKey, http: &http.Client{Timeout: 30 * time.Second}}
}

// flexString decodes a JSON string or number into a string. The API
// documents IDs as strings, but the key permission examples use numeric
// zone IDs, so accept both rather than fail on the first number.
type flexString string

func (f *flexString) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		*f = ""
		return nil
	}
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*f = flexString(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return err
	}
	*f = flexString(n.String())
	return nil
}

type dnsZone struct {
	ID     flexString `json:"zone_id"`
	Name   string     `json:"zone_name"`
	Active flexString `json:"zone_active"`
}

// dnsRecord is a record as the Gigahost API sees it. Name is relative to
// the zone, with "@" for the apex.
type dnsRecord struct {
	ID    flexString `json:"record_id,omitempty"`
	Name  string     `json:"record_name"`
	Type  string     `json:"record_type"`
	Value string     `json:"record_value"`
	TTL   int        `json:"record_ttl,omitempty"`
}

// envelope is the wrapper every response comes in: {"meta": {...}, "data": ...}.
type envelope struct {
	Meta struct {
		Status        int    `json:"status"`
		StatusMessage string `json:"status_message"`
		Message       string `json:"message"`
	} `json:"meta"`
	Data json.RawMessage `json:"data"`
}

// do sends a request and decodes data into out (when out is non-nil).
// what names the operation in errors.
func (c *client) do(ctx context.Context, method string, u *url.URL, body any, out any, what string) error {
	var buf io.Reader = http.NoBody
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("gigahost %s: %w", what, err)
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), buf)
	if err != nil {
		return fmt.Errorf("gigahost %s: %w", what, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("gigahost %s: %w", what, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		var env envelope
		if json.Unmarshal(raw, &env) == nil && env.Meta.Message != "" {
			return fmt.Errorf("gigahost %s: %s: %s", what, resp.Status, env.Meta.Message)
		}
		return fmt.Errorf("gigahost %s: %s: %s", what, resp.Status, bytes.TrimSpace(raw))
	}
	if out == nil {
		return nil
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return fmt.Errorf("gigahost %s: %w", what, err)
	}
	if err := json.Unmarshal(env.Data, out); err != nil {
		return fmt.Errorf("gigahost %s: %w", what, err)
	}
	return nil
}

func (c *client) endpoint(parts ...string) *url.URL {
	u, _ := url.Parse(baseURLVar)
	return u.JoinPath(parts...)
}

// listZones returns the active zones the key can see. A key limited to
// specific zone IDs gets a list filtered to those zones.
func (c *client) listZones(ctx context.Context) ([]dnsZone, error) {
	var zones []dnsZone
	if err := c.do(ctx, http.MethodGet, c.endpoint("dns", "zones"), nil, &zones, "list zones"); err != nil {
		return nil, err
	}
	active := zones[:0]
	for _, z := range zones {
		if z.Active == "1" {
			active = append(active, z)
		}
	}
	return active, nil
}

// listRaw returns the raw dnsRecord slice for a zone. Used by getRecords,
// deleteRecord (content-match path) and SetRecords (RRset-wipe path).
func (c *client) listRaw(ctx context.Context, z *dnsZone) ([]dnsRecord, error) {
	var raw []dnsRecord
	err := c.do(ctx, http.MethodGet, c.endpoint("dns", "zones", string(z.ID), "records"), nil, &raw, "list records")
	return raw, err
}

// getRecords returns the zone's records with names relative to callerZone,
// the zone libdns asked about.
func (c *client) getRecords(ctx context.Context, z *dnsZone, callerZone string) ([]libdns.Record, error) {
	raw, err := c.listRaw(ctx, z)
	if err != nil {
		return nil, err
	}
	out := make([]libdns.Record, 0, len(raw))
	for _, r := range raw {
		fqdn := libdns.AbsoluteName(r.Name, z.Name)
		out = append(out, libdns.RR{
			Type: r.Type,
			Name: libdns.RelativeName(fqdn, callerZone),
			Data: r.Value,
			TTL:  time.Duration(r.TTL) * time.Second,
		})
	}
	return out, nil
}

func ttlSeconds(d time.Duration) int {
	if s := int(d / time.Second); s > 0 {
		return s
	}
	return defaultTTL
}

// createRecord creates r, whose Name must be an FQDN inside z.
func (c *client) createRecord(ctx context.Context, z *dnsZone, r libdns.RR) error {
	body := dnsRecord{
		Name:  libdns.RelativeName(strings.TrimSuffix(r.Name, "."), z.Name),
		Type:  r.Type,
		Value: r.Data,
		TTL:   ttlSeconds(r.TTL),
	}
	what := fmt.Sprintf("create %s %q", body.Type, body.Name)
	return c.do(ctx, http.MethodPost, c.endpoint("dns", "zones", string(z.ID), "records"), body, nil, what)
}

// deleteByID removes a single record. The API wants the record's name and
// type as query parameters alongside its ID.
func (c *client) deleteByID(ctx context.Context, z *dnsZone, rec dnsRecord) error {
	u := c.endpoint("dns", "zones", string(z.ID), "records", string(rec.ID))
	q := u.Query()
	q.Set("name", rec.Name)
	q.Set("type", rec.Type)
	u.RawQuery = q.Encode()
	return c.do(ctx, http.MethodDelete, u, nil, nil, fmt.Sprintf("delete %s %q (id %s)", rec.Type, rec.Name, rec.ID))
}

// deleteRecord deletes the record matching r's name, type and value. r.Name
// must be an FQDN inside z. Returns nil, nil when nothing matched.
func (c *client) deleteRecord(ctx context.Context, z *dnsZone, r libdns.RR) (*libdns.RR, error) {
	raw, err := c.listRaw(ctx, z)
	if err != nil {
		return nil, err
	}

	name := libdns.RelativeName(strings.TrimSuffix(r.Name, "."), z.Name)
	for _, existing := range raw {
		if strings.EqualFold(existing.Name, name) && existing.Type == r.Type && existing.Value == r.Data {
			if err := c.deleteByID(ctx, z, existing); err != nil {
				return nil, err
			}
			return &r, nil
		}
	}
	// No matching record found - treat as no-op (idempotent delete).
	return nil, nil
}
