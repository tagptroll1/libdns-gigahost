// provider.go
package gigahost

import (
	"context"
	"fmt"
	"strings"

	"github.com/libdns/libdns"
)

// Provider implements the libdns interfaces for Gigahost DNS.
//
// APIKey is a Gigahost API key ("flux_live_..."). It only needs DNS
// read-write, and can be limited to the zones it should touch.
//
// We deliberately do NOT trust the `zone` argument that certmagic/libdns
// passes in. Some resolvers and certmagic's zone-finder can settle on a
// public-suffix-ish zone like "no." for *.ybmn.no, which would then make
// us ask the API for a zone we don't own. Instead, we list the account's
// zones and pick the longest suffix match against the record's FQDN.
type Provider struct {
	APIKey string `json:"api_key"`
}

func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	client := newClient(p.APIKey)
	zones, err := client.listZones(ctx)
	if err != nil {
		return nil, err
	}
	z, _ := pickZoneForName(zones, zone)
	if z == nil {
		return nil, fmt.Errorf("no gigahost-managed zone matches zone %q", zone)
	}
	return client.getRecords(ctx, z, zone)
}

func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIKey)
	zones, err := client.listZones(ctx)
	if err != nil {
		return nil, err
	}

	created := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		r := rec.RR()
		fqdn, z := resolveFQDN(zones, r.Name, zone)
		if z == nil {
			return created, fmt.Errorf("no gigahost-managed zone matches %q (zone %q)", r.Name, zone)
		}
		// createRecord needs the FQDN so it can derive the zone-relative
		// name for the Gigahost API. But the returned libdns.Record must
		// keep r.Name as the caller passed it (relative to the input zone),
		// otherwise certmagic's propagation check will AbsoluteName(...)
		// it again and end up querying e.g. _acme-challenge.X.ybmn.no.ybmn.no.
		apiCall := r
		apiCall.Name = fqdn
		if err := client.createRecord(ctx, z, apiCall); err != nil {
			return created, err
		}
		created = append(created, rec)
	}
	return created, nil
}

// SetRecords replaces records in the zone for each (name, type) RRset.
// For every input record, all existing records with the same relative
// name and type are deleted, then the desired records are created. This
// is what certmagic uses for DNS-01: it guarantees the TXT under
// _acme-challenge.<host> always reflects the *current* challenge value,
// even if a previous attempt left stale records behind.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIKey)
	zones, err := client.listZones(ctx)
	if err != nil {
		return nil, err
	}

	// Group inputs by (zone, relative-name, type) so we wipe each RRset
	// exactly once before writing the desired records into it.
	type rrkey struct {
		zoneID string
		name   string
		rtype  string
	}
	// Each entry pairs the FQDN-form RR we pass to the API with the
	// original caller-supplied Record we hand back unchanged. Returning
	// the original preserves Name's relativity to the input zone - see
	// AppendRecords for why that matters for the propagation check.
	type pair struct {
		apiCall libdns.RR
		orig    libdns.Record
	}
	type bucket struct {
		z     *dnsZone
		name  string
		rtype string
		pairs []pair
	}
	buckets := make(map[rrkey]*bucket)
	order := []rrkey{}

	for _, rec := range records {
		r := rec.RR()
		fqdn, z := resolveFQDN(zones, r.Name, zone)
		if z == nil {
			return nil, fmt.Errorf("no gigahost-managed zone matches %q (zone %q)", r.Name, zone)
		}
		name := strings.ToLower(libdns.RelativeName(strings.TrimSuffix(fqdn, "."), z.Name))
		k := rrkey{string(z.ID), name, r.Type}
		if _, ok := buckets[k]; !ok {
			buckets[k] = &bucket{z: z, name: name, rtype: r.Type}
			order = append(order, k)
		}
		apiCall := r
		apiCall.Name = fqdn
		buckets[k].pairs = append(buckets[k].pairs, pair{apiCall: apiCall, orig: rec})
	}

	out := make([]libdns.Record, 0, len(records))
	for _, k := range order {
		b := buckets[k]

		existing, err := client.listRaw(ctx, b.z)
		if err != nil {
			return out, err
		}
		for _, e := range existing {
			if strings.EqualFold(e.Name, b.name) && e.Type == b.rtype {
				if err := client.deleteByID(ctx, b.z, e); err != nil {
					return out, err
				}
			}
		}

		for _, p := range b.pairs {
			if err := client.createRecord(ctx, b.z, p.apiCall); err != nil {
				return out, err
			}
			out = append(out, p.orig)
		}
	}
	return out, nil
}

func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	client := newClient(p.APIKey)
	zones, err := client.listZones(ctx)
	if err != nil {
		return nil, err
	}

	deleted := make([]libdns.Record, 0, len(records))
	for _, rec := range records {
		r := rec.RR()
		fqdn, z := resolveFQDN(zones, r.Name, zone)
		if z == nil {
			return deleted, fmt.Errorf("no gigahost-managed zone matches %q (zone %q)", r.Name, zone)
		}
		apiCall := r
		apiCall.Name = fqdn
		out, err := client.deleteRecord(ctx, z, apiCall)
		if err != nil {
			return deleted, err
		}
		if out != nil {
			deleted = append(deleted, rec)
		}
	}
	return deleted, nil
}

// candidateFQDNs returns FQDN candidates to try matching against the owned
// zone list. We don't trust the zone arg (it can be misleading like "no."),
// nor do we know whether libdns passed name as already-absolute or as
// relative-to-zone. So we try the as-is form first, then the joined form.
func candidateFQDNs(name, zone string) []string {
	name = strings.TrimSuffix(name, ".")
	z := strings.TrimSuffix(zone, ".")
	if name == "@" || name == "" {
		return []string{z}
	}
	out := []string{name}
	if z != "" && name != z && !strings.HasSuffix(name, "."+z) {
		out = append(out, name+"."+z)
	}
	return out
}

// resolveFQDN picks the first candidate FQDN that has an owned zone match.
// Returns the resolved FQDN and the matching zone.
func resolveFQDN(zones []dnsZone, name, callerZone string) (string, *dnsZone) {
	for _, c := range candidateFQDNs(name, callerZone) {
		if z, _ := pickZoneForName(zones, c); z != nil {
			return c, z
		}
	}
	return "", nil
}

// pickZoneForName picks the zone whose name is the longest suffix of name,
// plus the zone name to pass to libdns.RelativeName. Match is
// case-insensitive and tolerates a trailing dot.
func pickZoneForName(zones []dnsZone, name string) (*dnsZone, string) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	var best *dnsZone
	for i, z := range zones {
		zn := strings.ToLower(strings.TrimSuffix(z.Name, "."))
		if n == zn || strings.HasSuffix(n, "."+zn) {
			if best == nil || len(zn) > len(best.Name) {
				best = &zones[i]
			}
		}
	}
	if best == nil {
		return nil, ""
	}
	return best, best.Name
}

// Ensure interfaces are satisfied
var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)
