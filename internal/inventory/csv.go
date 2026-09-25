// SPDX-License-Identifier: FSL-1.1-ALv2

package inventory

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
)

// ImportCSV reads devices from a spreadsheet export. The first row is a
// header; recognised columns are name (or hostname, device), role, site,
// tags and status, in any order and case. Unknown columns are ignored so a
// NetBox or Nautobot export works without editing.
func ImportCSV(r io.Reader) ([]Target, error) {
	cr := csv.NewReader(r)
	cr.TrimLeadingSpace = true
	cr.FieldsPerRecord = -1
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("inventory: csv: read header: %w", err)
	}
	col := map[string]int{}
	for i, h := range header {
		h = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))
		switch h {
		case "hostname", "device", "device_name":
			h = "name"
		case "device_role", "role_name":
			h = "role"
		case "site_name", "location":
			h = "site"
		}
		if _, dup := col[h]; !dup {
			col[h] = i
		}
	}
	nameIdx, ok := col["name"]
	if !ok {
		return nil, fmt.Errorf("inventory: csv: no name/hostname/device column in header %v", header)
	}
	get := func(rec []string, key string) string {
		i, ok := col[key]
		if !ok || i >= len(rec) {
			return ""
		}
		return strings.TrimSpace(rec[i])
	}
	var out []Target
	line := 1
	for {
		rec, err := cr.Read()
		if err == io.EOF {
			break
		}
		line++
		if err != nil {
			return nil, fmt.Errorf("inventory: csv line %d: %w", line, err)
		}
		if len(rec) == 0 || (len(rec) == 1 && strings.TrimSpace(rec[0]) == "") {
			continue
		}
		name := strings.TrimSpace(rec[nameIdx])
		if name == "" {
			return nil, fmt.Errorf("inventory: csv line %d: empty name", line)
		}
		out = append(out, Target{
			Name:   name,
			Role:   get(rec, "role"),
			Site:   get(rec, "site"),
			Tags:   SplitTags(get(rec, "tags")),
			Status: get(rec, "status"),
		})
	}
	return out, nil
}
