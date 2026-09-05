// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// immutableMsgRe captures the FIELD-NAME token of the Kachō immutable-field
// contract message `"<field> is immutable after <Resource>.Create"`
// (api-conventions.md, update_mask discipline).
var immutableMsgRe = regexp.MustCompile(`"([A-Za-z_][A-Za-z0-9_]*) is immutable after ([A-Za-z]+)\.Create"`)

// TestImmutableFieldMessages_UseWireCasing is a structural convention gate over
// every iam use-case: the field name inside an immutable-field error message must
// be spelled the way the client spelled it ON THE WIRE — camelCase.
//
// api-conventions.md fixes JSON/REST as camelCase (`accountId`, `createdAt`), so
// a snake_case message names a field the caller never typed and cannot find in the
// REST surface. The pre-fix state was inconsistent WITHIN iam — project/update.go
// said "accountId is immutable after Project.Create" while group/update.go said
// "account_id is immutable after Group.Create" for the same wire field — so the
// text was not even a stable contract across resources.
//
// The gate is structural (source scan, cf. compute's no_direct_fga_test.go /
// commentlint) so a NEW iam resource cannot reintroduce snake_case in its own
// immutable map without turning this red.
//
// NB: it constrains the message TEXT only. The map KEYS legitimately carry both
// spellings (`account_id` AND `accountId`) — grpc-gateway may deliver either form
// in update_mask, and both must be recognised.
func TestImmutableFieldMessages_UseWireCasing(t *testing.T) {
	root := filepath.Join("..", "api")
	var offenders []string

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		for _, m := range immutableMsgRe.FindAllStringSubmatch(string(b), -1) {
			field, resource := m[1], m[2]
			if !strings.Contains(field, "_") {
				continue // already wire-cased (or a single lowercase word)
			}
			offenders = append(offenders, path+": "+field+
				" (message \""+field+" is immutable after "+resource+".Create\") — want camelCase "+
				toCamel(field))
		}
		return nil
	})
	require.NoError(t, err)

	sort.Strings(offenders)
	if len(offenders) > 0 {
		t.Fatalf("immutable-field messages must name the field in wire (camelCase) form, got %d snake_case:\n  %s",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// toCamel converts a proto snake_case field name to its JSON/wire camelCase form
// (the same rule protobuf-JSON applies): `owner_user_id` → `ownerUserId`.
func toCamel(s string) string {
	parts := strings.Split(s, "_")
	var b strings.Builder
	for i, p := range parts {
		if p == "" {
			continue
		}
		if i == 0 {
			b.WriteString(p)
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	return b.String()
}
