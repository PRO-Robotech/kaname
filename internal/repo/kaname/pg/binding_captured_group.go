// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"bytes"
	"context"
	"encoding/json"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// This adapter replaces three actual legacy SELECTs, not the independent owner
// verification. It exists only for one group coordinate in one RR stage. All
// bindings' versioned rows remain in source.entries, including empty witnesses.
type bindingCapturedGroupStore struct {
	*bindingSnapshotStore
	sequence    *bindingSequenceCapture
	source      *resourceSourceCapture
	binding     domain.AccessBindingID
	id          string
	members     []domain.TargetMember
	ledger      []domain.MembershipTuple
	membersRead bool
	ledgerRead  bool
}

func (g *bindingCapturedGroupStore) check(ctx context.Context, s *bindingSequenceCapture, typ, id string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if g == nil || s == nil || g.sequence != s || g.binding != s.binding || typ != "iam.group" || id != g.id ||
		g.bindingSnapshotStore == nil || g.reconcileStore == nil || s.parents == nil || s.parents.source == nil {
		return kaname.ErrSourceUnconfirmed
	}
	c := s.parents.source
	if c != g.source || c.sealed || c.stageTX == nil || s.parents.tx != c.stageTX || g.tx != c.stageTX ||
		c.conn == nil || g.tx.Conn() != c.conn || c.lifetime == nil || c.lifetime.ended ||
		c.lifetime.conn != c.conn || c.lifetime.prepared != nil || c.lifetime.writer != nil {
		return kaname.ErrSourceUnconfirmed
	}
	return nil
}

// Validate the versioned row envelope as well as the projected value. This is a
// local decoding check, never a substitute for SQL's fresh xmin/ctid comparison.
func bindingCapturedValue(row resourceSourceRow) (map[string]json.RawMessage, error) {
	var state []json.RawMessage
	var xmin, ctid string
	var value, versioned map[string]json.RawMessage
	if json.Unmarshal([]byte(row.state), &state) != nil || len(state) != 3 ||
		json.Unmarshal(state[0], &xmin) != nil || json.Unmarshal(state[1], &ctid) != nil ||
		json.Unmarshal(row.value, &value) != nil || value == nil ||
		json.Unmarshal(state[2], &versioned) != nil || versioned == nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if _, err := strconv.ParseUint(xmin, 10, 32); err != nil {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if !strings.HasPrefix(ctid, "(") || !strings.HasSuffix(ctid, ")") {
		return nil, kaname.ErrSourceUnconfirmed
	}
	parts := strings.Split(ctid[1:len(ctid)-1], ",")
	if len(parts) != 2 {
		return nil, kaname.ErrSourceUnconfirmed
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return nil, kaname.ErrSourceUnconfirmed
		}
	}
	var a, b any
	valueDecoder := json.NewDecoder(bytes.NewReader(row.value))
	versionDecoder := json.NewDecoder(bytes.NewReader(state[2]))
	valueDecoder.UseNumber()
	versionDecoder.UseNumber()
	if valueDecoder.Decode(&a) != nil || versionDecoder.Decode(&b) != nil || !reflect.DeepEqual(a, b) {
		return nil, kaname.ErrSourceUnconfirmed
	}
	return value, nil
}

func bindingCapturedText(value map[string]json.RawMessage, key string) (string, error) {
	var out string
	if json.Unmarshal(value[key], &out) != nil || out == "" {
		return "", kaname.ErrSourceUnconfirmed
	}
	return out, nil
}

func (s *bindingSequenceCapture) captureGroup(ctx context.Context, store *bindingSnapshotStore, id string) (*bindingCapturedGroupStore, domain.MirrorObject, bool, error) {
	var empty domain.MirrorObject
	if s == nil || s.parents == nil {
		return nil, empty, false, kaname.ErrSourceUnconfirmed
	}
	g := &bindingCapturedGroupStore{bindingSnapshotStore: store, sequence: s, source: s.parents.source, binding: s.binding, id: id, members: []domain.TargetMember{}}
	if err := g.check(ctx, s, "iam.group", id); err != nil {
		return nil, empty, false, err
	}
	if !nativeQuestionToken(id) || !nativeQuestionToken(string(s.binding)) {
		return nil, empty, false, kaname.ErrSourceUnconfirmed
	}
	// Validate even the projection envelope; captureObjectProjection then uses
	// the exact same cache entry and the existing typed projection semantics.
	for _, kind := range []resourceSourceKind{resourceSourceIAMObject, resourceSourceObjectMembers, resourceSourceObjectLedger} {
		rows, err := s.parents.source.read(ctx, s.parents.tx, resourceSourceKey{kind: kind, typ: "iam.group", id: id})
		if err != nil {
			return nil, empty, false, err
		}
		for _, row := range rows {
			value, err := bindingCapturedValue(row)
			if err != nil {
				return nil, empty, false, err
			}
			if kind == resourceSourceIAMObject {
				continue // Existing projection decoder checks the group ID.
			}
			fields := []string{"binding_id", "role_id", "rule_fp", "object_type", "object_id", "verification_status"}
			if kind == resourceSourceObjectLedger {
				fields = []string{"binding_id", "member_object_type", "member_object_id", "fga_user", "relation", "object"}
			}
			v := make([]string, len(fields))
			for i, field := range fields {
				v[i], err = bindingCapturedText(value, field)
				if err != nil {
					return nil, empty, false, err
				}
			}
			if kind == resourceSourceObjectMembers {
				if v[3] != "iam.group" || v[4] != id {
					return nil, empty, false, kaname.ErrSourceUnconfirmed
				}
				if v[0] == string(s.binding) {
					g.members = append(g.members, domain.TargetMember{BindingID: s.binding, RoleID: domain.RoleID(v[1]), RuleFP: v[2], ObjectType: v[3], ObjectID: v[4], VerificationStatus: domain.VerificationStatus(v[5])})
				}
			} else {
				if v[1] != "iam.group" || v[2] != id {
					return nil, empty, false, kaname.ErrSourceUnconfirmed
				}
				if v[0] == string(s.binding) {
					g.ledger = append(g.ledger, domain.MembershipTuple{User: v[3], Relation: v[4], Object: v[5]})
				}
			}
		}
	}
	slices.SortStableFunc(g.members, func(a, b domain.TargetMember) int { return strings.Compare(a.RuleFP, b.RuleFP) })
	obj, present, err := s.parents.captureObjectProjection(ctx, "iam.group", id)
	if err != nil {
		return nil, empty, false, err
	}
	return g, obj, present, nil
}

func (g *bindingCapturedGroupStore) CurrentMembersForObject(ctx context.Context, binding domain.AccessBindingID, typ, id string) ([]domain.TargetMember, error) {
	if g == nil || g.sequence == nil || binding != g.sequence.binding {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := g.check(ctx, g.sequence, typ, id); err != nil {
		return nil, err
	}
	g.membersRead = true
	return slices.Clone(g.members), nil
}

func (g *bindingCapturedGroupStore) LedgerTuplesForMember(ctx context.Context, binding domain.AccessBindingID, coord reconcile.MemberCoord) ([]domain.MembershipTuple, error) {
	if g == nil || g.sequence == nil || binding != g.sequence.binding {
		return nil, kaname.ErrSourceUnconfirmed
	}
	if err := g.check(ctx, g.sequence, coord.ObjectType, coord.ObjectID); err != nil {
		return nil, err
	}
	g.ledgerRead = true
	return slices.Clone(g.ledger), nil
}
