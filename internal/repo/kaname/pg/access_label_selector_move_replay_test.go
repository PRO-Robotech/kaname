// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

type selectorMoveReplayTx struct {
	*resourceSourceTx
	role, matches  []resourceSourceRow
	account        []resourceSourceRow
	predicateReads int
}

func (t *selectorMoveReplayTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	switch {
	case strings.Contains(sql, "FROM kaname.roles r WHERE r.id"):
		return &resourceSourceRows{rows: t.role}, nil
	case strings.Contains(sql, "FROM kaname.accounts r WHERE r.id"):
		return &resourceSourceRows{rows: t.account}, nil
	case strings.Contains(sql, "FROM kaname.role_rule_selectors r WHERE r.role_id"),
		strings.Contains(sql, "FROM kaname.access_bindings r WHERE r.role_id"):
		return &resourceSourceRows{}, nil
	case strings.Contains(sql, "jsonb_build_object('object_type',$1::text"):
		t.predicateReads++
		return &resourceSourceRows{rows: t.matches}, nil
	default:
		return nil, kaname.ErrSourceUnconfirmed
	}
}

func TestAccessLabelMoveReplayChecksEmptyPredicateAndExactRequest(t *testing.T) {
	source, rr, _ := resourceSourceFixture(t)
	p, err := newResourceParentCapture(rr, source)
	require.NoError(t, err)
	role := domain.Role{ID: "rol-replay", AccountID: "acc-replay", ResourceVersion: "29", Rules: domain.Rules{{
		Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"team": "red"},
	}}}
	after, moves, err := role.Rules.PlanAccessLabelSelectorMoves([]domain.AccessLabelSelectorMove{{
		Fingerprint: role.Rules[0].Fingerprint(),
	}}, domain.PolicyOfRole(false, ""), domain.ModuleSetOf("registry"))
	require.NoError(t, err)
	beforeBytes, err := rulesToJSON(role.Rules)
	require.NoError(t, err)
	afterBytes, err := rulesToJSON(after)
	require.NoError(t, err)
	value, err := json.Marshal(map[string]any{"id": role.ID, "account_id": role.AccountID,
		"rules": json.RawMessage(beforeBytes), "permissions": []string{}, "labels": map[string]string{}})
	require.NoError(t, err)
	state, err := json.Marshal([]any{role.ResourceVersion, "(0,4)", json.RawMessage(value)})
	require.NoError(t, err)
	roleKey := resourceSourceKey{kind: resourceSourceRole, typ: "role", id: string(role.ID)}
	source.entries[roleKey] = []resourceSourceRow{{state: string(state), value: value}}
	scope := domain.ScopeAnchor{Type: "account", ID: string(role.AccountID)}
	projected := resourceSelectorPredicate{RuleFP: role.Rules[0].Fingerprint(), Arm: domain.ArmLabels,
		Scope: scope, Labels: role.Rules[0].MatchLabels, Targets: []string{}}
	raw, err := json.Marshal(projected)
	require.NoError(t, err)
	key := resourceSourceKey{kind: resourceSourceRoleSelectorObjects, typ: "registry.registries", id: string(role.ID), projection: string(raw)}
	source.entries[key] = nil

	// Сохранённые дополнительные поля не воспроизводятся typed codec.
	exactImage := json.RawMessage(strings.Replace(string(afterBytes), "\"module\":", "\"legacy_wire\":null,\"module\":", 1))
	capture := accessLabelSelectorMoveCapture{Before: role, ProposedRules: after, ProposedImage: exactImage, Moves: moves}
	capture.proof, err = p.rememberAccessLabelMoveRR(capture)
	require.NoError(t, err)
	replay, err := p.sealAccessLabelMoveReplay(capture)
	require.NoError(t, err)
	require.Contains(t, string(replay.image), `"legacy_wire":null`)
	capture.ProposedImage[0] = ' '
	require.Equal(t, byte('['), replay.image[0])
	require.Len(t, replay.predicates, 1)
	require.Equal(t, []domain.ScopeAnchor{scope}, replay.predicates[0].Scopes, "пустой результат не отменяет ограду области")
	_, err = source.read(t.Context(), rr, key)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)

	rc := &selectorMoveReplayTx{resourceSourceTx: rr, role: source.entries[roleKey]}
	writer := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: rc}}}
	req := kaname.RoleMutationRequest{Role: role, Rules: true, Update: true, ExpectedVersion: role.ResourceVersion, UpdateMask: []string{"rules"}}
	recheck := func() error {
		_, err := replay.recheck(t.Context(), writer, req)
		return err
	}
	require.ErrorIs(t, recheck(), kaname.ErrSourceUnconfirmed, "подмена правил")
	require.Zero(t, rc.predicateReads)

	req.Role.Rules = after
	req.Role.AccountID = "acc-alien"
	require.ErrorIs(t, recheck(), kaname.ErrSourceUnconfirmed, "подмена владельца")
	require.Zero(t, rc.predicateReads)
	req.Role.AccountID = role.AccountID
	rc.matches = []resourceSourceRow{{state: "new-match", value: json.RawMessage(`{"object_type":"registry.registries","object_id":"new"}`)}}
	require.ErrorIs(t, recheck(), kaname.ErrAuthorityClassificationChanged, "появился объект в пустой выборке")
	require.Equal(t, 1, rc.predicateReads)
	require.ErrorIs(t, recheck(), kaname.ErrSourceUnconfirmed, "попытка не переиспользуется после расхождения")
}
