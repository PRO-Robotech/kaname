// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// grant_delegation_i_audit_integration_test.go — группа I приёмки делегированных
// выдач (PRO-Robotech/kaname#986): аудит каждого шага, GD-70. Держатель аудита —
// чтение `kaname.audit_outbox` (RPC чтения аудита нет, §0.6 приёмки).

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// gdAuditRow — строка `kaname.audit_outbox`.
type gdAuditRow struct {
	eventType string
	payload   map[string]any
	tenant    sql.NullString
}

func (w *gdWorld) auditRows() []gdAuditRow {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `SELECT event_type, event_payload, tenant_account_id FROM kaname.audit_outbox ORDER BY created_at, id`)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []gdAuditRow
	for rows.Next() {
		var r gdAuditRow
		var raw []byte
		require.NoError(w.t, rows.Scan(&r.eventType, &raw, &r.tenant))
		require.NoError(w.t, json.Unmarshal(raw, &r.payload))
		out = append(out, r)
	}
	require.NoError(w.t, rows.Err())
	return out
}

// findAudit — строки данного типа, чей `binding_id` (если задан) совпадает.
func findAudit(rows []gdAuditRow, eventType, bindingID string) []gdAuditRow {
	var out []gdAuditRow
	for _, r := range rows {
		if r.eventType != eventType {
			continue
		}
		if bindingID != "" && fmt.Sprint(r.payload["binding_id"]) != bindingID {
			continue
		}
		out = append(out, r)
	}
	return out
}

// delegateNamed — `delegate` полезной нагрузки называет учётку (строкой либо {type, id}).
func delegateNamed(v any, sva string) bool {
	switch d := v.(type) {
	case string:
		return d == sva
	case map[string]any:
		return d["id"] == sva
	}
	return false
}

// GD-70 — аудит каждого шага.
func TestGrantDelegation_GD70_EveryStepIsAudited(t *testing.T) {
	w := newGDWorld(t)
	w.requireSubject("GD-70")
	ua, sa := asUser(w.ctx, w.usrA), asSA(w.ctx, w.svaIss)

	// 1. usr-A заводит D1.
	d1 := w.d1()
	// 2. sva-iss выдаёт B10, B13, B14.
	b10 := requireGranted(t, w.tryGrant(sa, w.v()), "GD-70 шаг 2: B10")
	b13 := requireGranted(t, w.tryGrant(sa, w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.RoleId, r.Subjects = string(w.rolPuller), []*iamv1.Subject{classSubject("anonymous")}
	})), "GD-70 шаг 2: B13")
	b14 := requireGranted(t, w.tryGrant(sa, w.vWith(func(r *iamv1.CreateAccessBindingRequest) {
		r.Subjects = []*iamv1.Subject{svaSubject(w.svaA2)}
		r.Target = resourcesTarget(&iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrXApp}, &iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrYApp})
	})), "GD-70 шаг 2: B14")
	// 3. sva-iss отзывает B10.
	op, err := w.revokeBinding(sa, b10)
	w.requireVerbDone(op.GetId(), err, "GD-70 шаг 3")
	// 4. usr-A отзывает B14 прежним путём; выдаёт Bo и отзывает её.
	w.awaitRemovalRight(w.usrA, b14, "GD-70 шаг 4 Дано: у владельца v_delete на B14")
	op, err = w.revokeBinding(ua, b14)
	w.requireVerbDone(op.GetId(), err, "GD-70 шаг 4: B14")
	bo := w.boOf()
	w.awaitRemovalRight(w.usrA, bo, "GD-70 шаг 4 Дано: у владельца v_delete на Bo")
	op, err = w.revokeBinding(ua, bo)
	w.requireVerbDone(op.GetId(), err, "GD-70 шаг 4: Bo")
	// 5. sva-iss пытается выдать по телу GD-11 a.
	requireDenied(t, w.tryGrant(sa, w.vWith(func(r *iamv1.CreateAccessBindingRequest) { r.RoleId = string(w.rolRegGet) })),
		"GD-70 шаг 5")
	// 6. usr-A отзывает D1.
	w.revokeDelegation(ua, d1, "GD-70 шаг 6")

	rows := w.auditRows()
	t.Logf("GD-70: прочитано строк kaname.audit_outbox — %d", len(rows))
	require.NotEmpty(t, rows, "GD-70: не выполнилось — 0 прочитанных строк аудита")

	one := func(eventType, bindingID, why string) gdAuditRow {
		t.Helper()
		got := findAudit(rows, eventType, bindingID)
		require.Lenf(t, got, 1, "%s: строк %s (binding_id %q)", why, eventType, bindingID)
		return got[0]
	}
	acc := string(w.accA)
	tenantIs := func(r gdAuditRow, want string, why string) {
		t.Helper()
		if want == "" {
			assert.Falsef(t, r.tenant.Valid, "%s: tenant_account_id = %q, а должен быть NULL", why, r.tenant.String)
			return
		}
		assert.Truef(t, r.tenant.Valid && r.tenant.String == want, "%s: tenant_account_id = %v, ожидался %s", why, r.tenant, want)
	}

	// Шаг 1.
	created := findAudit(rows, "iam.grant_delegation.created", "")
	require.Len(t, created, 1, "GD-70 шаг 1: строк iam.grant_delegation.created")
	assert.Equal(t, d1, created[0].payload["delegation_id"], "GD-70 шаг 1: delegation_id")
	assert.True(t, delegateNamed(created[0].payload["delegate"], w.svaIss), "GD-70 шаг 1: delegate = %v", created[0].payload["delegate"])
	assert.Equal(t, "registry", created[0].payload["module"], "GD-70 шаг 1: module")
	assert.Equal(t, string(w.usrA), created[0].payload["actor"], "GD-70 шаг 1: actor")
	tenantIs(created[0], acc, "GD-70 шаг 1")
	// Шаг 2.
	for _, id := range []string{b10, b13, b14} {
		r := one("iam.access_binding.granted", id, "GD-70 шаг 2")
		assert.Equalf(t, d1, r.payload["delegation_id"], "GD-70 шаг 2: delegation_id %s", id)
		assert.Equalf(t, w.svaIss, r.payload["actor"], "GD-70 шаг 2: actor %s", id)
		tenantIs(r, acc, "GD-70 шаг 2 "+id)
	}
	// Шаг 3.
	r := one("iam.access_binding.revoked", b10, "GD-70 шаг 3")
	assert.Equal(t, d1, r.payload["delegation_id"], "GD-70 шаг 3: delegation_id")
	assert.Equal(t, w.svaIss, r.payload["actor"], "GD-70 шаг 3: actor")
	tenantIs(r, acc, "GD-70 шаг 3")
	// Шаг 4: B14 — отзыв обычным держателем права тоже несёт delegation_id; Bo — нет.
	r = one("iam.access_binding.revoked", b14, "GD-70 шаг 4: B14")
	assert.Equal(t, d1, r.payload["delegation_id"], "GD-70 шаг 4: delegation_id B14")
	assert.Equal(t, string(w.usrA), r.payload["actor"], "GD-70 шаг 4: actor B14")
	tenantIs(r, acc, "GD-70 шаг 4 B14")
	r = one("iam.access_binding.revoked", bo, "GD-70 шаг 4: Bo")
	assert.NotContains(t, r.payload, "delegation_id", "GD-70 шаг 4: у Bo ключ delegation_id")
	assert.Equal(t, string(w.usrA), r.payload["actor"], "GD-70 шаг 4: actor Bo")
	tenantIs(r, "", "GD-70 шаг 4 Bo (отзыв)")
	tenantIs(one("iam.access_binding.granted", bo, "GD-70 шаг 4: выдача Bo"), "", "GD-70 шаг 4 Bo (выдача)")
	// Шаг 6.
	r = one("iam.access_binding.delegation_revoked", b13, "GD-70 шаг 6")
	assert.Equal(t, d1, r.payload["delegation_id"], "GD-70 шаг 6: delegation_id")
	assert.Equal(t, "delegation_revoked", r.payload["revocation_reason"], "GD-70 шаг 6: revocation_reason")
	tenantIs(r, acc, "GD-70 шаг 6 B13")
	revoked := findAudit(rows, "iam.grant_delegation.revoked", "")
	require.Len(t, revoked, 1, "GD-70 шаг 6: строк iam.grant_delegation.revoked")
	assert.Equal(t, d1, revoked[0].payload["delegation_id"], "GD-70 шаг 6: delegation_id")
	assert.EqualValues(t, 1, revoked[0].payload["revoked_binding_count"], "GD-70 шаг 6: revoked_binding_count (действовала одна B13)")
	tenantIs(revoked[0], acc, "GD-70 шаг 6")
	// Шаг 5 строки не добавил.
	granted := 0
	for _, g := range findAudit(rows, "iam.access_binding.granted", "") {
		if g.payload["actor"] == w.svaIss {
			granted++
		}
	}
	assert.Equal(t, 3, granted, "GD-70: строк granted от sva-iss — ровно три")
}
