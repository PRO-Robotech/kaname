// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// public_container_read_multi_subject_converge_integration_test.go — выдача ПЧ
// [authenticated, anonymous], развёрнутая ДО kaname#880 одному первому
// субъекту, доводится до полного состава полным проходом материализатора —
// тем, что зовут обход по таймеру и проход при старте (seed/reconcile_worker.go,
// seed/migrate_backfill.go).
//
// Прежнее состояние воспроизводится в базе ровно тем, чем оно отличалось:
// у второго субъекта нет ни строк реестра выпущенного, ни прямых фактов, а
// ключ члена `public_reader` — прежней формы, без классов. Предусловие
// утверждается исходом владельца: аноним видит реестр X, но не его
// репозиторий.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

const pcrAnonRef = "system_class:anonymous"

// anonFacts — прямые факты анонима на реестрах и репозиториях мира.
func (p *pcrWorld) anonFacts() []string {
	p.t.Helper()
	rows, err := p.pool.Query(p.ctx,
		`SELECT relation || ' ' || object_type || ':' || object_id FROM kaname.relation_fact
		  WHERE subject = $1 AND object_type IN ($2, $3)`, pcrAnonRef, pcrRegType, pcrRepoType)
	require.NoError(p.t, err, "чтение фактов анонима")
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		require.NoError(p.t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(p.t, rows.Err())
	sort.Strings(out)
	return out
}

// anonLedger — строки реестра выпущенного выдачей id на анонима.
func (p *pcrWorld) anonLedger(id string) []string {
	p.t.Helper()
	rows, err := p.pool.Query(p.ctx,
		`SELECT relation || ' ' || object FROM kaname.access_binding_emitted_tuples
		  WHERE binding_id = $1 AND fga_user = $2`, id, pcrAnonRef)
	require.NoError(p.t, err, "чтение реестра выпущенного")
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		require.NoError(p.t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(p.t, rows.Err())
	sort.Strings(out)
	return out
}

// rewindToPreFix приводит выдачу id к состоянию, которое оставлял код до
// kaname#880: второй субъект (аноним) не развёрнут, ключ `public_reader` — без
// классов.
func (p *pcrWorld) rewindToPreFix(id string) {
	p.t.Helper()
	tx, err := p.pool.Begin(p.ctx)
	require.NoError(p.t, err)
	defer func() { _ = tx.Rollback(p.ctx) }()
	_, err = tx.Exec(p.ctx,
		`DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1 AND fga_user = $2`, id, pcrAnonRef)
	require.NoError(p.t, err, "снятие реестра анонима")
	_, err = tx.Exec(p.ctx,
		`DELETE FROM kaname.relation_fact WHERE subject = $1 AND object_type IN ($2, $3)`,
		pcrAnonRef, pcrRegType, pcrRepoType)
	require.NoError(p.t, err, "снятие фактов анонима")
	tag, err := tx.Exec(p.ctx,
		`UPDATE kaname.access_binding_target_members SET rule_fp = split_part(rule_fp, '@', 1)
		  WHERE binding_id = $1 AND rule_fp LIKE 'public_reader:%'`, id)
	require.NoError(p.t, err, "ключ public_reader прежней формы")
	require.EqualValues(p.t, 1, tag.RowsAffected(), "у выдачи ровно один член public_reader")
	require.NoError(p.t, tx.Commit(p.ctx))
}

// TestPublicContainerRead_MultiSubject_PreFixGrantConvergesOnTheFullPass —
// kaname#880, Н1 ревью: выдача [authenticated, anonymous], оставленная прежним
// кодом, после полного прохода открывает репозиторий анониму, а её факты и
// реестр совпадают с развёрнутыми свежей выдачей.
func TestPublicContainerRead_MultiSubject_PreFixGrantConvergesOnTheFullPass(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("kaname#880 доводка")
	anon, signedIn, _ := p.readers()

	id := p.createDone(asUser(p.ctx, p.usrA),
		p.pchSubjectsRequest(classSubject("authenticated"), classSubject("anonymous")), "kaname#880 доводка: выдача ПЧ")
	for _, q := range fourPairs() {
		p.pollAsk(anon, q.relation, q.modelType, q.id, true, "kaname#880 доводка, свежая выдача: "+q.String())
	}
	freshFacts, freshLedger := p.anonFacts(), p.anonLedger(id)
	require.NotEmpty(t, freshLedger, "kaname#880 доводка, контроль: свежая выдача выпустила анониму кортежи")

	p.rewindToPreFix(id)
	// Предусловие — исход владельца: реестр анониму открыт ветвью выдач,
	// репозиторий — закрыт; вошедшему открыто всё.
	p.requireAsk(anon, "v_get", pcrRegType, pcrX, true, "kaname#880 доводка, прежнее состояние: реестр X")
	p.requireAsk(anon, "v_get", pcrRepoType, pcrXApp, false, "kaname#880 доводка, прежнее состояние: репозиторий X/app")
	p.requireAsk(signedIn, "v_get", pcrRepoType, pcrXApp, true, "kaname#880 доводка, прежнее состояние: вошедшему X/app")

	require.NoError(t, p.rec.ReconcileBinding(p.ctx, domain.AccessBindingID(id)), "kaname#880 доводка: полный проход")

	for _, q := range fourPairs() {
		p.pollAsk(anon, q.relation, q.modelType, q.id, true, "kaname#880 доводка, после прохода: "+q.String())
	}
	require.Equal(t, freshFacts, p.anonFacts(), "kaname#880 доводка: факты анонима — как у свежей выдачи")
	require.Equal(t, freshLedger, p.anonLedger(id), "kaname#880 доводка: реестр анонима — как у свежей выдачи")
	require.Equal(t, []string{"system_class:anonymous", "system_class:authenticated"}, p.publicReadersOn(pcrX),
		"kaname#880 доводка: public_reader на X у обоих классов")
}
