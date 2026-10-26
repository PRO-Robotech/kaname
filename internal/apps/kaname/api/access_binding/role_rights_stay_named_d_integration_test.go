// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// role_rights_stay_named_d_integration_test.go — группа D приёмки
// role-rights-stay-within-what-is-named.md: существующее не отзывается (Р4).
// ESC-30 — материализация, оставленная прежним выводом яруса, сводится к новому
// сводящим проходом `ConvergeBinding` без отзыва выдач (задачи
// PRO-Robotech/kaname#1035, PRO-Robotech/kaname#1039). ESC-31 держат пробы
// делегирования `TestGrantDelegation_GD10/11/16/25` без правки.

import (
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ledgerOf — строки реестра выпущенного выдачей id, отсортированные.
func (w *escWorld) ledgerOf(id string) []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx,
		`SELECT member_object_type || ' ' || member_object_id || ' ' || fga_user || ' ' || relation || ' ' || object
		   FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`, id)
	require.NoError(w.t, err, "чтение реестра выпущенного")
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		require.NoError(w.t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(w.t, rows.Err())
	sort.Strings(out)
	return out
}

// ledgerRelationCount — строк реестра выдачи id с отношением relation.
func (w *escWorld) ledgerRelationCount(id, relation string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1 AND relation = $2`,
		id, relation).Scan(&n))
	return n
}

// outboxRows — строк журнала записи фактов.
func (w *escWorld) outboxRows() int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.fga_outbox`).Scan(&n))
	return n
}

// seedPriorDeleteTier — прежнее состояние, которое оставлял вывод яруса из
// `delete` (`delete` → `admin`): к каждой строке реестра выдачи с отношением
// `v_delete` — строка `admin` той же выдачи, координаты члена, субъекта, объекта
// и источника, и на каждую добавленную строку — строка журнала факта `admin`
// (форма `gdSeedTuple`: триггер складывает её в факт тем же коммитом). Одна
// транзакция, один оператор для всех выдач (форма `rewindToPreFix`).
func (w *escWorld) seedPriorDeleteTier(ids ...string) {
	w.t.Helper()
	tx, err := w.pool.Begin(w.ctx)
	require.NoError(w.t, err)
	defer func() { _ = tx.Rollback(w.ctx) }()
	_, err = tx.Exec(w.ctx, `
		WITH added AS (
		  INSERT INTO kaname.access_binding_emitted_tuples
		         (binding_id, member_object_type, member_object_id, fga_user, relation, object, source)
		  SELECT binding_id, member_object_type, member_object_id, fga_user, 'admin', object, source
		    FROM kaname.access_binding_emitted_tuples
		   WHERE binding_id = ANY($1) AND relation = 'v_delete'
		  ON CONFLICT DO NOTHING
		  RETURNING fga_user, object)
		INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		SELECT 'fga.tuple.write', jsonb_build_object('user', fga_user, 'relation', 'admin', 'object', object), now()
		  FROM added`, ids)
	require.NoError(w.t, err, "посев прежнего состояния: строки admin реестра и журнала")
	require.NoError(w.t, tx.Commit(w.ctx))
}

// activeBindingIDs — действующие выдачи мира.
func (w *escWorld) activeBindingIDs() []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `SELECT id FROM kaname.access_bindings WHERE revoked_at IS NULL ORDER BY id`)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(w.t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(w.t, rows.Err())
	require.NotEmpty(w.t, out, "предпосылка: в мире есть действующие выдачи")
	return out
}

// convergeAll — сводящий проход по каждой действующей выдаче мира (тот, что
// `seed.BackfillRunner` исполняет при старте новой редакции).
func (w *escWorld) convergeAll(why string) {
	w.t.Helper()
	for _, id := range w.activeBindingIDs() {
		require.NoErrorf(w.t, w.rec.ConvergeBinding(w.ctx, domain.AccessBindingID(id)), "%s: сводящий проход %s", why, id)
	}
}

// ESC-30 — материализация, оставленная прежним выводом яруса, сводится к новому без отзыва выдач.
func TestRoleRightsStayNamed_ESC30_PriorDeleteTierConvergesWithoutRevocation(t *testing.T) {
	w := newEscWorld(t)
	prj := "project:" + string(w.prjA)
	x := pcrRegType + ":" + pcrX
	rulesBefore := w.rulesOf(w.rolE1)

	ledgerStarBefore := w.ledgerOf(w.bStar)
	w.seedPriorDeleteTier(w.bDel, w.bStar)

	// Контроли посева: прежнее состояние видно; у выдачи с `*` оператор ничего не добавил.
	w.pollRelation(escUser(w.usrDel), "admin", prj, true, "ESC-30 контроль посева: usr-D admin на prj-A")
	w.pollRelation(escUser(w.usrDel), "admin", x, true, "ESC-30 контроль посева: usr-D admin на X")
	require.Equal(t, ledgerStarBefore, w.ledgerOf(w.bStar), "ESC-30 контроль посева: реестр выдачи usr-W не изменился")

	w.convergeAll("ESC-30")

	// Выдачи прежние и действуют, правила роли прежние.
	for _, id := range []string{w.bDel, w.bStar, w.bE1R, w.bG1} {
		assert.Equalf(t, "ACTIVE", w.getBinding(id).GetStatus().String(), "ESC-30: выдача %s действует", id)
	}
	assert.Equal(t, rulesBefore, w.rulesOf(w.rolE1), "ESC-30: правила rol-e1 прежние")

	// usr-W (близнец) сохраняет admin; реестр его выдачи тот же.
	w.pollRelation(escUser(w.usrStar), "admin", prj, true, "ESC-30: usr-W admin на prj-A")
	assert.Equal(t, ledgerStarBefore, w.ledgerOf(w.bStar), "ESC-30: строки реестра выдачи usr-W те же, что до прохода")

	// Повторный проход не пишет ни одной строки журнала. Утверждается до
	// утверждений о usr-D, чтобы охрана читалась и там, где предмет красный.
	before := w.outboxRows()
	w.convergeAll("ESC-30 повтор")
	assert.Equal(t, before, w.outboxRows(), "ESC-30: повторный проход не пишет строк журнала")

	// usr-D — только удаление.
	assert.True(t, w.eventually(escUser(w.usrDel), "admin", prj, false), "ESC-30: usr-D admin на prj-A снят")
	assert.True(t, w.eventually(escUser(w.usrDel), "admin", x, false), "ESC-30: usr-D admin на X снят")
	assert.True(t, w.relation(escUser(w.usrDel), "v_delete", prj), "ESC-30: usr-D v_delete на prj-A")
	assert.True(t, w.relation(escUser(w.usrDel), "v_delete", x), "ESC-30: usr-D v_delete на X")
	assert.Zero(t, w.ledgerRelationCount(w.bDel, "admin"), "ESC-30: строк реестра выдачи usr-D с отношением admin")
}

// eventually — дошёл ли ответ модели до want в окне материализации (30 с),
// без остановки пробы: соседние утверждения читаются и при отказе этого.
func (w *escWorld) eventually(subject, relation, object string, want bool) bool {
	w.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if w.relation(subject, relation, object) == want {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}
