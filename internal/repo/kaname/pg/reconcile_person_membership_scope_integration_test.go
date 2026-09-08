// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_person_membership_scope_integration_test.go — СЕЛЕКТОРНАЯ ВЫДАЧА НА
// ЛЮДЕЙ сужается ЧЛЕНСТВОМ, а не колонкой `kaname.users.account_id`
// (задача kacho#1172).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// План чтения материализации (`iamDirectScanSpecs`) брал аккаунт личности из
// колонки её строки. Колонка одна, а членств у человека может быть несколько
// (#470/#471), поэтому она называет ОДИН аккаунт из многих — и отсюда два
// наблюдаемых следствия у арендатора:
//
//	1. привязка с `matchLabels` на `iam.user`, выданная во ВТОРОМ аккаунте, не
//	   материализуется на человеке ВООБЩЕ: отбор по меткам людей у второго
//	   аккаунта пуст by construction;
//	2. человек, ИСКЛЮЧЁННЫЙ из аккаунта, остаётся в его отборе: снятие членства
//	   колонку не трогает (она легаси и правится своим шагом), и селекторная
//	   привязка продолжает материализовать на нём глаголы.
//
// Цепь областей (`kaname.resource_scope_edge`) ту же связь берёт из
// `kaname.memberships` с #944 — то есть об одном предмете было два места, и
// они разошлись.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ — ИСХОД, А НЕ ВЫЗОВ
//
// Спрашивается материализованная выдача: КОМУ на КАКОМ объекте она есть после
// прохода реконсайлера. Ни один вызов адаптера здесь не утверждается: план
// чтения — деталь, наблюдаемо же то, накрыла привязка человека или нет.
//
// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ СТОИТ У КАЖДОГО ОТРИЦАНИЯ. «Второй аккаунт видит
// своего» зеленело бы и на реализации, которая накрывает всех подряд, поэтому
// рядом стоит человек, чьё членство только в первом аккаунте: второй аккаунт
// его НЕ накрывает. И наоборот — «исключённый выпал» зеленело бы на
// реализации, не материализующей никого, поэтому рядом с исключением стоит
// живая выдача второго аккаунта на том же человеке.
//
// Третий аккаунт с ДОСЛОВНО ТЕМ ЖЕ правилом не накрывает ни одного из двоих:
// расширение обязано быть ограничено членствами, а не снимать сужение вовсе.
//
// RED до перевода плана чтения на членства, GREEN после.
// Прогон: `go test -C services/iam ./internal/repo/kaname/pg/ -run PersonSelector`
// (testcontainers + Docker). Пропускается под -short.

import (
	"context"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// seedLabeledPerson кладёт строку человека, чья КОЛОНКА называет `columnAccount`,
// и вешает на него метки. Зеркало 470001 заводит членство в том же аккаунте.
//
// Колонка задаётся явно (а не через mustSeedUser, заводящий человеку свой
// аккаунт-пустышку) именно потому, что предмет пробы — расхождение колонки с
// членствами: состояние, в котором они называют разное, обязано быть построено
// здесь, а не получиться случайно.
func seedLabeledPerson(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	suffix string, columnAccount domain.AccountID, labels map[string]string,
) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err := pool.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, labels)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE', $6::jsonb)`,
		string(uid), string(columnAccount),
		fmt.Sprintf("ext-%s-%s", suffix, uid),
		fmt.Sprintf("p-%s-%s@example.com", suffix, uid),
		"Person "+suffix,
		jsonObject(labels),
	)
	require.NoError(t, err, "сев человека %s", suffix)
	return uid
}

// dropMembership снимает членство — то же действие, которым исключает из
// аккаунта распорядитель (#1127). Колонка строки при этом НЕ трогается: она
// легаси-поле перехода и снимается своим шагом.
func dropMembership(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID domain.UserID, accountID domain.AccountID) {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`DELETE FROM kaname.memberships WHERE user_id = $1 AND account_id = $2`,
		string(userID), string(accountID))
	require.NoError(t, err, "снятие членства (%s → %s)", userID, accountID)
	require.EqualValues(t, 1, tag.RowsAffected(),
		"снимать было нечего: предпосылка шага не выполнена, и «выпал из отбора» "+
			"означало бы «его там и не было»")
}

// personSelectorRole — роль с ОДНИМ правилом полосы `labels` на `iam.user`.
func personSelectorRule(labels map[string]string) domain.Rule {
	return domain.Rule{
		Module: "iam", Resources: []string{"user"}, Verbs: []string{"get"},
		MatchLabels: labels,
	}
}

// TestPersonSelectorGrant_FollowsMembership_NotTheLegacyColumn — kacho#1172.
func TestPersonSelectorGrant_FollowsMembership_NotTheLegacyColumn(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)
	rec, _ := newReconciler(pool)

	// Три аккаунта: A — тот, что стоит в колонке; B — второй, куда человека
	// пригласили; C — посторонний, несущий ДОСЛОВНО ТО ЖЕ правило.
	accA := seedAccount(t, ctx, repo, "acc-pms-a", mustSeedUser(t, ctx, pool, "pms-own-a"))
	accB := seedAccount(t, ctx, repo, "acc-pms-b", mustSeedUser(t, ctx, pool, "pms-own-b"))
	accC := seedAccount(t, ctx, repo, "acc-pms-c", mustSeedUser(t, ctx, pool, "pms-own-c"))

	labels := map[string]string{"team": "alpha"}

	// dual — человек с членствами в A и B; колонка называет A.
	dual := seedLabeledPerson(t, ctx, pool, "dual", accA.ID, labels)
	seedMembership(t, ctx, pool, dual, accB.ID, "ACTIVE")

	// onlyA — ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: те же метки, членство только в A.
	onlyA := seedLabeledPerson(t, ctx, pool, "onlya", accA.ID, labels)

	rule := personSelectorRule(labels)
	fp := rule.Fingerprint()

	bind := func(acc domain.AccountID, name string) domain.AccessBindingID {
		roleID := seedAccountRulesRole(t, ctx, pool, repo, acc, name, domain.Rules{rule})
		subject := mustSeedUser(t, ctx, pool, name+"-subj")
		return insertThinBindingScope(t, ctx, repo, subject, roleID,
			"account", string(acc), domain.ScopeAccount)
	}
	bindA := bind(accA.ID, "pmsrolea")
	bindB := bind(accB.ID, "pmsroleb")
	bindC := bind(accC.ID, "pmsrolec")

	active := func(bid domain.AccessBindingID, uid domain.UserID) bool {
		st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "iam.user", string(uid))
		return ok && st == domain.VerificationActive
	}

	require.NoError(t, rec.ReconcileBinding(ctx, bindA))
	require.NoError(t, rec.ReconcileBinding(ctx, bindB))
	require.NoError(t, rec.ReconcileBinding(ctx, bindC))

	// (+) аккаунт колонки видит обоих своих — контроль того, что отбор вообще работает.
	assert.True(t, active(bindA, dual),
		"аккаунт A обязан накрыть человека, чьё членство в A есть")
	assert.True(t, active(bindA, onlyA),
		"положительный контроль: отбор по меткам людей в аккаунте A работает")

	// (+) ВТОРОЙ аккаунт видит своего — предмет пункта 1 задачи.
	assert.True(t, active(bindB, dual),
		"аккаунт B обязан накрыть человека, чьё членство в B есть: селекторная "+
			"выдача сужается ЧЛЕНСТВОМ, а не колонкой строки")

	// (−) и только своего.
	assert.False(t, active(bindB, onlyA),
		"аккаунт B НЕ вправе накрыть человека, членства которого в B нет")

	// (−) посторонний аккаунт с тем же правилом — ни одного.
	assert.False(t, active(bindC, dual), "аккаунт C не накрывает чужого человека")
	assert.False(t, active(bindC, onlyA), "аккаунт C не накрывает чужого человека")

	// ── исключение из аккаунта: предмет пункта 2 задачи ──────────────────────
	dropMembership(t, ctx, pool, dual, accA.ID)
	require.NoError(t, rec.ReconcileBinding(ctx, bindA))
	require.NoError(t, rec.ReconcileBinding(ctx, bindB))

	assert.False(t, active(bindA, dual),
		"исключённый из A обязан выпасть из селекторного отбора A: снятие членства "+
			"колонку не трогает, и выдача не вправе держаться за неё")
	// (+) положительный контроль исключения: выдача ДРУГОГО аккаунта уцелела —
	// иначе «выпал» зеленело бы на реализации, снявшей вообще всё.
	assert.True(t, active(bindB, dual),
		"членство в B снятием членства в A не задето")
	assert.True(t, active(bindA, onlyA),
		"положительный контроль: отбор аккаунта A продолжает работать на том, "+
			"чьё членство в A уцелело")
}

// TestPersonForwardFanout_ReachesEveryAccountOfTheMembership — kacho#1172,
// БЫСТРЫЙ ПУТЬ.
//
// Полная пересборка выше спрашивает «кого накрывает эта выдача». Здесь
// спрашивается обратное и по другому коду: «какие выдачи обязаны пересобраться,
// потому что изменился ЭТОТ человек». Полоса «якорь» этого подбора сужается тем
// же выражением источника аккаунтов, что и проекция, — значит на скалярной форме
// она называла ОДИН аккаунт, и человек, чьё членство во втором аккаунте не
// первое, не попадал бы на быстрый путь ВООБЩЕ: доступ появлялся бы только
// периодическим проходом, а «не доехало» и «не выдано» снаружи неразличимы.
//
// Утверждается ИСХОД обеих половин: и перечень выдач-кандидатов, и то, что после
// прохода по объекту участник материализован в обоих аккаунтах. Отрицание —
// посторонний аккаунт с ДОСЛОВНО ТЕМ ЖЕ правилом — стоит рядом с обоими.
func TestPersonForwardFanout_ReachesEveryAccountOfTheMembership(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)
	rec, adapter := newReconciler(pool)

	accA := seedAccount(t, ctx, repo, "acc-pfo-a", mustSeedUser(t, ctx, pool, "pfo-own-a"))
	accB := seedAccount(t, ctx, repo, "acc-pfo-b", mustSeedUser(t, ctx, pool, "pfo-own-b"))
	accC := seedAccount(t, ctx, repo, "acc-pfo-c", mustSeedUser(t, ctx, pool, "pfo-own-c"))

	// Человек с членствами в A и B; колонка называет A.
	dual := seedLabeledPerson(t, ctx, pool, "pfodual", accA.ID, map[string]string{})
	seedMembership(t, ctx, pool, dual, accB.ID, "ACTIVE")

	// Полоса «якорь»: правило без меток и без имён — «все люди области».
	fp := domain.Rule{Module: "iam", Resources: []string{"user"}, Verbs: []string{"*"}}.Fingerprint()
	bind := func(acc domain.AccountID, name string) (domain.AccessBindingID, string) {
		roleID := seedAdminRulesRole(t, ctx, pool, repo, acc, name, "user")
		subject := mustSeedUser(t, ctx, pool, name+"-subj")
		bid := insertThinBindingScope(t, ctx, repo, subject, roleID,
			"account", string(acc), domain.ScopeAccount)
		return bid, "user:" + string(subject)
	}
	bindA, _ := bind(accA.ID, "pforolea")
	bindB, _ := bind(accB.ID, "pforoleb")
	bindC, _ := bind(accC.ID, "pforolec")

	// ── половина 1: перечень выдач-кандидатов ────────────────────────────────
	cands := iamDirectAnchorCandidates(t, ctx, adapter, "iam.user", string(dual))
	assert.True(t, containsBinding(cands, bindA),
		"положительный контроль: выдача аккаунта, названного колонкой, остаётся кандидатом")
	assert.True(t, containsBinding(cands, bindB),
		"выдача ВТОРОГО аккаунта членства обязана быть кандидатом: иначе доступ там "+
			"появляется только периодическим проходом, а то и не появляется вовсе")
	assert.False(t, containsBinding(cands, bindC),
		"выдача постороннего аккаунта кандидатом быть не вправе")

	// ── половина 2: исход прохода по объекту ─────────────────────────────────
	require.NoError(t, rec.ReconcileObject(ctx, "iam.user", string(dual)))
	activeOn := func(bid domain.AccessBindingID) bool {
		st, ok := memberStatusByRule(t, ctx, pool, bid, fp, "iam.user", string(dual))
		return ok && st == domain.VerificationActive
	}
	assert.True(t, activeOn(bindA), "положительный контроль: аккаунт A накрыл своего человека")
	assert.True(t, activeOn(bindB), "аккаунт B обязан накрыть своего человека и быстрым путём")
	assert.False(t, activeOn(bindC), "посторонний аккаунт не накрывает чужого человека")
}
