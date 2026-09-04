// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// withdrawn_grants_are_readable_integration_test.go — у ведомости переселения
// ПОЯВИЛСЯ путь чтения (задача продукта #1992).
//
// # Что было неверно
//
// Ведомость `role_grant_orphan` наполнялась применителем каталога и не читалась
// НИКЕМ: писателей два, прод-читателей ноль. Заведена она затем, чтобы
// отобранное право было восстановимо и объяснимо, — и не давала этого, потому
// что цепочка обрывалась на пути чтения. Со стороны арендатора «право отобрали»
// не отличалось от «права не было»: свою роль он не менял, а действовать она
// перестала.
//
// Это тот же класс, что «значение, которое пишут и не читают»: обрыв невидим
// отовсюду, потому что каждая половина по отдельности исправна.
//
// # Что утверждается
//
// Пара, обе стороны: у роли, чью проекцию переселило снятие строки каталога,
// отобранное ЧИТАЕТСЯ и несёт причину, момент и популяцию; у роли, ничего не
// терявшей, ответ ПУСТ. Без второй половины утверждение зеленело бы на
// реализации, всегда возвращающей одно и то же.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestWithdrawnGrantsAreReachableByReading — ведомость ЧИТАЕТСЯ.
func TestWithdrawnGrantsAreReachableByReading(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)
	applier := applierOver(t, pool)

	_, err := applier.Apply(ctx, probeManifest(
		probeResource("wd1992gone", "get"),
		probeResource("wd1992stay", "get"),
	))
	require.NoError(t, err)

	// ── ВХОД: у роли есть ОБЕ проекции обречённого типа ───────────────────────
	//
	// Объявление правила (`role_rule_ref`) переселяется по своему входу, выдача
	// глагола (`role_verb`) — по своему. Обе популяции нужны: они разные события,
	// и путь чтения обязан их различать, а не складывать.
	role := catalogRole(t, ctx, pool, "wd1992")
	require.NoError(t, writeRuleRefs(t, ctx, repo, role,
		[]domain.RoleRuleRef{{Module: applierProbeModule, Resource: "wd1992gone", Verb: "get"}}))
	_, err = pool.Exec(ctx, `
		INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'get')`,
		string(role), applierProbeModule+".wd1992gone")
	require.NoError(t, err)

	// ── ПРЕДПОСЫЛКА: до снятия отобранного нет ────────────────────────────────
	before := readWithdrawn(t, ctx, repo, role)
	require.Emptyf(t, before, "у роли уже есть отобранное %v — измеренное дальше "+
		"будет смешано с чужим", before)

	// ── ГЛАГОЛ ────────────────────────────────────────────────────────────────
	gone, err := applier.Apply(ctx, probeManifest(probeResource("wd1992stay", "get")))
	require.NoError(t, err)
	require.Positivef(t, gone.RetiredResources,
		"ресурс не снят (%s) — вход не произведён, и всё ниже вакуумно", gone)
	require.Equalf(t, 1, gone.Resettled.RuleRefs, "объявление правила не переселено: %s", gone)
	require.Equalf(t, 1, gone.Resettled.RoleVerbs, "выдача глагола не переселена: %s", gone)

	// ── ИСХОД: ОТОБРАННОЕ ЧИТАЕТСЯ ────────────────────────────────────────────
	got := readWithdrawn(t, ctx, repo, role)
	t.Logf("отобранное у роли: %d %+v", len(got), got)
	require.Lenf(t, got, 2, "переселено 2 строки (объявление и выдача), а прочитано %d — "+
		"путь чтения видит не всё, что записал применитель", len(got))

	bySource := map[domain.WithdrawnGrantSource]domain.WithdrawnGrant{}
	for _, g := range got {
		bySource[g.Source] = g
	}
	grant, ok := bySource[domain.WithdrawnGrantSourceGrant]
	require.Truef(t, ok, "популяция «право отобрано» не прочитана: %+v", got)
	rule, ok := bySource[domain.WithdrawnGrantSourceRuleRef]
	require.Truef(t, ok, "популяция «правило перестало резолвиться» не прочитана: %+v", got)
	require.NotEqualf(t, grant.Source, rule.Source,
		"популяции не различены — «право отобрано» и «правило перестало резолвиться» "+
			"суть разные события, и сложив их, мы теряем именно это различие")

	for _, g := range got {
		require.Equalf(t, applierProbeModule+".wd1992gone", g.ObjectType,
			"прочитан не тот тип: %+v", g)
		require.NotEmptyf(t, g.Reason, "отобранное прочитано БЕЗ ПРИЧИНЫ: %+v\n"+
			"Причина — то, чем «право отобрали» отличается от «права не было»", g)
		require.Falsef(t, g.WithdrawnAt.IsZero(), "отобранное прочитано БЕЗ МОМЕНТА: %+v", g)
		require.Equalf(t, g.WithdrawnAt.Truncate(time.Second), g.WithdrawnAt,
			"момент не усечён до секунд — микросекунды базы текут на провод: %+v", g)
	}
	require.Equalf(t, grant.WithdrawnAt, rule.WithdrawnAt,
		"момент у строк ОДНОГО применения разошёлся")

	// Причина — та же, что записана снятой строкой каталога: второй экземпляр
	// одной величины разошёлся бы с первым молча.
	var retiredReason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT retired_reason FROM kacho_iam.catalog_resource WHERE dotted = $1`,
		applierProbeModule+".wd1992gone").Scan(&retiredReason))
	require.Equal(t, retiredReason, grant.Reason,
		"причина в ведомости разошлась с причиной снятия строки каталога")
}

// TestWithdrawnGrantsOfAnUntouchedRoleAreEmpty — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него «отобранное прочитано» было бы неотличимо от реализации, отдающей
// одно и то же на любой вход, — а именно она и была бы самой опасной: арендатор
// увидел бы отобранным то, чего у него не отбирали.
func TestWithdrawnGrantsOfAnUntouchedRoleAreEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)
	applier := applierOver(t, pool)

	// Снятие в системе ПРОИСХОДИТ — иначе «пусто» вышло бы и у пустой ведомости,
	// то есть контроль ничего бы не различал.
	_, err := applier.Apply(ctx, probeManifest(
		probeResource("wd1992ctrlgone", "get"), probeResource("wd1992ctrlstay", "get")))
	require.NoError(t, err)
	victim := catalogRole(t, ctx, pool, "wd1992victim")
	require.NoError(t, writeRuleRefs(t, ctx, repo, victim,
		[]domain.RoleRuleRef{{Module: applierProbeModule, Resource: "wd1992ctrlgone", Verb: "get"}}))

	bystander := catalogRole(t, ctx, pool, "wd1992bystander")
	require.NoError(t, writeRuleRefs(t, ctx, repo, bystander,
		[]domain.RoleRuleRef{{Module: applierProbeModule, Resource: "wd1992ctrlstay", Verb: "get"}}))

	gone, err := applier.Apply(ctx, probeManifest(probeResource("wd1992ctrlstay", "get")))
	require.NoError(t, err)
	require.Positivef(t, gone.Resettled.RuleRefs,
		"переселения не произошло (%s) — контроль вакуумен", gone)

	require.NotEmptyf(t, readWithdrawn(t, ctx, repo, victim),
		"у пострадавшей роли отобранного не прочитано — контроль сравнивает не с чем")
	require.Emptyf(t, readWithdrawn(t, ctx, repo, bystander),
		"у роли, ничего не терявшей, прочитано отобранное: путь чтения отдаёт чужое")
}

// TestWithdrawnGrantsAskedOnceForThePage — ОДИН вопрос на страницу, а не по
// вопросу на роль: стоимость обязана следовать странице, величина которой
// ограничена контрактом, а не популяции ролей, не ограниченной ничем.
func TestWithdrawnGrantsAskedOnceForThePage(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// Пустой вход законен и означает «спрашивать не о чем».
	got, err := rd.Roles().WithdrawnGrants(ctx, nil)
	require.NoError(t, err)
	require.Empty(t, got, "пустой вход обязан давать пустой ответ, а не отказ")

	ids := make([]domain.RoleID, 0, 64)
	for i := 0; i < 64; i++ {
		ids = append(ids, domain.RoleID("rolabsent0000000000"))
	}
	got, err = rd.Roles().WithdrawnGrants(ctx, ids)
	require.NoError(t, err, "страница из несуществующих ролей обязана читаться без отказа")
	require.Empty(t, got, "несуществующие роли принесли отобранное")
}

// readWithdrawn — путь чтения СВОИМ вопросом, в своей транзакции чтения.
func readWithdrawn(t *testing.T, ctx context.Context, repo kachorepo.Repository, role domain.RoleID) []domain.WithdrawnGrant {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Roles().WithdrawnGrants(ctx, []domain.RoleID{role})
	require.NoError(t, err)
	return got[role]
}
