// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_grant_withdrawal_reaches_the_subscriber_integration_test.go — ОТЗЫВ ПРАВА
// ПОСЛЕДСТВИЕМ КАТАЛОГА ВИДЕН ПОДПИСЧИКУ (задача службы #76).
//
// # Предмет
//
// Снятие строки каталога отбирает у арендаторской роли глагол либо сегмент, а
// строки роли путь последствий не трогает ни одним оператором. Журнал подписки
// эмитит правку роли ТОЛЬКО со строки роли (решение #73) — значит без явного
// объявления событие не рождается, и отзыв для подписчика неотличим от «ничего
// не произошло».
//
// # Что здесь утверждается, а что НЕТ
//
// Утверждается СВОЙСТВО ТРАНЗАКЦИИ, а не факт вызова. «Событие эмитировано» —
// утверждение о вызове: оно осталось бы зелёным и у эмиссии после коммита,
// которая на откате даёт подписчику отзыв, которого не было. Поэтому §3 гонит
// то же снятие под транзакцией, которая ОТКАТЫВАЕТСЯ, и требует, чтобы вместе с
// отобранным ушло и событие.
//
// НЕ утверждается свойство СХЕМЫ: голая запись подтаблицы в обход строки роли
// события по-прежнему не даёт, и это решение #73, а не остаток. Ту половину
// держит `internal/migrations/role_subtable_boot_volume_integration_test.go` §3 —
// там же сказано, почему триггер на трёх подтаблицах отвергнут ЗАМЕРОМ.
//
// # Почему проба ходит ПРИМЕНЕНИЕМ, а не собирает три оператора руками
//
// Предмет задачи — наблюдаемость отзыва у арендатора, а отзыв производит
// применение. Проба, собравшая шаги сама, утверждала бы о своей сборке: пропусти
// применитель шаг объявления, она осталась бы зелёной. Руками собран только §3 —
// там нужен ОТКАТ, а применение, дошедшее до конца, коммитит by construction.

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestIntegration_RoleGrantWithdrawalReachesTheSubscriber — #76.
func TestIntegration_RoleGrantWithdrawalReachesTheSubscriber(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	boot := applierOver(t, pool)
	writeRepo := kanamepg.NewCatalogWriteRepo(pool)
	repo := kanamepg.New(pool, nil)
	role := catalogRole(t, ctx, pool, "wd76")

	const (
		doomedName    = "wd76doomed"
		rolledBackTwo = "wd76rollback"
		keptName      = "wd76kept"
	)
	// ТОЧЕЧНОЕ имя строки каталога — `модуль.ИМЯ РЕСУРСА`, и именно им адресуются
	// проекции роли (`role_verb.object_type` → `catalog_resource(dotted, live)`).
	// Имя типа объекта манифеста (`probemod_wd76doomed`) — ДРУГОЙ словарь, и
	// подставленное сюда оно дало бы ключу строку, которой нет: отказ был бы
	// громким, но о фикстуре, а не о предмете.
	doomed := applierProbeModule + "." + doomedName
	second := applierProbeModule + "." + rolledBackTwo
	kept := applierProbeModule + "." + keptName

	// ── §0. ПРЕДПОСЫЛКА ────────────────────────────────────────────────────
	//
	// Три ресурса заводятся ОДНИМ применением, потом сужающий манифест снимает
	// первый. Второй нужен §3: у отката обязан быть СВОЙ предмет — снятое в §1
	// снято насовсем, и повтор отбирал бы пустоту.
	rep, err := boot.Apply(ctx, probeManifest(
		probeResource(doomedName, "get"),
		probeResource(rolledBackTwo, "get"),
		probeResource(keptName, "get"),
	))
	require.NoError(t, err, "заведение ресурсов пробы отвергнуто: %s", rep)
	require.Truef(t, rep.Changed(), "каталог не изменился — отбирать будет нечего: %s", rep)

	// Роль получает ВСЕ ТРИ проекции на снимаемый тип: событие приходится на
	// РОЛЬ, а строки она набирает в каждой популяции. Одна популяция не показала
	// бы, что событие не удваивается.
	require.NoError(t, writeRuleRefs(t, ctx, repo, role, []domain.RoleRuleRef{
		{Module: applierProbeModule, Resource: doomedName, Verb: "get"},
		{Module: applierProbeModule, Resource: rolledBackTwo, Verb: "get"},
	}), "объявления правила не записаны — ПЕРВАЯ популяция была бы беспредметна")
	writeRoleVerbsAt(t, ctx, pool, role, doomed, second, kept)
	require.NoError(t, writeSelector(ctx, pool, role, "fp-wd76-a", []string{doomed, kept}),
		"селектор не записан — ТРЕТЬЯ популяция была бы беспредметна")
	require.NoError(t, writeSelector(ctx, pool, role, "fp-wd76-b", []string{second, kept}),
		"то же для предмета отката")

	// ── §1. ПОЛОЖИТЕЛЬНЫЙ: отобрано ⇒ подписчик извещён, и РОВНО ОДИН раз ──
	mark := journalMark(t, ctx, pool)
	rep, err = boot.Apply(ctx, probeManifest(
		probeResource(rolledBackTwo, "get"),
		probeResource(keptName, "get"),
	))
	require.NoError(t, err, "сужающее применение отвергнуто: %s", rep)
	t.Logf("перепись применения: %s", rep)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ПРЕДПОСЫЛКИ: отобрано и вправду, причём всеми тремя
	// популяциями. Без него «одно событие» зеленело бы там, где отбирать нечего.
	require.Positivef(t, rep.Resettled.RuleRefs, "первая популяция не двинулась: %s", rep)
	require.Positivef(t, rep.Resettled.RoleVerbs, "вторая популяция не двинулась: %s", rep)
	require.Positivef(t, rep.PrunedSelectorTypes, "третья популяция не двинулась: %s", rep)

	require.Equalf(t, 1, rep.AnnouncedRoleWithdrawals,
		"перепись применения обязана назвать РОВНО одну роль, у которой отобрано: "+
			"роль одна, популяций три, и событие приходится на роль, а не на строку. "+
			"%s", rep)

	events := roleEventsSince(t, ctx, pool, string(role), mark)
	require.Equalf(t, []string{"UPDATED"}, events,
		"подписчик обязан получить РОВНО одно событие `iam_role` `UPDATED` на роль и "+
			"транзакцию. Ноль означает, что право отобрано МОЛЧА (это и есть #76); "+
			"больше одного — что три популяции объявили отзыв порознь, и подписчик "+
			"перечитывает роль трижды на одно применение")

	// ── §2. ОТРИЦАТЕЛЬНЫЙ: отбирать было нечего ⇒ события нет ──────────────
	//
	// Тот же манифест вторым заходом: снимать больше нечего. Без этой половины
	// §1 зеленела бы и у объявления, которое эмитит на КАЖДОМ применении.
	mark = journalMark(t, ctx, pool)
	rep, err = boot.Apply(ctx, probeManifest(
		probeResource(rolledBackTwo, "get"),
		probeResource(keptName, "get"),
	))
	require.NoError(t, err, "повторное применение отвергнуто: %s", rep)
	require.Falsef(t, rep.Changed(), "второе применение подряд изменило каталог: %s", rep)
	require.Zerof(t, rep.AnnouncedRoleWithdrawals,
		"объявлен отзыв, которого не было: %s", rep)
	require.Emptyf(t, roleEventsSince(t, ctx, pool, string(role), mark),
		"холостое применение родило событие: подписчик перечитывает роль, у которой "+
			"ничего не отобрано, и отличить настоящий отзыв от шума ему станет нечем")

	// ── §3. ОТКАТ: событие лежит в ТОЙ ЖЕ транзакции, что и отобранное ─────
	//
	// Утверждается ПАРА, и порознь ни одна половина не достаточна: «журнал пуст»
	// зеленел бы и у объявления, которое не зовут вовсе, а «проекции целы» — у
	// эмиссии после коммита.
	mark = journalMark(t, ctx, pool)
	verbsBefore := roleVerbRowsOf(t, ctx, pool, string(role))
	require.Positive(t, verbsBefore,
		"у роли не осталось выдач — откатывать было бы нечего, и §3 стала бы вакуумной")

	rows := []catalog.ResourceRow{{
		Module:     applierProbeModule,
		Resource:   rolledBackTwo,
		ObjectType: applierProbeModule + "_" + rolledBackTwo,
	}}
	errRolledBack := errors.New("откат намеренный: предмет §3 — транзакционность объявления")
	rerr := writeRepo.RunInWriteTx(ctx, func(ctx context.Context, w modulecatalog.CatalogWriter) error {
		resettled, serr := w.ResettleTenantProjections(ctx, rows, nil, "проба отката", "probe-wd76")
		if serr != nil {
			return serr
		}
		pruned, perr := w.PruneRetiredSelectorTypes(ctx, rows, "probe-wd76")
		if perr != nil {
			return perr
		}
		withdrawnFrom := append(append([]string(nil), resettled.Roles...), pruned.Roles...)
		if len(withdrawnFrom) == 0 {
			return errors.New("ПРЕДПОСЫЛКА §3: отобрать было нечего — откатывать нечего тоже")
		}
		announced, aerr := w.AnnounceRoleGrantWithdrawal(ctx, withdrawnFrom)
		if aerr != nil {
			return aerr
		}
		if announced != 1 {
			return errors.New("объявление внутри транзакции не дало ровно одного события")
		}
		return errRolledBack
	})
	require.ErrorIs(t, rerr, errRolledBack,
		"транзакция §3 завершилась не нашим отказом — предмет отката подменён чужим")

	require.Emptyf(t, roleEventsSince(t, ctx, pool, string(role), mark),
		"событие пережило ОТКАТ: подписчик извещён об отзыве, которого не было. "+
			"Это и означает, что объявление лежит не в транзакции предмета")
	require.Equalf(t, verbsBefore, roleVerbRowsOf(t, ctx, pool, string(role)),
		"откат не вернул выдач: ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ §3 нарушен — «журнал пуст» "+
			"выполнилось бы и потому, что отбирать было нечего")
}

// ─────────────────────────────────────────────────────────────────────────────
// Помощники набора

// journalMark — верхняя граница журнала НА МИГ ЗАМЕРА.
//
// Водяной знак, а не очистка таблицы: фикстура пробы (человек, аккаунт, роль)
// сама рождает события, и `TRUNCATE` унёс бы заодно чужие — то есть проба стала
// бы писателем состояния, которого не заводила.
func journalMark(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var mark int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT coalesce(max(sequence_no), 0) FROM kaname.resource_journal`).Scan(&mark))
	return mark
}

// roleEventsSince — РОДА изменения, пришедшие подписчику про эту роль после
// знака, по возрастанию номера.
//
// Отдаются слова, а не число: «одно событие» не говорит, правка это или снятие,
// а подписчик на снятии убирает предмет у себя. Проба, знающая лишь мощность,
// зеленела бы на `DELETED` — то есть на извещении, по которому арендатор снёс бы
// живую роль.
func roleEventsSince(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	roleID string, mark int64) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `
		SELECT event_type FROM kaname.resource_journal
		 WHERE resource_kind = 'iam_role' AND resource_id = $1 AND sequence_no > $2
		 ORDER BY sequence_no`, roleID, mark)
	require.NoError(t, err)
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ev string
		require.NoError(t, rows.Scan(&ev))
		out = append(out, ev)
	}
	require.NoError(t, rows.Err())
	return out
}

// roleVerbRowsOf — выдач глаголов у роли. Вторая половина §3: без неё «журнал
// пуст» неотличимо от «отбирать было нечего».
func roleVerbRowsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_verb WHERE role_id = $1`, roleID).Scan(&n))
	return n
}
