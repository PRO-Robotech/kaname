// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// pruned_selectors_are_readable_integration_test.go — у ведомости ВЫРЕЗАННОГО
// появился путь чтения (задача продукта #1988, вторая половина).
//
// # Что было неверно
//
// Ведомость `role_selector_prune` завелась и наполняется применителем каталога
// тем же оператором, что вырезает, — а ЧИТАЛ её ноль прод-мест:
//
//	git grep -c 'FROM kacho_iam.role_selector_prune' \
//	  -- 'services/iam/**/*.go' ':!*_test.go'   → 0
//
// Это ровно тот класс, ради которого заводилась ведомость СОСЕДНЯЯ: «значение,
// которое пишут и не читают». У переселения он был найден и закрыт (#1992,
// `role_grant_orphan` → `Role.withdrawn_grants`); у вырезания остался. Задача
// #1988 просит ведомость «ПО ОБРАЗЦУ ведомости переселения», а у образца путь
// чтения теперь есть — значит и здесь он часть предмета, а не соседняя работа.
//
// Со стороны арендатора цена та же: его правило перестало отбирать тип, своей
// роли он не менял, и «отобрали» неотличимо от «не было».
//
// # Что утверждается — пара, обе стороны
//
// У роли, чей отбор урезало снятие строки каталога, вырезанное ЧИТАЕТСЯ и несёт
// тип, исход строки, причину и момент; у роли, ничего не терявшей, ключа в
// ответе НЕТ. Без второй половины утверждение зеленело бы на реализации,
// возвращающей одно и то же всем.
//
// # Почему отпечаток правила НАРУЖУ не едет — и что из этого следует
//
// `rule_fp` — ключ ХРАНЕНИЯ, содержательный хеш правила; в контрактах платформы
// он не выставлен ни разу. Выставь мы его — способ хеширования стал бы частью
// контракта, а арендатору он не даёт ничего: своё правило он знает содержанием,
// а не нашим дайджестом.
//
// Следствие названо прямо, а не умолчано: две строки ведомости, различавшиеся
// ТОЛЬКО отпечатком, для читающего есть ОДИН факт и произносятся ОДИН раз.
// Отдай мы их как есть — арендатор увидел бы пару неотличимых записей и прочёл
// бы её как дефект. Это утверждается отдельной пробой ниже, потому что решение
// принято здесь, а не унаследовано.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// prunedByReading — вырезанное у роли, прочитанное ЧЕРЕЗ ПОРТ.
//
// Отдаёт ВЕСЬ ответ, а не только срез спрошенной роли, и здесь же утверждает,
// что чужих ключей в нём нет. Утверждение стоит в помощнике намеренно: оно
// нужно КАЖДОМУ вызывающему, а срез спрошенной роли его не выражает —
// `got[role]` остаётся верным и у читателя, который сузить по роли ЗАБЫЛ, потому
// что ключом карты служит `role_id` строки. Инъекция это и показала: снятие
// сужения не покраснило ничего, пока проба смотрела только на свой срез.
//
// Цена такого читателя не косметическая: он читает ведомость ЦЕЛИКОМ на каждой
// странице — стоимость перестаёт следовать странице и начинает следовать
// популяции, а в памяти оказываются строки чужих ролей.
func prunedByReading(
	t *testing.T, ctx context.Context, repo kachorepo.Repository, role domain.RoleID,
) ([]domain.PrunedSelectorType, int) {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err, "открыть транзакцию чтения")
	defer func() { _ = rd.Rollback(ctx) }()

	got, err := rd.Roles().PrunedSelectorTypes(ctx, []domain.RoleID{role})
	require.NoError(t, err, "путь чтения ведомости вырезанного отказал")

	for id := range got {
		require.Equalf(t, role, id, "ответ несёт ключ роли, которую не спрашивали (%s): "+
			"читатель сужение по роли не применил — он читает ведомость целиком, и "+
			"стоимость следует популяции, а не странице", id)
	}
	return got[role], len(got)
}

// TestPrunedSelectorTypesAreReachableByReading — ВЫРЕЗАННОЕ ЧИТАЕТСЯ.
func TestPrunedSelectorTypesAreReachableByReading(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)
	applier := applierOver(t, pool)

	role := catalogRole(t, ctx, pool, "rd1988")
	const doomed = applierProbeModule + ".rd1988gone"
	const kept = applierProbeModule + ".rd1988kept"

	_, err := applier.Apply(ctx, probeManifest(
		probeResource("rd1988gone", "get"),
		probeResource("rd1988kept", "get"),
	))
	require.NoError(t, err)

	// Две строки отбора: одна назовёт ТОЛЬКО обречённый тип (её снимут целиком),
	// вторая смешанная (её укоротят). Оба исхода нужны: читающий обязан их
	// различать, а не складывать.
	require.NoError(t, writeSelector(ctx, pool, role, "fp-rd-only", []string{doomed}),
		"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой тип обязан записаться, иначе вырезать нечего")
	require.NoError(t, writeSelector(ctx, pool, role, "fp-rd-mixed", []string{doomed, kept}))

	// ── ПРЕДПОСЫЛКА: до вырезания читать нечего ──────────────────────────────
	before, _ := prunedByReading(t, ctx, repo, role)
	require.Emptyf(t, before, "у роли, ещё ничего не терявшей, прочитано %+v — "+
		"всё, что проба измерит дальше, будет смешано с чужим", before)

	// ── ГЛАГОЛ ────────────────────────────────────────────────────────────────
	gone, err := applier.Apply(ctx, probeManifest(probeResource("rd1988kept", "get")))
	require.NoError(t, err)
	require.Positivef(t, gone.RetiredResources,
		"применитель ресурса не снял (%s) — вход не произведён, и всё ниже вакуумно", gone)
	require.Equalf(t, 2, gone.PrunedSelectorTypes,
		"вырезано не два элемента — по одному из каждой строки отбора (%s)", gone)

	// ── ИСХОД: ПРОЧИТАНО ─────────────────────────────────────────────────────
	after, roles := prunedByReading(t, ctx, repo, role)
	t.Logf("прочитано: ролей в ответе %d · у роли записей %d %+v · вырезано элементов %d",
		roles, len(after), after, gone.PrunedSelectorTypes)

	require.Lenf(t, after, 2, "вырезано %d элементов, прочитано %d — цепочка "+
		"обрывается на пути чтения ровно там, где ведомость и заводилась",
		gone.PrunedSelectorTypes, len(after))

	byOutcome := map[domain.SelectorPruneOutcome]domain.PrunedSelectorType{}
	for _, p := range after {
		byOutcome[p.Outcome] = p
	}

	dropped, ok := byOutcome[domain.SelectorPruneOutcomeDropped]
	require.Truef(t, ok, "строка отбора, снятая ЦЕЛИКОМ, чтением не названа: %+v", after)
	require.Equal(t, doomed, dropped.ObjectType, "прочитан не тот вырезанный тип")

	shortened, ok := byOutcome[domain.SelectorPruneOutcomeShortened]
	require.Truef(t, ok, "УКОРОЧЕННАЯ строка отбора чтением не названа: %+v", after)
	require.Equalf(t, doomed, shortened.ObjectType,
		"прочитан ЖИВОЙ тип: укорочение унесло бы больше, чем сняла платформа")

	// ── ПРИЧИНА И МОМЕНТ доезжают до читающего ───────────────────────────────
	var retiredReason string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT retired_reason FROM kacho_iam.catalog_resource WHERE dotted = $1`,
		doomed).Scan(&retiredReason))
	require.NotEmpty(t, retiredReason,
		"снятая строка каталога причины не несёт — тогда её нечего и доносить")
	for _, p := range after {
		require.Equalf(t, retiredReason, p.Reason,
			"причина у читающего разошлась с причиной снятия строки каталога: %+v", p)
		require.Falsef(t, p.PrunedAt.IsZero(),
			"момент не доехал: «когда отобрали» читающему неизвестно: %+v", p)
	}
}

// TestPrunedSelectorTypesAreAbsentForAnUntouchedRole — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ.
//
// Без него «прочитано две записи» было бы неотличимо от пути чтения, который
// отдаёт одно и то же всякому спрашивающему. Роль здесь берётся из ТОЙ ЖЕ базы,
// где у соседней записи есть: ноль обязан быть свойством роли, а не пустой
// ведомости.
func TestPrunedSelectorTypesAreAbsentForAnUntouchedRole(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)
	applier := applierOver(t, pool)

	hurt := catalogRole(t, ctx, pool, "rd1988hurt")
	calm := catalogRole(t, ctx, pool, "rd1988calm")
	const doomed = applierProbeModule + ".rd1988ctlgone"

	_, err := applier.Apply(ctx, probeManifest(
		probeResource("rd1988ctlgone", "get"),
		probeResource("rd1988ctlstay", "get"),
	))
	require.NoError(t, err)
	require.NoError(t, writeSelector(ctx, pool, hurt, "fp-rd-ctl", []string{doomed}))

	gone, err := applier.Apply(ctx, probeManifest(probeResource("rd1988ctlstay", "get")))
	require.NoError(t, err)
	require.Positivef(t, gone.PrunedSelectorTypes,
		"вырезано ноль (%s) — контроль вакуумен: ведомость пуста у ОБЕИХ ролей", gone)

	got, roles := prunedByReading(t, ctx, repo, hurt)
	require.NotEmptyf(t, got, "ПРЕДПОСЫЛКА КОНТРОЛЯ: у пострадавшей роли не прочитано "+
		"ничего (ролей в ответе %d) — тогда пусто у соседней ничего не доказывает", roles)

	quiet, _ := prunedByReading(t, ctx, repo, calm)
	t.Logf("контроль: у пострадавшей роли %d записей · у нетронутой %d", len(got), len(quiet))
	require.Emptyf(t, quiet, "у роли, ничего не терявшей, прочитано %+v — путь чтения "+
		"отдаёт чужое, и «отобранное» перестало быть свойством роли", quiet)
}

// TestPrunedSelectorTypesCollapseRowsThatDifferOnlyByFingerprint — РЕШЕНИЕ, а не
// унаследованное поведение.
//
// Отпечаток правила наружу не едет (см. шапку файла), поэтому две строки
// ведомости, различавшиеся ТОЛЬКО им, для читающего есть один факт. Отдай мы их
// как есть — арендатор увидел бы пару неотличимых записей об одном типе с одним
// исходом и прочёл бы её как дефект.
//
// Проба ставит ровно этот вход: ДВЕ строки отбора разных правил, обе теряют один
// и тот же тип и обе УКОРАЧИВАЮТСЯ, то есть исход у них совпадает. В ведомости
// строк две, у читающего запись одна.
func TestPrunedSelectorTypesCollapseRowsThatDifferOnlyByFingerprint(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	repo := kachopg.New(pool, nil)
	applier := applierOver(t, pool)

	role := catalogRole(t, ctx, pool, "rd1988dup")
	const doomed = applierProbeModule + ".rd1988dupgone"
	const kept = applierProbeModule + ".rd1988dupkept"

	_, err := applier.Apply(ctx, probeManifest(
		probeResource("rd1988dupgone", "get"),
		probeResource("rd1988dupkept", "get"),
	))
	require.NoError(t, err)

	// Обе строки СМЕШАННЫЕ — значит обе укоротятся, и исход у них совпадёт.
	// Различать их будет ТОЛЬКО отпечаток, который наружу не едет.
	require.NoError(t, writeSelector(ctx, pool, role, "fp-rd-dup-a", []string{doomed, kept}))
	require.NoError(t, writeSelector(ctx, pool, role, "fp-rd-dup-b", []string{doomed, kept}))

	gone, err := applier.Apply(ctx, probeManifest(probeResource("rd1988dupkept", "get")))
	require.NoError(t, err)
	require.Equalf(t, 2, gone.PrunedSelectorTypes,
		"вырезано не два элемента — вход пробы не произведён (%s)", gone)

	var ledger int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_selector_prune WHERE role_id = $1`,
		string(role)).Scan(&ledger))
	require.Equalf(t, 2, ledger, "ПРЕДПОСЫЛКА: в ведомости не две строки, а %d — "+
		"схлопывать нечего, и проба вакуумна", ledger)

	got, _ := prunedByReading(t, ctx, repo, role)
	t.Logf("строк в ведомости %d · записей у читающего %d %+v", ledger, len(got), got)
	require.Lenf(t, got, 1, "две строки, различавшиеся ТОЛЬКО отпечатком, приехали "+
		"читающему двумя неотличимыми записями: %+v", got)
	require.Equal(t, doomed, got[0].ObjectType)
	require.Equal(t, domain.SelectorPruneOutcomeShortened, got[0].Outcome)
}
