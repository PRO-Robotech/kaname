// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// ledgers_name_the_author_integration_test.go — обе ведомости, объясняющие
// потерю права, называют АВТОРА снятия (задача продукта #2005).
//
// # Предмет
//
// Причина и момент у арендатора были: ведомости несут `reason`/`retired_reason` и
// `orphaned_at`/`pruned_at`. Не было ТОГО, КТО СНЯЛ. Для разбора «почему у меня
// отобрали право» это второй по важности вопрос после «почему», и ответить на
// него было неоткуда: применение отбирает права необратимо, а следа автора не
// оставалось ни в одной строке.
//
// # Почему автор — ИНИЦИАТОР, а не служебная учётка исполнителя
//
// Применение уже разрешает актора ПЕРВЫМ действием, до чтения манифеста и до
// открытия транзакции (`modulecatalog.actorOf`): на пути глагола это проверенная
// личность вызывающего, на пути старта — названный процессный актор. Записать
// сюда учётку, под которой исполнялась транзакция, значило бы ответить «снял
// iam» на вопрос «кто снял» — то есть не ответить.
//
// # Почему проба утверждает ДВА применения, а не одно
//
// Одно применение даёт одного автора, и утверждение «автор записан» зеленело бы
// у писателя, вписывающего КОНСТАНТУ. Различить константу и настоящего актора
// можно только вторым применением от ДРУГОГО субъекта: тогда у строк разные
// авторы, и каждая названа своим.
//
// # Почему обе ведомости в одной пробе
//
// Они наполняются ОДНИМ применением и разными операторами. Проба на одну из них
// зеленела бы при второй, оставшейся без автора, — а вопрос «кто снял» у них
// общий: арендатор не различает, какой из трёх проекций лишился.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/modulecatalog"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// ledgerAuthorProbeSubjects — два РАЗНЫХ инициатора.
//
// Значения отличимы от настоящих намеренно: правдоподобный крокфордов
// идентификатор совпал бы с чужим, и проба разбиралась бы как дефект применения.
var ledgerAuthorProbeSubjects = [2]operations.Principal{
	{Type: "user", ID: "usr-probe-ledger-author-first", DisplayName: "первый инициатор снятия"},
	{Type: "user", ID: "usr-probe-ledger-author-second", DisplayName: "второй инициатор снятия"},
}

// orphanAuthorsOf — авторы строк ведомости ПЕРЕСЕЛЕНИЯ у одной роли, по типу
// объекта, плюс ОБЪЁМ ОСМОТРЕННОГО по всей таблице.
//
// Две величины, а не одна: «у этой роли строк столько» не отличает «ведомость
// пуста» от «ведомость не читается».
func orphanAuthorsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	role string) (map[string]string, int) {
	t.Helper()
	var total int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_grant_orphan`).Scan(&total))

	rows, err := pool.Query(ctx, `
		SELECT object_type, applied_by
		  FROM kacho_iam.role_grant_orphan
		 WHERE role_id = $1
		 ORDER BY object_type`, role)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var objectType, author string
		require.NoError(t, rows.Scan(&objectType, &author))
		out[objectType] = author
	}
	require.NoError(t, rows.Err())
	return out, total
}

// prunedAuthorsOf — то же для ведомости ВЫРЕЗАНИЯ.
func prunedAuthorsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	role string) (map[string]string, int) {
	t.Helper()
	var total int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_selector_prune`).Scan(&total))

	rows, err := pool.Query(ctx, `
		SELECT object_type, applied_by
		  FROM kacho_iam.role_selector_prune
		 WHERE role_id = $1
		 ORDER BY object_type`, role)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var objectType, author string
		require.NoError(t, rows.Scan(&objectType, &author))
		out[objectType] = author
	}
	require.NoError(t, rows.Err())
	return out, total
}

// TestBothLedgersNameTheApplyingAuthor — ПЕРВАЯ половина: автор, записанный
// применением, есть тот актор, которого применение разрешило.
//
// Полоса СТАРТА: её актор — названный процессный, и он проверяем без личности в
// контексте. Полоса ГЛАГОЛА здесь не берётся намеренно — см. вторую половину.
func TestBothLedgersNameTheApplyingAuthor(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	boot := applierOver(t, pool)
	role := catalogRole(t, ctx, pool, "led2005")

	const doomed = applierProbeModule + ".led2005boot"
	const kept = applierProbeModule + ".led2005kept"

	// ── ПРЕДПОСЫЛКА: у этой роли обе ведомости пусты, а таблицы читаются ──────
	o0, ot0 := orphanAuthorsOf(t, ctx, pool, string(role))
	p0, pt0 := prunedAuthorsOf(t, ctx, pool, string(role))
	t.Logf("ДО: переселение всего %d · у роли %d; вырезание всего %d · у роли %d",
		ot0, len(o0), pt0, len(p0))
	require.Emptyf(t, o0, "у свежей роли ведомость переселения непуста (%v) — "+
		"всё, что проба измерит дальше, смешано с чужим", o0)
	require.Empty(t, p0, "то же у ведомости вырезания")

	// ── ВХОД ─────────────────────────────────────────────────────────────────
	rep, err := boot.Apply(ctx, probeManifest(
		probeResource("led2005boot", "get"),
		probeResource("led2005kept", "get"),
	))
	require.NoError(t, err)
	require.Truef(t, rep.Changed(), "заведение ресурсов обязано изменить каталог: %s", rep)

	// Обе популяции: применение обязано наполнить ОБЕ ведомости, иначе проба
	// утверждала бы про одну.
	writeRoleVerbsAt(t, ctx, pool, role, doomed)
	require.NoError(t, writeSelector(ctx, pool, role, "fp-led2005-boot", []string{doomed, kept}))

	// ── ПРИМЕНЕНИЕ ───────────────────────────────────────────────────────────
	gone, err := boot.Apply(ctx, probeManifest(probeResource("led2005kept", "get")))
	require.NoErrorf(t, err, "применение отвергнуто: %v", err)
	require.Positivef(t, gone.RetiredResources,
		"применение ничего не сняло (%s) — вход не произведён, и всё ниже вакуумно", gone)

	// ── ИСХОД ────────────────────────────────────────────────────────────────
	orphans, ot1 := orphanAuthorsOf(t, ctx, pool, string(role))
	pruned, pt1 := prunedAuthorsOf(t, ctx, pool, string(role))
	t.Logf("ПОСЛЕ: переселение всего %d · у роли %d %v; вырезание всего %d · у роли %d %v",
		ot1, len(orphans), orphans, pt1, len(pruned), pruned)

	got, ok := orphans[doomed]
	require.Truef(t, ok, "ведомость переселения не несёт строки про %s: %v — "+
		"вход не произведён, и утверждение об авторе беспредметно", doomed, orphans)
	require.Equalf(t, modulecatalog.BootActorID, got,
		"переселение записало автора %q, а применение шло под актором %q.\n"+
			"Автор обязан быть ИНИЦИАТОРОМ применения, снявшего строку, — иначе на вопрос "+
			"«кто у меня отобрал» ведомость отвечает «не тот»", got, modulecatalog.BootActorID)

	gotPruned, ok := pruned[doomed]
	require.Truef(t, ok, "ведомость вырезания не несёт строки про %s: %v", doomed, pruned)
	require.Equalf(t, modulecatalog.BootActorID, gotPruned,
		"вырезание записало автора %q вместо %q", gotPruned, modulecatalog.BootActorID)

	// Пустая строка означала бы «строка записана ДО заведения колонки» — то есть
	// что применение автора не проставило вовсе. Утверждается отдельно: равенство
	// выше поймало бы это только потому, что процессный актор непуст, а у полосы
	// глагола такого совпадения нет.
	require.NotEmpty(t, got, "автор пуст: применение не проставило его вовсе")
	require.NotEmpty(t, gotPruned, "то же у ведомости вырезания")
}

// TestLedgerAuthorFollowsTheApplierNotAConstant — ВТОРАЯ половина: автор следует
// ПРИМЕНЕНИЮ, а не вписан константой.
//
// # Почему предмет проверяется у ПИСАТЕЛЯ, а не двумя применениями
//
// Двух применений с РАЗНЫМИ акторами на этом дереве не построить: актор полосы
// старта — константа платформы, а полоса глагола сверяет опору паритета ГЛОБАЛЬНО
// и на этой базе отвергает применение ещё до записи (проверено: соседняя проба
// пути глагола `TestApplyConfirmsTheStateItWasPlannedAgainst` красна и БЕЗ этой
// правки — предмет чужой, заведён отдельно).
//
// Поэтому «разные субъекты — разные авторы» утверждается на ТЕХ ЖЕ операторах,
// которыми пишет применение, вызванных напрямую с разными акторами. Это ровно тот
// шов, на котором свойство и живёт: значение приходит ПАРАМЕТРОМ, и вписать его
// константой можно было бы только в самом операторе.
//
// Граница названа честно: половина «актор, приходящий сюда, есть инициатор»
// проверяется ПЕРВОЙ пробой, а не этой. Порознь ни одна из двух не достаточна.
func TestLedgerAuthorFollowsTheApplierNotAConstant(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	boot := applierOver(t, pool)
	repo := kachopg.NewCatalogWriteRepo(pool)
	role := catalogRole(t, ctx, pool, "led2005two")

	const firstDoomed = applierProbeModule + ".led2005a"
	const secondDoomed = applierProbeModule + ".led2005b"
	const kept = applierProbeModule + ".led2005keep2"

	rep, err := boot.Apply(ctx, probeManifest(
		probeResource("led2005a", "get"),
		probeResource("led2005b", "get"),
		probeResource("led2005keep2", "get"),
	))
	require.NoError(t, err)
	require.Truef(t, rep.Changed(), "заведение ресурсов обязано изменить каталог: %s", rep)

	writeRoleVerbsAt(t, ctx, pool, role, firstDoomed, secondDoomed)
	require.NoError(t, writeSelector(ctx, pool, role, "fp-led2005-a", []string{firstDoomed, kept}))
	require.NoError(t, writeSelector(ctx, pool, role, "fp-led2005-b", []string{secondDoomed, kept}))

	first, second := ledgerAuthorProbeSubjects[0].ID, ledgerAuthorProbeSubjects[1].ID
	require.NotEqual(t, first, second,
		"ПРЕДПОСЫЛКА: акторы обязаны различаться, иначе «разные авторы» выполняется "+
			"у писателя, вписывающего константу")

	// Каждое снятие — СВОЯ транзакция и СВОЙ актор: у применения они тоже разные
	// транзакции, и общая смешала бы два автора в одном снимке.
	retire := func(resource, objectType, author string) {
		t.Helper()
		rows := []catalog.ResourceRow{{
			Module: applierProbeModule, Resource: resource, ObjectType: objectType,
		}}
		require.NoError(t, repo.RunInWriteTx(ctx,
			func(ctx context.Context, w modulecatalog.CatalogWriter) error {
				// Строка каталога НЕ снимается, и это не упрощение: предмет пробы —
				// колонка автора, а оба оператора ведомости работают от ПЕРЕДАННОГО
				// списка снимаемого, а не от признака живости. Сняв строку, проба
				// потащила бы за собой весь порядок снятия каталога (глаголы прежде
				// ресурса, выдачи прежде глаголов) — то есть повторила бы применение
				// целиком и отказала бы по чужому ключу, ничего не сказав об авторе.
				if _, rerr := w.ResettleTenantProjections(ctx, rows, nil, "проба автора", author); rerr != nil {
					return rerr
				}
				_, perr := w.PruneRetiredSelectorTypes(ctx, rows, author)
				return perr
			}))
	}
	retire("led2005a", "probemod_led2005a", first)
	retire("led2005b", "probemod_led2005b", second)

	orphans, ot := orphanAuthorsOf(t, ctx, pool, string(role))
	pruned, pt := prunedAuthorsOf(t, ctx, pool, string(role))
	t.Logf("переселение всего %d · у роли %v; вырезание всего %d · у роли %v",
		ot, orphans, pt, pruned)

	for _, c := range []struct {
		ledger  string
		got     map[string]string
		subject string
		author  string
	}{
		{"переселения", orphans, firstDoomed, first},
		{"переселения", orphans, secondDoomed, second},
		{"вырезания", pruned, firstDoomed, first},
		{"вырезания", pruned, secondDoomed, second},
	} {
		got, ok := c.got[c.subject]
		require.Truef(t, ok, "ведомость %s не несёт строки про %s: %v",
			c.ledger, c.subject, c.got)
		require.Equalf(t, c.author, got,
			"ведомость %s: строку про %s снял %q, а записан %q — автор не следует снятию",
			c.ledger, c.subject, c.author, got)
	}

	// ── ОТРИЦАНИЕ: авторы РАЗНЫЕ, а не один на обе строки ───────────────────
	//
	// Без него четыре утверждения выше зеленели бы у писателя, вписывающего
	// последнего актора во ВСЕ строки роли.
	require.NotEqualf(t, orphans[firstDoomed], orphans[secondDoomed],
		"обе строки переселения записаны одним автором %q: значит автор проставляется "+
			"задним числом всей роли, а не следует СНЯТИЮ", orphans[firstDoomed])
	require.NotEqualf(t, pruned[firstDoomed], pruned[secondDoomed],
		"то же у ведомости вырезания: один автор %q на обе строки", pruned[firstDoomed])
}

// writeRoleVerbsAt кладёт выдачи глаголов на названные точечные типы.
//
// Своя, а не общая с соседями: те кладут по СВОЕМУ набору типов, и общая
// связала бы две пробы одной строкой.
func writeRoleVerbsAt(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	role domain.RoleID, objectTypes ...string) {
	t.Helper()
	for _, ot := range objectTypes {
		_, err := pool.Exec(ctx, `
			INSERT INTO kacho_iam.role_verb (role_id, object_type, verb)
			VALUES ($1, $2, 'get')
			ON CONFLICT DO NOTHING`, string(role), ot)
		require.NoErrorf(t, err, "выдача глагола на %s не записана — "+
			"ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: без неё переселять будет нечего", ot)
	}
}
