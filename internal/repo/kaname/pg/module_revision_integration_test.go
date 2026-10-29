// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// module_revision_integration_test.go — ПРИМЕНИТЕЛЬ И СХЕМА над живой
// Postgres: редакция манифеста модуля только растёт (kaname#865, приёмка
// `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`,
// сценарии 865-05, 865-06, 865-10, 865-18, 865-25, 865-30, 865-31 и посылка
// `TestPremise865`).
//
// Оператор сравнения-и-записи пары судится здесь, на базе, а не в модульной
// пробе: его условие выражено в `WHERE`, и подставной писатель его не несёт.

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogstate"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

const (
	rev865Module   = "probemod"
	rev865Resource = "boxes"
)

// rev865Doc — R(n, open) фикстуры P11; n == 0 — без ключа `revision`.
func rev865Doc(t *testing.T, n int64, open bool) []byte {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(t, err)
	if !open {
		doc, err = publicreadfixture.WithoutKey(doc)
		require.NoError(t, err)
	}
	if n > 0 {
		doc, err = publicreadfixture.WithRevision(doc, n)
		require.NoError(t, err)
	}
	return doc
}

func rev865Load(t *testing.T, doc []byte) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	return m
}

func rev865R(t *testing.T, n int64, open bool) *manifest.Manifest {
	t.Helper()
	return rev865Load(t, rev865Doc(t, n, open))
}

func rev865Applied(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (*int64, *string) {
	t.Helper()
	return catalogstate.Applied(t, ctx, pool, rev865Module)
}

func rev865I64(n int64) *int64 { return &n }

// TestPremise865_OlderRevisionDoesNotOverwriteNewer — посылка задачи: новая
// редакция (контейнер открыт), затем старая (контейнер закрыт) — строка
// обязана нести значение новой. На дереве до правки (`892853c45`) старая
// редакция перезаписывала новую: признак контейнера — `false`.
func TestPremise865_OlderRevisionDoesNotOverwriteNewer(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	_, err := applier.Apply(ctx, rev865R(t, 5, true))
	require.NoError(t, err)
	_, err = applier.Apply(ctx, rev865R(t, 3, false))
	require.NoError(t, err)
	got := catalogstate.ContainerFlag(t, ctx, pool, rev865Module, rev865Resource)
	t.Logf("порядок 5 → 3: public_read_to_children=%v (новая редакция объявляет true)", got)
	require.True(t, got, "строка каталога несёт значение СТАРОЙ редакции")
}

// Test865_05_FirstApplicationAfterMigration — колонки пусты после миграции;
// первое применение заводит пару, в том числе у модуля без строки.
func Test865_05_FirstApplicationAfterMigration(t *testing.T) {
	ctx, pool := catalogPool(t)
	var seeded, empty int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE applied_revision IS NULL AND applied_digest IS NULL)
		  FROM kaname.catalog_module
		 WHERE module IN ('iam', 'vpc', 'compute', 'loadbalancer', 'registry', 'storage')`).
		Scan(&seeded, &empty))
	require.Equal(t, 6, seeded, "шесть строк посева 0001_initial.sql")
	require.Equal(t, 6, empty, "существующие строки получают обе колонки пустыми: обратного заполнения нет")

	applier := applierOver(t, pool)
	iamDoc, err := publicreadfixture.WithRevision(servicemanifest.Raw(), 3)
	require.NoError(t, err)
	rep, err := applier.Apply(ctx, rev865Load(t, iamDoc))
	require.NoError(t, err)
	require.False(t, rep.Changed(), "манифест самого модуля строк посеянной базы не меняет: %s", rep)
	rev, _ := catalogstate.Applied(t, ctx, pool, "iam")
	require.Equal(t, rev865I64(3), rev)

	rep, err = applier.Apply(ctx, rev865R(t, 2, true))
	require.NoError(t, err)
	require.True(t, rep.ModuleWritten, "строка модуля заведена — это изменение каталога (CE-08)")
	rev, _ = rev865Applied(t, ctx, pool)
	require.Equal(t, rev865I64(2), rev)
}

// rev865Race — две транзакции применителя одновременно над чистой базой.
func rev865Race(t *testing.T, a, b *manifest.Manifest) (modulecatalog.Report, modulecatalog.Report, context.Context, *pgxpool.Pool) {
	t.Helper()
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	var (
		wg         sync.WaitGroup
		start      = make(chan struct{})
		repA, repB modulecatalog.Report
		errA, errB error
	)
	wg.Add(2)
	go func() { defer wg.Done(); <-start; repA, errA = applier.Apply(ctx, a) }()
	go func() { defer wg.Done(); <-start; repB, errB = applier.Apply(ctx, b) }()
	close(start)
	wg.Wait()
	require.NoError(t, errA)
	require.NoError(t, errB)
	return repA, repB, ctx, pool
}

// Test865_06_RaceOfTwoRevisionsEndsOnTheNewer — состязание двух редакций, 20
// повторов на чистой базе.
func Test865_06_RaceOfTwoRevisionsEndsOnTheNewer(t *testing.T) {
	r3, r5 := rev865R(t, 3, false), rev865R(t, 5, true)
	seen := map[string]int{}
	for i := 0; i < 20; i++ {
		rep3, rep5, ctx, pool := rev865Race(t, r3, r5)
		require.True(t, catalogstate.ContainerFlag(t, ctx, pool, rev865Module, rev865Resource), "прогон %d", i)
		rev, _ := rev865Applied(t, ctx, pool)
		require.Equal(t, rev865I64(5), rev, "прогон %d", i)
		pair := rep3.Revision.Outcome.String() + "/" + rep5.Revision.Outcome.String()
		seen[pair]++
		switch {
		case rep3.Revision.Outcome == modulecatalog.RevisionFirst && rep5.Revision.Outcome == modulecatalog.RevisionNewer:
		case rep5.Revision.Outcome == modulecatalog.RevisionFirst && rep3.Revision.Outcome == modulecatalog.RevisionStale:
		default:
			t.Fatalf("прогон %d: исход %s вне двух допустимых пар", i, pair)
		}
	}
	t.Logf("исходы 20 прогонов (3/5): %v", seen)
}

// Test865_10_StaleRevisionLeavesNoTrace — младшая редакция не пишет ни строки
// и не оставляет следа; отчёт называет исход «младшая» с обоими номерами.
func Test865_10_StaleRevisionLeavesNoTrace(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	_, err := applier.Apply(ctx, rev865R(t, 5, true))
	require.NoError(t, err)
	before := catalogstate.Fingerprint(t, ctx, pool)
	traces := catalogstate.AppliedTraces(t, ctx, pool, modulecatalog.AppliedEventType, rev865Module)

	rep, err := applier.Apply(ctx, rev865R(t, 3, false))
	require.NoError(t, err)
	require.Equal(t, before, catalogstate.Fingerprint(t, ctx, pool))
	require.Equal(t, traces, catalogstate.AppliedTraces(t, ctx, pool, modulecatalog.AppliedEventType, rev865Module))
	require.Equal(t, modulecatalog.RevisionStale, rep.Revision.Outcome, "отчёт: %s", rep)
	require.NotNil(t, rep.Revision.Declared)
	require.NotNil(t, rep.Revision.Previous)
	require.EqualValues(t, 3, rep.Revision.Declared.Revision)
	require.EqualValues(t, 5, rep.Revision.Previous.Revision)
}

// Test865_18_ZeroRevisionIsRefusedBySchema — ноль запрещён схемой.
func Test865_18_ZeroRevisionIsRefusedBySchema(t *testing.T) {
	ctx, pool := catalogPool(t)
	_, err := pool.Exec(ctx, `UPDATE kaname.catalog_module
		SET applied_revision = 0, applied_digest = 'sha256:' || repeat('0', 64) WHERE module = 'vpc'`)
	code, constraint := pgCode(err)
	require.Equal(t, "23514", code, "%v", err)
	require.Equal(t, "catalog_module_applied_revision_positive", constraint)

	_, err = pool.Exec(ctx, `UPDATE kaname.catalog_module
		SET applied_revision = 1, applied_digest = 'sha256:' || repeat('0', 64) WHERE module = 'vpc'`)
	require.NoError(t, err, "близнец: номер 1 при законной форме отпечатка проходит")
}

// Test865_30_PairAndFormAreHeldBySchema — связка номера и отпечатка и форма
// отпечатка закреплены схемой.
func Test865_30_PairAndFormAreHeldBySchema(t *testing.T) {
	ctx, pool := catalogPool(t)
	cases := []struct {
		set, constraint string
	}{
		{`applied_revision = 1`, "catalog_module_applied_pair"},
		{`applied_digest = 'sha256:' || repeat('0', 64)`, "catalog_module_applied_pair"},
		{`applied_revision = 1, applied_digest = 'sha256:' || repeat('0', 63)`, "catalog_module_applied_digest_form"},
		{`applied_revision = 1, applied_digest = 'SHA256:' || repeat('0', 64)`, "catalog_module_applied_digest_form"},
	}
	for _, c := range cases {
		_, err := pool.Exec(ctx, `UPDATE kaname.catalog_module SET `+c.set+` WHERE module = 'vpc'`)
		code, constraint := pgCode(err)
		require.Equal(t, "23514", code, "%s: %v", c.set, err)
		require.Equal(t, c.constraint, constraint, c.set)
		rev, digest := catalogstate.Applied(t, ctx, pool, "vpc")
		require.Nil(t, rev, "после отказа %s колонки пусты", c.set)
		require.Nil(t, digest, "после отказа %s колонки пусты", c.set)
	}
	_, err := pool.Exec(ctx, `UPDATE kaname.catalog_module
		SET applied_revision = 1, applied_digest = 'sha256:' || repeat('0', 64) WHERE module = 'vpc'`)
	require.NoError(t, err, "близнец: законная пара проходит")
}

// Test865_25_ReformattedDocumentIsNotAConflict — переформатированный документ
// той же редакции — повтор, а не конфликт.
func Test865_25_ReformattedDocumentIsNotAConflict(t *testing.T) {
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	doc := rev865Doc(t, 5, true)
	m := rev865Load(t, doc)
	_, err := applier.Apply(ctx, m)
	require.NoError(t, err)
	before := catalogstate.Fingerprint(t, ctx, pool)

	ref, err := publicreadfixture.Reformatted(doc)
	require.NoError(t, err)
	mRef := rev865Load(t, ref)
	require.Equal(t, m.Digest(), mRef.Digest())

	census, err := applier.ApplyAll(ctx, []*manifest.Manifest{mRef})
	require.NoError(t, err)
	require.Equal(t, 1, census.Applied)
	require.Empty(t, census.RefusedConflict)
	require.False(t, census.Changed())
	require.Equal(t, before, catalogstate.Fingerprint(t, ctx, pool))
	_, digest := rev865Applied(t, ctx, pool)
	require.NotNil(t, digest, "пара не записана")
	require.Equal(t, m.Digest(), *digest)
}

// Test865_31_RaceOfTwoContentsUnderOneRevision — состязание двух документов
// одной редакции, 20 повторов на чистой базе.
func Test865_31_RaceOfTwoContentsUnderOneRevision(t *testing.T) {
	open, closed := rev865R(t, 5, true), rev865R(t, 5, false)
	seen := map[string]int{}
	for i := 0; i < 20; i++ {
		repOpen, repClosed, ctx, pool := rev865Race(t, open, closed)
		flag := catalogstate.ContainerFlag(t, ctx, pool, rev865Module, rev865Resource)
		_, digest := rev865Applied(t, ctx, pool)
		require.NotNil(t, digest)
		pair := repOpen.Revision.Outcome.String() + "/" + repClosed.Revision.Outcome.String()
		seen[pair]++
		switch {
		case repOpen.Revision.Outcome == modulecatalog.RevisionFirst && repClosed.Revision.Outcome == modulecatalog.RevisionConflict:
			require.True(t, flag, "прогон %d", i)
			require.Equal(t, open.Digest(), *digest, "прогон %d", i)
		case repClosed.Revision.Outcome == modulecatalog.RevisionFirst && repOpen.Revision.Outcome == modulecatalog.RevisionConflict:
			require.False(t, flag, "прогон %d", i)
			require.Equal(t, closed.Digest(), *digest, "прогон %d", i)
		default:
			t.Fatalf("прогон %d: исход %s вне двух допустимых пар", i, pair)
		}
	}
	t.Logf("исходы 20 прогонов (открытый/закрытый): %v", seen)
}

// TestFingerprintSeesEveryColumnTheApplierWrites — отпечаток шести таблиц
// видит КАЖДУЮ колонку, которую пишет применитель и которую называет условие
// CE-18: применённую пару (`applied_revision`, `applied_digest`) строки модуля
// и имя типа, указатели и признак контейнера (`object_type`, `parent_types`,
// `public_read_to_children`) строки ресурса. Каждая колонка меняется ОДНА, от
// состояния после предыдущей: равенство отпечатков, которым пробы утверждают
// «ничего не изменилось», обязано краснеть на любой из них.
//
// Проба держит СОСТАВ отпечатка: снятие любой из пяти колонок из
// `catalogstate.Fingerprint` краснит её строку, называя колонку (CV-865-2:
// проба, менявшая только `applied_digest`, оставалась зелёной при снятом
// `applied_revision`).
func TestFingerprintSeesEveryColumnTheApplierWrites(t *testing.T) {
	ctx, pool := catalogPool(t)
	_, err := applierOver(t, pool).Apply(ctx, rev865R(t, 5, true))
	require.NoError(t, err)

	const (
		moduleRow   = `WHERE module = $1`
		resourceRow = `WHERE module = $1 AND resource = $2`
	)
	cases := []struct {
		column, update string
		args           []any
	}{
		{"catalog_module.applied_revision",
			`UPDATE kaname.catalog_module SET applied_revision = applied_revision + 1 ` + moduleRow,
			[]any{rev865Module}},
		{"catalog_module.applied_digest",
			`UPDATE kaname.catalog_module SET applied_digest = 'sha256:' || repeat('f', 64) ` + moduleRow,
			[]any{rev865Module}},
		{"catalog_module.class_grants_only_on_containers",
			`UPDATE kaname.catalog_module SET class_grants_only_on_containers = NOT class_grants_only_on_containers ` + moduleRow,
			[]any{rev865Module}},
		{"catalog_resource.object_type",
			`UPDATE kaname.catalog_resource SET object_type = object_type || '_probe' ` + resourceRow,
			[]any{rev865Module, rev865Resource}},
		{"catalog_resource.parent_types",
			`UPDATE kaname.catalog_resource SET parent_types = parent_types || 'probe_parent'::text ` + resourceRow,
			[]any{rev865Module, rev865Resource}},
		{"catalog_resource.public_read_to_children",
			`UPDATE kaname.catalog_resource SET public_read_to_children = NOT public_read_to_children ` + resourceRow,
			[]any{rev865Module, rev865Resource}},
	}
	for _, c := range cases {
		before := catalogstate.Fingerprint(t, ctx, pool)
		tag, err := pool.Exec(ctx, c.update, c.args...)
		require.NoError(t, err, c.column)
		require.EqualValues(t, 1, tag.RowsAffected(), "%s: изменена не одна строка — колонка не тронута", c.column)
		require.NotEqual(t, before, catalogstate.Fingerprint(t, ctx, pool),
			"отпечаток не видит колонки %s", c.column)
	}
}

// TestAppliedEditionReaderReadsWhatTheWriterWrote — читатель пары `Get`
// (`CatalogRepo.ReadAppliedEdition`) отдаёт то, что записал оператор
// сравнения-и-записи, и nil у модуля без пары.
func TestAppliedEditionReaderReadsWhatTheWriterWrote(t *testing.T) {
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewCatalogRepo(pool)
	ed, err := repo.ReadAppliedEdition(ctx, "iam")
	require.NoError(t, err)
	require.Nil(t, ed, "посеянная строка без пары — nil, а не нулевая пара")

	m := rev865R(t, 5, true)
	_, err = applierOver(t, pool).Apply(ctx, m)
	require.NoError(t, err)
	ed, err = repo.ReadAppliedEdition(ctx, rev865Module)
	require.NoError(t, err)
	require.Equal(t, &modulecatalog.Edition{Revision: 5, Digest: m.Digest()}, ed)
}
