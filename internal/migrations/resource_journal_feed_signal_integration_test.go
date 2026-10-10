// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package migrations_test

// resource_journal_feed_signal_integration_test.go — журнал подписки принимает
// строку сигнала ленты `notification_feed:kaname` ровно в одной форме
// (`20261010031946_resource_journal_admits_the_feed_signal.sql`; NTF-2 Р1,
// задача PRO-Robotech/kaname#484, полоса G1).
//
// # Производитель входа, а не выписанная строка
//
// Положительный случай пишет НАСТОЯЩИЙ писатель — `feed.JournalSignal`
// фундамента через `subscription.Journal.Emit` в транзакции `journaltx`, с
// именем ленты из `manifest.AccessServiceFeed`. Строка, выписанная рукой,
// доказывала бы, что база принимает строку пробы, а не строку, которую
// постановка письма положит на деле.
//
// # Каждый отказ меняет ОДИН факт против положительного близнеца
//
// Близнец — та же вставка с законной формой, принятая в том же прогоне. Без
// него «отвергнуто 23514» зеленело бы и на ограничении, отвергающем всё.

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/journaltx"
	"github.com/PRO-Robotech/corelib/notify/feed"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/corelib/subscription"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
)

const (
	feedSignalMigration int64 = 20261010031946
	// beforeFeedSignal — старшая миграция цепи до этой. Новая миграция обязана
	// старшинствовать над всеми лежащими (TestNewMigrationOutranksEveryAppliedOne),
	// поэтому между ними не встанет ничего.
	beforeFeedSignal    int64 = 20261008020109
	kindCheck                 = "resource_journal_resource_kind_check"
	feedSignalFormCheck       = "resource_journal_feed_signal_form_check"
)

// feedSignalSchema — схема, накатанная целиком, и DSN той же базы: писатель
// фундамента ходит пулом pgx, а цепь миграций — `database/sql`.
func feedSignalSchema(t *testing.T) (*sql.DB, string) {
	t.Helper()
	dsn := pgtest.NewEmptyDB(t)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.Up(db, "."), "цепь миграций обязана накатиться целиком")
	return db, dsn
}

// journalWithFeedKey — объявление журнала службы, к которому добавлен ключ ленты
// в той форме, которую требует `feed.JournalSignal`. Объявление вида — предмет
// полосы реализации, а не схемы; здесь оно только фикстура писателя.
func journalWithFeedKey() subscription.Journal {
	j := subscriptionjournal.Journal()
	kinds := make(map[string]subscription.Kind, len(j.Mapping.Kinds)+1)
	for k, v := range j.Mapping.Kinds {
		kinds[k] = v
	}
	kinds[feed.JournalKey] = subscription.Kind{
		ObjectType: "notification_feed",
		Action:     "platform.subscription.subscribe",
		NameForm:   subscription.NameFormNone,
		Scope:      subscription.ScopeCluster,
	}
	j.Mapping.Kinds = kinds
	return j
}

// signalThroughTheWriter — строка сигнала, записанная писателем фундамента, и
// его ответ.
func signalThroughTheWriter(t *testing.T, dsn, module string) error {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	sig, err := feed.JournalSignal(journalWithFeedKey(), module, "UPDATED")
	require.NoError(t, err, "фикстура: объявление писателя обязано собраться")

	cctx, err := journaltx.AsComponent(ctx, "kaname", "mail")
	require.NoError(t, err)
	tx, err := journaltx.Begin(cctx, pool, journaltx.NewOptions(true))
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	if err := sig.SignalFeed(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// insertJournalRow — вставка строки журнала одним оператором в транзакции с
// выставленным инициатором; ответ — SQLSTATE и имя ограничения отказа.
type journalRow struct {
	kind, id, project, scope, event string
}

func insertJournalRow(t *testing.T, db *sql.DB, r journalRow) (code, constraint string) {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.ExecContext(ctx, `SELECT set_config($1, 'system:kaname-mail', true)`,
		journaltx.SettingInitiator)
	require.NoError(t, err)
	_, err = tx.ExecContext(ctx, `INSERT INTO kaname.resource_journal
		  (resource_kind, resource_id, project_id, scope, event_type, payload)
		VALUES ($1, $2, $3, $4::jsonb, $5, '{}'::jsonb)`,
		r.kind, r.id, r.project, r.scope, r.event)
	if err == nil {
		require.NoError(t, tx.Commit())
		return "", ""
	}
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "отказ не от базы: %v", err)
	return pgErr.Code, pgErr.ConstraintName
}

// legalSignal — законная форма строки сигнала: положительный близнец каждого
// отказа ниже.
func legalSignal() journalRow {
	return journalRow{kind: feed.JournalKey, id: manifest.AccessServiceFeed,
		project: "", scope: "[]", event: "UPDATED"}
}

// TestResourceJournal_FeedSignalFromTheWriterIsAdmitted — строку, которую кладёт
// писатель фундамента с именем ленты службы, база принимает, и лежит она в той
// форме, которую объявляет миграция.
func TestResourceJournal_FeedSignalFromTheWriterIsAdmitted(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db, dsn := feedSignalSchema(t)

	require.NoError(t, signalThroughTheWriter(t, dsn, manifest.AccessServiceFeed),
		"строку сигнала, которую кладёт постановка письма, база обязана принять: "+
			"иначе при включённом флаге падает каждая постановка")

	var (
		n                                    int
		id, project, scope, event, initiator string
	)
	require.NoError(t, db.QueryRow(`
		SELECT count(*) OVER (), resource_id, project_id, scope::text, event_type, initiator
		  FROM kaname.resource_journal WHERE resource_kind = $1`, feed.JournalKey).
		Scan(&n, &id, &project, &scope, &event, &initiator))
	require.Equal(t, 1, n, "одна постановка — одна строка сигнала")
	require.Equal(t, manifest.AccessServiceFeed, id)
	require.Equal(t, "", project, "лента уровня кластера якоря не несёт")
	require.Equal(t, "[]", scope, "захваченных областей у сигнала нет")
	require.Equal(t, "UPDATED", event)
	require.Equal(t, "system:kaname-mail", initiator,
		"инициатор строки — компонент, открывший транзакцию journaltx")
}

// TestResourceJournal_FeedSignalOfAnotherFeedIsRefused — тот же писатель, имя
// чужой ленты (законная DNS-метка — фундамент её пропускает): отвергает база.
func TestResourceJournal_FeedSignalOfAnotherFeedIsRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	_, dsn := feedSignalSchema(t)

	err := signalThroughTheWriter(t, dsn, "storage")
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "строку чужой ленты база обязана отвергнуть: %v", err)
	require.Equal(t, "23514", pgErr.Code)
	require.Equal(t, feedSignalFormCheck, pgErr.ConstraintName)
}

// TestResourceJournal_FeedSignalFormIsHeldByTheBase — каждое отклонение от
// законной формы меняет ОДИН факт и отвергается `23514` названным ограничением;
// близнец принят в том же прогоне.
func TestResourceJournal_FeedSignalFormIsHeldByTheBase(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db, _ := feedSignalSchema(t)

	code, _ := insertJournalRow(t, db, legalSignal())
	require.Empty(t, code, "положительный близнец: законная форма сигнала принята")

	cases := []struct {
		name       string
		edit       func(*journalRow)
		constraint string
	}{
		{"имя чужой ленты", func(r *journalRow) { r.id = "storage" }, feedSignalFormCheck},
		{"пустое имя ленты", func(r *journalRow) { r.id = "" }, feedSignalFormCheck},
		{"проектный якорь", func(r *journalRow) { r.project = "prj-x" }, feedSignalFormCheck},
		{"захваченная область", func(r *journalRow) {
			r.scope = `[{"type":"account","id":"acc-x"}]`
		}, feedSignalFormCheck},
		{"род CREATED", func(r *journalRow) { r.event = "CREATED" }, feedSignalFormCheck},
		{"род DELETED", func(r *journalRow) { r.event = "DELETED" }, feedSignalFormCheck},
		{"вид вне словаря", func(r *journalRow) { r.kind = "notification_feed" }, kindCheck},
	}
	for _, c := range cases {
		r := legalSignal()
		c.edit(&r)
		code, constraint := insertJournalRow(t, db, r)
		require.Equal(t, "23514", code, "%s: строка обязана быть отвергнута формой", c.name)
		require.Equal(t, c.constraint, constraint, "%s: отвергнута не тем ограничением", c.name)
	}

	// Ограничение формы касается ТОЛЬКО сигнала: строка ресурса с областью,
	// родом CREATED и чужим идентификатором принимается, как прежде.
	code, _ = insertJournalRow(t, db, journalRow{kind: subscriptionjournal.KindGroup,
		id: "grp-feed-twin", project: "", scope: `[{"type":"account","id":"acc-x"}]`, event: "CREATED"})
	require.Empty(t, code, "форма сигнала не вправе касаться остальных видов")
	t.Logf("сверено: отказов %d, принятых близнецов 2", len(cases))
}

// TestResourceJournal_LiveKindDictionaryIsTheOwnersPlusTheFeedKey — словарь
// видов, действующий в базе после всей цепи, есть семь видов владельца и ключ
// ленты фундамента. Читается КАТАЛОГ, а не текст файла: ограничение переставлено
// поздней миграцией, и текст первой больше не есть действующий словарь.
func TestResourceJournal_LiveKindDictionaryIsTheOwnersPlusTheFeedKey(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db, _ := feedSignalSchema(t)

	var def string
	require.NoError(t, db.QueryRow(`
		SELECT pg_get_constraintdef(c.oid) FROM pg_constraint c
		 WHERE c.conrelid = 'kaname.resource_journal'::regclass AND c.conname = $1`,
		kindCheck).Scan(&def))
	var live []string
	for _, m := range regexp.MustCompile(`'([a-z_]+)'::text`).FindAllStringSubmatch(def, -1) {
		live = append(live, m[1])
	}
	sort.Strings(live)
	require.NotEmpty(t, live, "перепись словаря пуста: прочитано не то ограничение")

	// Множество, а не список: когда объявление владельца само назовёт ключ
	// ленты, слово не должно считаться дважды.
	set := map[string]bool{feed.JournalKey: true}
	for k := range subscriptionjournal.Journal().Mapping.Kinds {
		set[k] = true
	}
	want := make([]string, 0, len(set))
	for k := range set {
		want = append(want, k)
	}
	sort.Strings(want)
	require.Equal(t, want, live)
}

// TestResourceJournal_FeedSignalMigrationRollsBack — обратный шаг возвращает
// словарь из семи видов; повторный прямой шаг — снова восемь. Обратный шаг при
// лежащей строке сигнала отказывает, а не теряет её.
func TestResourceJournal_FeedSignalMigrationRollsBack(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db, _ := feedSignalSchema(t)

	require.NoError(t, goose.DownTo(db, ".", beforeFeedSignal))
	code, constraint := insertJournalRow(t, db, legalSignal())
	require.Equal(t, "23514", code, "после отката сигнал вне словаря")
	require.Equal(t, kindCheck, constraint)
	code, _ = insertJournalRow(t, db, journalRow{kind: subscriptionjournal.KindGroup,
		id: "grp-down-twin", scope: "[]", event: "CREATED"})
	require.Empty(t, code, "близнец: семь видов владельца откат не трогает")

	require.NoError(t, goose.UpTo(db, ".", feedSignalMigration))
	code, _ = insertJournalRow(t, db, legalSignal())
	require.Empty(t, code, "после повторного прямого шага сигнал снова принят")

	require.Error(t, goose.DownTo(db, ".", beforeFeedSignal),
		"сужение словаря при лежащей строке сигнала обязано отказать, а не потерять её")
}
