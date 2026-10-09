// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// objectprojection_injection_test.go — способность гейта
// `TestObjectProjectionHasOneProducer` упасть и смолчать (NTF3-180 (г) и
// пустой обход). Каждая инъекция — с близнецом, меняющим ОДИН факт; оба
// прогона идут теми же сборщиками и тем же предикатом, что и гейт, на
// синтетике: дерево Go и миграций — во временном каталоге, таблицы и функции —
// в отдельной схеме клона базы.
package repohygiene_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
)

const projInjSchema = "projgate"

// projInjBase — синтетическая проекция с ОДНИМ производителем: функция
// триггера на таблице приёма пишет зеркало, рёбра и голову.
const projInjBase = `
CREATE SCHEMA projgate;
CREATE TABLE projgate.intake (object_id text, generation bigint);
CREATE TABLE projgate.resource_mirror (object_id text PRIMARY KEY, source_version bigint);
CREATE TABLE projgate.resource_parent_edge (object_id text, parent_id text, source_version bigint);
CREATE TABLE projgate.object_head (object_id text PRIMARY KEY, generation bigint);
CREATE FUNCTION projgate.apply_intake() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    -- комментарий: INSERT INTO projgate.resource_mirror здесь не считается
    INSERT INTO projgate.object_head (object_id, generation) VALUES (NEW.object_id, NEW.generation)
        ON CONFLICT (object_id) DO UPDATE SET generation = EXCLUDED.generation
        WHERE object_head.generation < EXCLUDED.generation;
    INSERT INTO projgate.resource_mirror (object_id, source_version) VALUES (NEW.object_id, NEW.generation)
        ON CONFLICT (object_id) DO UPDATE SET source_version = EXCLUDED.source_version;
    DELETE FROM projgate.resource_parent_edge WHERE object_id = NEW.object_id;
    RETURN NULL;
END $$;
CREATE TRIGGER apply_intake AFTER INSERT ON projgate.intake FOR EACH ROW EXECUTE FUNCTION projgate.apply_intake();
`

// projInjDB — клон базы с синтетической схемой и дополнительным SQL.
func projInjDB(t *testing.T, extra string) (context.Context, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("инъекция гейта поднимает Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	_, err = pool.Exec(ctx, projInjBase+extra)
	require.NoError(t, err, "синтетическая схема")
	return ctx, pool
}

// projInjTree — синтетическое дерево: файлы Go и каталог миграций.
func projInjTree(t *testing.T, goFiles map[string]string, sqlFiles map[string]string) (root, migrations string) {
	t.Helper()
	root = t.TempDir()
	for rel, body := range goFiles {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}
	migrations = filepath.Join(root, "internal", "migrations")
	require.NoError(t, os.MkdirAll(migrations, 0o755))
	for name, body := range sqlFiles {
		require.NoError(t, os.WriteFile(filepath.Join(migrations, name), []byte(body), 0o600))
	}
	return root, migrations
}

var projInjTables = []string{"resource_mirror", "resource_parent_edge", "object_head"}

// projInjReader — законный файл сценария использования: читает зеркало, о
// записи говорит только комментарий.
const projInjReader = `package usecase

// Пишет зеркало триггер: INSERT INTO projgate.resource_mirror — не здесь.
const readMirror = "SELECT object_id FROM projgate.resource_mirror WHERE object_id = $1"
`

// projInjWriter — тот же файл, но сценарий пишет зеркало своим запросом.
const projInjWriter = `package usecase

// Пишет зеркало триггер: INSERT INTO projgate.resource_mirror — не здесь.
const readMirror = "SELECT object_id FROM projgate.resource_mirror WHERE object_id = $1"

const writeMirror = ` + "`" + `INSERT INTO
		projgate.resource_mirror (object_id, source_version) VALUES ($1, $2)` + "`" + `
`

const projInjMigration = "-- +goose Up\nCREATE TABLE projgate.other (x int);\n"

func projInjVerdict(t *testing.T, ctx context.Context, pool *pgxpool.Pool, goFiles, sqlFiles map[string]string) []string {
	t.Helper()
	root, migrations := projInjTree(t, goFiles, sqlFiles)
	f := collectProjection(t, ctx, pool, root, migrations, projInjSchema, projInjTables)
	t.Logf("перепись:\n%s", projectionCensus(f))
	return projectionVerdict(f)
}

func requireProjFinding(t *testing.T, findings []string, parts ...string) {
	t.Helper()
	for _, f := range findings {
		hit := true
		for _, p := range parts {
			if !strings.Contains(f, p) {
				hit = false
				break
			}
		}
		if hit {
			return
		}
	}
	t.Fatalf("нет находки, называющей %q; находки: %q", parts, findings)
}

// (г): сценарий использования пишет зеркало своим запросом — красный с файлом
// и строкой. Близнец: тот же файл без записи (запись только триггером) — зелёный.
func TestObjectProjectionGate_UseCaseWriteIsNamedWithFileAndLine(t *testing.T) {
	ctx, pool := projInjDB(t, "")
	sql := map[string]string{"0001_x.sql": projInjMigration}

	red := projInjVerdict(t, ctx, pool, map[string]string{"internal/usecase/register.go": projInjWriter}, sql)
	requireProjFinding(t, red, "internal/usecase/register.go:6", "INSERT INTO", "projgate.resource_mirror", "кода Go")
	require.Len(t, red, 1, "ровно одна находка — запись из кода: %q", red)

	twin := projInjVerdict(t, ctx, pool, map[string]string{"internal/usecase/register.go": projInjReader}, sql)
	require.Empty(t, twin, "близнец: запись только триггером, комментарий о записи — не запись")
}

// Пакеты гейтов не судятся: образец распознавателя в internal/check — не запись.
func TestObjectProjectionGate_GatePackageLiteralIsNotAWrite(t *testing.T) {
	ctx, pool := projInjDB(t, "")
	sql := map[string]string{"0001_x.sql": projInjMigration}
	got := projInjVerdict(t, ctx, pool, map[string]string{
		"internal/usecase/register.go": projInjReader,
		"internal/check/marker.go":     "package check\n\nconst Marker = \"INSERT INTO projgate.resource_mirror\"\n",
	}, sql)
	require.Empty(t, got)

	// Близнец: тот же литерал вне пакета гейтов — запись.
	got = projInjVerdict(t, ctx, pool, map[string]string{
		"internal/usecase/register.go": projInjReader,
		"internal/other/marker.go":     "package other\n\nconst Marker = \"INSERT INTO projgate.resource_mirror\"\n",
	}, sql)
	requireProjFinding(t, got, "internal/other/marker.go:3")
}

// Второй производитель в базе — красный, названы оба. Близнец — один (база).
func TestObjectProjectionGate_SecondProducerIsNamed(t *testing.T) {
	ctx, pool := projInjDB(t, `
CREATE FUNCTION projgate.reconcile_mirror() RETURNS void LANGUAGE sql AS $f$
    UPDATE projgate.resource_mirror SET source_version = source_version + 1
$f$;`)
	got := projInjVerdict(t, ctx, pool, map[string]string{"internal/usecase/register.go": projInjReader},
		map[string]string{"0001_x.sql": projInjMigration})
	requireProjFinding(t, got, "производителей проекции в базе 2", "projgate.apply_intake()", "projgate.reconcile_mirror()")
	requireProjFinding(t, got, "projgate.reconcile_mirror()", "не привязана триггером")

	ctx, pool = projInjDB(t, "")
	twin := projInjVerdict(t, ctx, pool, map[string]string{"internal/usecase/register.go": projInjReader},
		map[string]string{"0001_x.sql": projInjMigration})
	require.Empty(t, twin, "близнец: один производитель, привязан триггером")
}

// Производитель без триггера — красный. Близнец — тот же с триггером (база).
func TestObjectProjectionGate_UnboundProducerIsNamed(t *testing.T) {
	ctx, pool := projInjDB(t, `DROP TRIGGER apply_intake ON projgate.intake;`)
	got := projInjVerdict(t, ctx, pool, map[string]string{"internal/usecase/register.go": projInjReader},
		map[string]string{"0001_x.sql": projInjMigration})
	requireProjFinding(t, got, "projgate.apply_intake()", "не привязана триггером")
	require.Len(t, got, 1, "%q", got)
}

// Нет производителя — красный; производитель пишет не все таблицы — красный.
func TestObjectProjectionGate_MissingProducerIsRed(t *testing.T) {
	ctx, pool := projInjDB(t, `DROP TRIGGER apply_intake ON projgate.intake; DROP FUNCTION projgate.apply_intake();`)
	got := projInjVerdict(t, ctx, pool, map[string]string{"internal/usecase/register.go": projInjReader},
		map[string]string{"0001_x.sql": projInjMigration})
	requireProjFinding(t, got, "у проекции нет производителя в базе")

	ctx, pool = projInjDB(t, `
CREATE OR REPLACE FUNCTION projgate.apply_intake() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO projgate.resource_mirror (object_id, source_version) VALUES (NEW.object_id, NEW.generation);
    RETURN NULL;
END $$;`)
	got = projInjVerdict(t, ctx, pool, map[string]string{"internal/usecase/register.go": projInjReader},
		map[string]string{"0001_x.sql": projInjMigration})
	requireProjFinding(t, got, "projgate.object_head", "не пишет")
	requireProjFinding(t, got, "projgate.resource_parent_edge", "не пишет")
}

// Заполнение миграцией вне функции — красный с файлом и строкой. Близнец —
// тот же оператор в теле функции (его судит база) и в комментарии/строке.
func TestObjectProjectionGate_MigrationBackfillIsNamed(t *testing.T) {
	ctx, pool := projInjDB(t, "")
	goFiles := map[string]string{"internal/usecase/register.go": projInjReader}

	got := projInjVerdict(t, ctx, pool, goFiles, map[string]string{
		"0002_backfill.sql": "-- +goose Up\nINSERT INTO kaname_placeholder.x VALUES (1);\n" +
			"INSERT INTO projgate.resource_mirror (object_id, source_version)\n  SELECT object_id, 1 FROM projgate.intake;\n",
	})
	requireProjFinding(t, got, "0002_backfill.sql:3", "INSERT INTO", "projgate.resource_mirror", "миграцией вне функции")

	twin := projInjVerdict(t, ctx, pool, goFiles, map[string]string{
		"0002_backfill.sql": "-- +goose Up\n-- INSERT INTO projgate.resource_mirror в комментарии\n" +
			"COMMENT ON TABLE projgate.intake IS 'INSERT INTO projgate.resource_mirror — пишет триггер';\n" +
			"CREATE FUNCTION projgate.noop() RETURNS void LANGUAGE plpgsql AS $body$ BEGIN RETURN; END $body$;\n" +
			"DO $$ BEGIN PERFORM 1; END $$;\n",
	})
	require.Empty(t, twin, "близнец: вне функций записей нет")
}

// Нет таблицы проекции — красный с её именем.
func TestObjectProjectionGate_MissingTableIsNamed(t *testing.T) {
	ctx, pool := projInjDB(t, `
CREATE OR REPLACE FUNCTION projgate.apply_intake() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO projgate.resource_mirror (object_id, source_version) VALUES (NEW.object_id, NEW.generation);
    DELETE FROM projgate.resource_parent_edge WHERE object_id = NEW.object_id;
    RETURN NULL;
END $$;
DROP TABLE projgate.object_head;`)
	got := projInjVerdict(t, ctx, pool, map[string]string{"internal/usecase/register.go": projInjReader},
		map[string]string{"0001_x.sql": projInjMigration})
	requireProjFinding(t, got, "таблицы projgate.object_head нет")
	require.Len(t, got, 1, "%q", got)
}

// Пустой обход — красный, а не «нарушений нет».
func TestObjectProjectionGate_EmptyWalkIsRed(t *testing.T) {
	ctx, pool := projInjDB(t, "")
	got := projInjVerdict(t, ctx, pool, map[string]string{}, map[string]string{})
	requireProjFinding(t, got, "обход Go пуст")
	requireProjFinding(t, got, "обход миграций пуст")
}
