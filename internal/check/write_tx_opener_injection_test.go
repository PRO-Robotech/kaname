// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// write_tx_opener_injection_test.go — гейт открывающего ловит каждый
// одно-фактный дефект и молчит на законном близнеце той же формы.
//
// Инъекция — синтетический файл, наложенный на настоящий пакет репозитория
// (`packages.Config.Overlay`): типы получателя выводит та же проверка типов,
// что судит дерево, а не подставленный разбор.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const writeOpenerInjPkg = "internal/repo/kaname/pg"

const writeOpenerInjHead = `package pg

import (
	"context"
	"os"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	_ = os.Getenv
	_ pgx.TxOptions
	_ context.Context
	_ *pgxpool.Pool
)

`

func TestWriteOpenerGateInjection(t *testing.T) {
	root := moduleRoot(t)
	tables, _, err := check.JournaledTables(filepath.Join(root, "internal", "migrations"))
	require.NoError(t, err)
	injPath := filepath.Join(root, writeOpenerInjPkg, "zz_write_opener_injection.go")

	cases := []struct {
		name string
		body string
		// want — подстрока находки; пусто — законный близнец, находок ноль.
		want string
	}{
		{name: "control", body: ``},
		{
			name: "W1-pool-begin",
			body: "func zzInj(ctx context.Context, p *pgxpool.Pool) { tx, _ := p.Begin(ctx); _ = tx }\n",
			want: "W1 " + writeOpenerInjPkg + "/zz_write_opener_injection.go:18 Begin",
		},
		{
			name: "W1-twin-read-only",
			body: "func zzInj(ctx context.Context, p *pgxpool.Pool) { tx, _ := p.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly}); _ = tx }\n",
		},
		{
			name: "W1-begin-tx-named-options",
			body: "func zzInj(ctx context.Context, p *pgxpool.Pool) { tx, _ := p.BeginTx(ctx, ceremonyWriterTx()); _ = tx }\n",
			want: "W1 " + writeOpenerInjPkg + "/zz_write_opener_injection.go:18 BeginTx",
		},
		{
			name: "W2-pool-writes-journaled-table",
			body: "func zzInj(ctx context.Context, p *pgxpool.Pool) { _, _ = p.Exec(ctx, `UPDATE users SET labels = $2 WHERE id = $1`) }\n",
			want: "W2 " + writeOpenerInjPkg + "/zz_write_opener_injection.go:18 Exec — оператор \"UPDATE users\"",
		},
		{
			name: "W2-twin-pool-writes-unjournaled-table",
			body: "func zzInj(ctx context.Context, p *pgxpool.Pool) { _, _ = p.Exec(ctx, `UPDATE token_signing_keys SET state = 'X'`) }\n",
		},
		{
			name: "W2-through-parameter",
			body: "func zzInj(ctx context.Context, p *pgxpool.Pool) { zzRun(ctx, p, `DELETE FROM kaname.group_members WHERE group_id = $1`) }\n" +
				"func zzRun(ctx context.Context, p *pgxpool.Pool, q string) { _, _ = p.Exec(ctx, q) }\n",
			want: "W2 " + writeOpenerInjPkg + "/zz_write_opener_injection.go:19 Exec — оператор \"DELETE FROM kaname.group_members\"",
		},
		{
			name: "W3-text-not-derivable",
			body: "func zzInj(ctx context.Context, p *pgxpool.Pool) { _, _ = p.Exec(ctx, os.Getenv(\"Q\")) }\n",
			want: "W3 " + writeOpenerInjPkg + "/zz_write_opener_injection.go:18 Exec",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			overlay := map[string][]byte{injPath: []byte(writeOpenerInjHead + tc.body)}
			sites, census, err := check.ScanWriteOpeners(root, []string{"./" + writeOpenerInjPkg}, tables, overlay)
			require.NoError(t, err)
			require.Positive(t, census.Files, "перепись пуста: инъекция судила бы пустоту")
			var got []string
			for _, s := range sites {
				got = append(got, s.String())
			}
			if tc.want == "" {
				require.Empty(t, got, "законный близнец краснеет")
				return
			}
			require.Len(t, got, 1, "инъекция одного факта обязана дать ровно одну находку: %v", got)
			require.True(t, strings.HasPrefix(got[0], tc.want), "находка %q, ожидалась %q…", got[0], tc.want)
		})
	}
}

// TestJournaledTablesFollowTheMigrationChain — перечень журналируемых таблиц
// выводится из цепи: триггер, снятый поздней миграцией, таблицу из перечня
// уводит; близнец — триггер, снятый на ДРУГОЙ таблице, — нет.
func TestJournaledTablesFollowTheMigrationChain(t *testing.T) {
	const create = `-- +goose Up
CREATE TRIGGER groups_resource_journal_insert_trg AFTER INSERT ON kaname.groups
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_group');
CREATE TRIGGER group_members_resource_journal_trg
  AFTER INSERT OR DELETE ON kaname.group_members
  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit_member('iam_group', 'group_id', 'groups');
-- +goose Down
DROP TRIGGER group_members_resource_journal_trg ON kaname.group_members;
`
	// Закомментированный триггер живым не является.
	const commented = "-- +goose Up\n-- CREATE TRIGGER users_resource_journal_insert_trg AFTER INSERT ON kaname.users\n" +
		"--   FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_user');\n"
	for _, tc := range []struct {
		name, drop string
		want       []string
	}{
		{name: "control", want: []string{"group_members", "groups"}},
		{name: "dropped", drop: "-- +goose Up\nDROP TRIGGER IF EXISTS group_members_resource_journal_trg ON kaname.group_members;\n",
			want: []string{"groups"}},
		{name: "twin-other-table", drop: "-- +goose Up\nDROP TRIGGER group_members_resource_journal_trg ON kaname.users;\n",
			want: []string{"group_members", "groups"}},
		{name: "commented-trigger-is-not-live", drop: commented, want: []string{"group_members", "groups"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, "0001_a.sql"), []byte(create), 0o600))
			if tc.drop != "" {
				require.NoError(t, os.WriteFile(filepath.Join(dir, "0002_b.sql"), []byte(tc.drop), 0o600))
			}
			got, files, err := check.JournaledTables(dir)
			require.NoError(t, err)
			require.Positive(t, files)
			require.Equal(t, tc.want, got)
		})
	}
}

// TestJournaledTablesReadsOnlyInsideTheMigrationsDirectory — файлы цепи
// читаются через корень каталога миграций (os.Root): файл, уводящий чтение за
// каталог (символическая ссылка наружу), отвергается ошибкой, а не читается;
// близнец — ссылка на файл ВНУТРИ каталога — читается.
func TestJournaledTablesReadsOnlyInsideTheMigrationsDirectory(t *testing.T) {
	const create = "-- +goose Up\nCREATE TRIGGER groups_resource_journal_insert_trg AFTER INSERT ON kaname.groups\n" +
		"  FOR EACH ROW EXECUTE FUNCTION kaname.resource_journal_emit('iam_group');\n"
	for _, tc := range []struct {
		name    string
		outside bool
	}{
		{name: "escape-is-refused", outside: true},
		{name: "twin-inside-is-read", outside: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "migrations")
			require.NoError(t, os.Mkdir(dir, 0o700))
			// Ссылки относительные: близнец отличается от инъекции только
			// тем, куда ведёт ссылка, — внутрь каталога или за него.
			link, target := "inner.txt", filepath.Join(dir, "inner.txt")
			if tc.outside {
				link, target = filepath.Join("..", "outside.sql"), filepath.Join(base, "outside.sql")
			}
			require.NoError(t, os.WriteFile(target, []byte(create), 0o600))
			require.NoError(t, os.Symlink(link, filepath.Join(dir, "0001_a.sql")))

			got, files, err := check.JournaledTables(dir)
			if tc.outside {
				require.Error(t, err, "файл за каталогом миграций прочитан: %v", got)
				return
			}
			require.NoError(t, err)
			require.Equal(t, 1, files)
			require.Equal(t, []string{"groups"}, got)
		})
	}
}
