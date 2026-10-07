// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authzrevcolumn_injection_test.go — гейт писателя версии прав доказан
// инъекцией в обе стороны (NTF3-180 (б), (д) и пустое множество таблиц):
// дефект краснеет и называет таблицу (и триггер); законный близнец той же
// формы, отличающийся ОДНИМ фактом, молчит.
//
// Вход синтетический и живёт в пробе: своя схема `arvgate` в своём клоне базы.
// Живые таблицы дерева фикстурой не служат — их снятие не должно ронять
// самопроверку гейта.
package repohygiene_test

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
)

const injSchema = "arvgate"

// injTriggerOK — законная форма: INSERT всегда, UPDATE — только при смене
// значимого столбца `sig`.
const injTriggerOK = `
CREATE FUNCTION arvgate.rev_ok() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  IF TG_OP = 'INSERT' OR NEW.sig IS DISTINCT FROM OLD.sig THEN
    NEW.authz_rev := pg_current_xact_id();
  ELSE
    NEW.authz_rev := OLD.authz_rev;
  END IF;
  RETURN NEW;
END $fn$;`

// injTriggerAnyUpdate — дефект (д): новая версия на ЛЮБОМ UPDATE.
const injTriggerAnyUpdate = `
CREATE FUNCTION arvgate.rev_any() RETURNS trigger LANGUAGE plpgsql AS $fn$
BEGIN
  NEW.authz_rev := pg_current_xact_id();
  RETURN NEW;
END $fn$;`

// injDB — свой клон с пустой схемой пробы и обеими функциями.
func injDB(t *testing.T) (context.Context, *pgxpool.Pool) {
	t.Helper()
	if testing.Short() {
		t.Skip("самопроверка гейта поднимает Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	_, err = pool.Exec(ctx, `CREATE SCHEMA arvgate;`+injTriggerOK+injTriggerAnyUpdate)
	require.NoError(t, err, "фикстура самопроверки: схема пробы не заведена")
	return ctx, pool
}

// injTable — таблица прав пробы: ключ, значимый `sig`, служебный `aux`.
func injTable(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name, revColumn, trigger string) {
	t.Helper()
	ddl := `CREATE TABLE arvgate.` + name + ` (id text NOT NULL, sig text NOT NULL, aux text NOT NULL DEFAULT ''` + revColumn + `);`
	if trigger != "" {
		ddl += ` CREATE TRIGGER ` + name + `_rev BEFORE INSERT OR UPDATE ON arvgate.` + name +
			` FOR EACH ROW EXECUTE FUNCTION arvgate.` + trigger + `();`
	}
	_, err := pool.Exec(ctx, ddl)
	require.NoErrorf(t, err, "фикстура самопроверки: таблица %s не заведена", name)
}

// verdictOf — вердикт гейта на схеме пробы, с переписью.
func verdictOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []string {
	t.Helper()
	revs := judgeRevisioned(t, ctx, pool, injSchema)
	t.Logf("перепись самопроверки:\n%s", revisionCensus(revs))
	return revisionVerdict(revs)
}

func requireFindingNames(t *testing.T, findings []string, parts ...string) {
	t.Helper()
	for _, f := range findings {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(f, p)
		}
		if ok {
			return
		}
	}
	t.Fatalf("находки, называющей %q, нет; находки:\n  · %s", parts, strings.Join(findings, "\n  · "))
}

// (б) колонка задана умолчанием без триггера — красный с именем таблицы;
// близнец — триггер — зелёный.
func TestAuthzRevisionGate_B_DefaultWithoutTriggerIsNamed(t *testing.T) {
	ctx, pool := injDB(t)
	injTable(t, ctx, pool, "rights_a", ", authz_rev xid8 DEFAULT pg_current_xact_id()", "")
	f := verdictOf(t, ctx, pool)
	requireFindingNames(t, f, "rights_a", "умолчание")
	requireFindingNames(t, f, "rights_a", "BEFORE INSERT OR UPDATE")

	ctx2, pool2 := injDB(t)
	injTable(t, ctx2, pool2, "rights_a", ", authz_rev xid8", "rev_ok")
	require.Empty(t, verdictOf(t, ctx2, pool2), "близнец (б) обязан молчать")
}

// (д) триггер ставит версию на любом UPDATE — красный с именем таблицы и
// триггера; близнец — сравнение по значимому столбцу — зелёный и печатает
// значимые столбцы [sig].
func TestAuthzRevisionGate_D_TriggerOnAnyUpdateIsNamed(t *testing.T) {
	ctx, pool := injDB(t)
	injTable(t, ctx, pool, "rights_a", ", authz_rev xid8", "rev_any")
	requireFindingNames(t, verdictOf(t, ctx, pool), "rights_a", "rights_a_rev", "без изменения")

	ctx2, pool2 := injDB(t)
	injTable(t, ctx2, pool2, "rights_a", ", authz_rev xid8", "rev_ok")
	require.Empty(t, verdictOf(t, ctx2, pool2), "близнец (д) обязан молчать")
	revs := judgeRevisioned(t, ctx2, pool2, injSchema)
	require.Len(t, revs, 1)
	require.Equal(t, []string{"sig"}, revs[0].significant, "перечень значимых столбцов выведен не тот")
}

// Пустое множество таблиц с колонкой — красный, а не вакуумный зелёный;
// близнец — одна таблица с законным триггером — зелёный.
func TestAuthzRevisionGate_EmptySetIsRed(t *testing.T) {
	ctx, pool := injDB(t)
	requireFindingNames(t, verdictOf(t, ctx, pool), "таблиц с колонкой authz_rev 0")

	ctx2, pool2 := injDB(t)
	injTable(t, ctx2, pool2, "rights_a", ", authz_rev xid8", "rev_ok")
	require.Empty(t, verdictOf(t, ctx2, pool2), "близнец пустого множества обязан молчать")
}
