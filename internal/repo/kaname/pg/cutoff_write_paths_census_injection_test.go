// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// cutoff_write_paths_census_injection_test.go — перепись путей записи строки
// отсечки доказана на синтетике, а не на живом дереве (задача kaname#379).
//
// Живое дерево меняется, и перепись, проверенная только на нём, краснеет на
// перемене дерева, а не на своём дефекте. Так она и сломалась: операцию записи
// переименовали (kaname#313), а перепись искала её по имени и перестала
// находить что-либо. Здесь каждая законная форма записи строки и каждый
// законный близнец подаются каталогом во временном месте, и перепись
// спрашивается о нём напрямую.
package pg_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// censusCorpus раскладывает синтетический пакет во временный каталог.
func censusCorpus(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600))
	}
	return dir
}

// censusDoorCorpus — форма, которую дал kaname#313: оператор строки вынесен
// константой, его исполняет одна функция, её зовёт дверь, а дверь зовут
// методы — по одному на исполнителя. Имя оператора выбрано НЕ тем, что в
// продукте: перепись обязана узнавать строку, а не имя.
const censusDoorCorpus = `package pg

import "context"

const renamedCutoffStatement = ` + "`" + `
	INSERT INTO user_token_revocations (user_id, revoke_before)
	VALUES ($1, $2)
	ON CONFLICT (user_id) DO UPDATE
	    SET revoke_before = GREATEST(user_token_revocations.revoke_before, EXCLUDED.revoke_before)` + "`" + `

func writeRow(ctx context.Context, ex executor, id string) error {
	_, err := ex.Exec(ctx, renamedCutoffStatement, id)
	return err
}

func door(ctx context.Context, ex executor, id string) error {
	return writeRow(ctx, ex, id)
}

func (r *PoolRepo) Write(ctx context.Context, id string) error { return door(ctx, r.pool, id) }

func (w *txWriter) WriteTx(ctx context.Context, id string) error { return door(ctx, w.tx, id) }
`

// TestCutoffCensusFindsTheWritersOfTheRowWhateverTheOperationIsCalled —
// путь записи опознаётся по СТРОКЕ, которую пишет оператор, а не по имени
// оператора: переименование не делает перепись пустой. Путь — внешний конец
// цепочки, а не функция, исполняющая оператор: дверь и её помощник путями не
// являются, их зовут пути.
func TestCutoffCensusFindsTheWritersOfTheRowWhateverTheOperationIsCalled(t *testing.T) {
	dir := censusCorpus(t, map[string]string{"repo.go": censusDoorCorpus})
	paths, parsed := cutoffWritePathsIn(t, dir)
	require.Equal(t, 1, parsed, "перепись: разобран ровно один файл синтетики")
	require.Equal(t, []string{"PoolRepo.Write", "txWriter.WriteTx"}, paths,
		"пути записи строки — методы, зовущие дверь; дверь и её помощник путями не являются")
}

// TestCutoffCensusLeavesTheWriterOfAnotherRowOut — законный близнец: та же
// форма цепочки, отличающаяся ОДНИМ фактом — оператор пишет другую строку
// (отсечку по ключу семейства в `minted_token_revocations`). Её писатель
// путём этой строки не является, а соседние пути остаются найденными.
func TestCutoffCensusLeavesTheWriterOfAnotherRowOut(t *testing.T) {
	const twin = `package pg

import "context"

const otherRowStatement = ` + "`" + `INSERT INTO kaname.minted_token_revocations (subject, revoke_before)
		VALUES ($1, $2)` + "`" + `

func writeOtherRow(ctx context.Context, ex executor, id string) error {
	_, err := ex.Exec(ctx, otherRowStatement, id)
	return err
}

func (f *FamilyWriter) Write(ctx context.Context, id string) error { return writeOtherRow(ctx, f.tx, id) }
`
	dir := censusCorpus(t, map[string]string{"repo.go": censusDoorCorpus, "family.go": twin})
	paths, parsed := cutoffWritePathsIn(t, dir)
	require.Equal(t, 2, parsed)
	require.Equal(t, []string{"PoolRepo.Write", "txWriter.WriteTx"}, paths,
		"писатель другой строки путём этой не является; пути этой строки найдены")
}

// TestCutoffCensusSeesEveryLawfulFormOfTheStatement — каждая законная форма
// записи оператора, по одной на прогон: перепись, не знающая формы, молчит о
// её пути, и молчание неотличимо от «пути нет».
func TestCutoffCensusSeesEveryLawfulFormOfTheStatement(t *testing.T) {
	const tail = `
func (r *Repo) Write(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, stmt, id)
	return err
}
`
	forms := []struct{ name, src string }{
		{"константа, сырая строка", "const stmt = `INSERT INTO user_token_revocations (user_id) VALUES ($1)`\n" + tail},
		{"константа, строка в кавычках", `const stmt = "INSERT INTO user_token_revocations (user_id) VALUES ($1)"` + "\n" + tail},
		{"константа, склеенная из частей", "const stmt = `INSERT INTO ` +\n\t`user_token_revocations (user_id) VALUES ($1)`\n" + tail},
		{"константа из соседней константы", "const head = `INSERT INTO user_token_revocations`\nconst stmt = head + ` (user_id) VALUES ($1)`\n" + tail},
		{"переменная пакета", "var stmt = `INSERT INTO user_token_revocations (user_id) VALUES ($1)`\n" + tail},
		{"имя схемы и кавычки", "const stmt = `INSERT INTO \"kaname\".\"user_token_revocations\" (user_id) VALUES ($1)`\n" + tail},
		{"UPDATE строки", "const stmt = `UPDATE kaname.user_token_revocations SET revoke_before = $2 WHERE user_id = $1`\n" + tail},
		{"литерал в теле", `
func (r *Repo) Write(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, "INSERT INTO user_token_revocations (user_id) VALUES ($1)", id)
	return err
}
`},
		{"литерал в теле, склеенный", `
func (r *Repo) Write(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, "INSERT INTO "+"user_token_revocations (user_id) VALUES ($1)", id)
	return err
}
`},
	}
	for _, form := range forms {
		t.Run(form.name, func(t *testing.T) {
			src := "package pg\n\nimport \"context\"\n\n" + form.src
			dir := censusCorpus(t, map[string]string{"repo.go": src})
			paths, parsed := cutoffWritePathsIn(t, dir)
			require.Equal(t, 1, parsed)
			require.Equalf(t, []string{"Repo.Write"}, paths, "форма «%s» не узнана", form.name)
		})
	}
}

// TestCutoffCensusDoesNotTakeAMentionForAWrite — упоминание строки записью не
// является: комментарий, читатель строки, текст ошибки, соседняя таблица с тем
// же началом имени и файл проб. На таком пакете перепись пуста — и это
// «не выполнилось» у живой переписи, а не «покрыто всё».
func TestCutoffCensusDoesNotTakeAMentionForAWrite(t *testing.T) {
	const mentions = `package pg

import (
	"context"
	"errors"
)

// Write — здесь стоял INSERT INTO user_token_revocations, теперь его нет.
func (r *Repo) Write(ctx context.Context, id string) error { return nil }

func (r *Repo) RevokedBefore(ctx context.Context, id string) error {
	_ = r.pool.QueryRow(ctx, "SELECT revoke_before FROM user_token_revocations WHERE user_id = $1", id)
	return errors.New("user_token_revocations: write failed")
}

func (r *Repo) Archive(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, "INSERT INTO user_token_revocations_archive (user_id) VALUES ($1)", id)
	return err
}
`
	const probe = `package pg

import "context"

func (r *Repo) SeedCutoff(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, "INSERT INTO user_token_revocations (user_id) VALUES ($1)", id)
	return err
}
`
	dir := censusCorpus(t, map[string]string{"repo.go": mentions, "seed_test.go": probe})
	paths, parsed := cutoffWritePathsIn(t, dir)
	require.Equal(t, 1, parsed, "файл проб не разбирается: он не продукт")
	require.Empty(t, paths, "упоминание строки записью не является")
}

// TestCutoffCensusReportsOuterEndsOfTheChain — путь есть внешний конец цепочки:
// функция без получателя, которую никто в пакете не зовёт, — путь сама; дверь,
// которую зовут, — нет. Метод, зовущий ПУТЬ через селектор, отдельным путём не
// считается: его подача — подача того пути, который он зовёт.
func TestCutoffCensusReportsOuterEndsOfTheChain(t *testing.T) {
	const chain = `package pg

import "context"

const stmt = ` + "`INSERT INTO user_token_revocations (user_id) VALUES ($1)`" + `

func door(ctx context.Context, ex executor, id string) error {
	_, err := ex.Exec(ctx, stmt, id)
	return err
}

func orphanWrite(ctx context.Context, ex executor, id string) error { return door(ctx, ex, id) }

func (r *Repo) Write(ctx context.Context, id string) error { return door(ctx, r.pool, id) }

func (a *Adapter) RevokeAll(ctx context.Context, id string) error { return a.repo.Write(ctx, id) }
`
	dir := censusCorpus(t, map[string]string{"repo.go": chain})
	paths, parsed := cutoffWritePathsIn(t, dir)
	require.Equal(t, 1, parsed)
	require.Equal(t, []string{"Repo.Write", "orphanWrite"}, paths,
		"внешние концы цепочки — путь; дверь — нет; зовущий путь через селектор — не отдельный путь")
}
