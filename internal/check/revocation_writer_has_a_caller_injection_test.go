// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// revocation_writer_has_a_caller_injection_test.go — ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ
// (задача kaname#313).
//
// Каждая инъекция сверх исхода утверждает ПЕРЕПИСЬ: писателей осмотрено ровно
// столько, сколько подано. Без этого опечатка во входе — или сузившийся
// разбор — обращала бы обе половины пары в зелёное, и молчание на близнеце было
// бы неотличимо от молчания на непрочитанном.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// revocationWriterSource — писатель отсечки одной формы. Меняется РОВНО имя.
func revocationWriterSource(name string) []byte {
	return []byte(`package pg

func (r *Repo) ` + name + `(ctx context.Context) error {
	const q = ` + "`INSERT INTO kaname.minted_token_revocations (subject) VALUES ($1)`" + `
	_, err := r.pool.Exec(ctx, q)
	return err
}
`)
}

func scanOneRevocationWriter(t *testing.T, src []byte) ([]check.RevocationWriter, check.RevocationWriterCensus) {
	t.Helper()
	w, c, err := check.ScanRevocationWriters("synthetic/w.go", src, map[string]string{})
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if c.Writers != 1 {
		t.Fatalf("вставка не долетела: писателей осмотрено %d, подан 1 — "+
			"дальнейший вердикт беспредметен", c.Writers)
	}
	if _, ok := c.Tables["minted_token_revocations"]; !ok {
		t.Fatalf("таблица отсечки не выведена из входа: %v", check.SortedTables(c))
	}
	return w, c
}

// TestRevocationWriterInjection_UncalledWriterIsFound — писателя не зовут.
func TestRevocationWriterInjection_UncalledWriterIsFound(t *testing.T) {
	t.Parallel()
	w, _ := scanOneRevocationWriter(t, revocationWriterSource("RevokeMintedTokens"))

	found := check.RevocationWritersWithoutACaller(w,
		map[string]struct{}{}, map[string]int{"RevokeMintedTokens": 1})
	if len(found) != 1 {
		t.Fatalf("писатель без вызывающего НЕ пойман: находок %d", len(found))
	}
	if !strings.Contains(found[0].Why, "не зовёт никто") {
		t.Errorf("находка называет причину %q — она обязана назвать ОТСУТСТВИЕ вызывающего", found[0].Why)
	}
}

// TestRevocationWriterInjection_CalledWriterIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ молчит.
//
// Отличается от дефекта выше РОВНО одним фактом: имя стоит среди вызванных.
func TestRevocationWriterInjection_CalledWriterIsSilent(t *testing.T) {
	t.Parallel()
	w, _ := scanOneRevocationWriter(t, revocationWriterSource("RevokeMintedTokens"))

	found := check.RevocationWritersWithoutACaller(w,
		map[string]struct{}{"RevokeMintedTokens": {}}, map[string]int{"RevokeMintedTokens": 1})
	if len(found) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ писателе: %+v", found)
	}
}

// TestRevocationWriterInjection_AmbiguousNameIsFoundEvenWhenCalled — ИМЕННО ТАК
// дефект и прятался: имя общее, вызов такого имени в дереве есть, и прибор
// молчал бы с той же уверенностью, с какой молчит на работающем контроле.
func TestRevocationWriterInjection_AmbiguousNameIsFoundEvenWhenCalled(t *testing.T) {
	t.Parallel()
	w, _ := scanOneRevocationWriter(t, revocationWriterSource("Revoke"))

	// Имя ЕСТЬ среди вызванных — и это не спасает: объявлено оно в дереве
	// многократно, поэтому вызов может принадлежать кому угодно.
	found := check.RevocationWritersWithoutACaller(w,
		map[string]struct{}{"Revoke": {}}, map[string]int{"Revoke": 18})
	if len(found) != 1 {
		t.Fatalf("неразличимое имя НЕ поймано: находок %d — гейт молчит там, "+
			"где он не может ничего утверждать", len(found))
	}
	if !strings.Contains(found[0].Why, "не разобрать") {
		t.Errorf("находка называет причину %q — она обязана назвать НЕРАЗЛИЧИМОСТЬ имени", found[0].Why)
	}
}

// TestRevocationWriterInjection_HoistedStatementIsSeen — оператор, ВЫНЕСЕННЫЙ из
// тела, тоже делает функцию писателем.
//
// Ось отдельная: форма эта — норма дерева (оператор выносят ради двух
// исполнителей), и разбор, знающий только литерал в теле, не видел бы именно
// тех писателей, которых делят две полосы. Такой промах уже был измерен:
// записей отсечки находилось 1 из 3, писателей 1 из 8.
func TestRevocationWriterInjection_HoistedStatementIsSeen(t *testing.T) {
	t.Parallel()
	decls := []byte(`package pg

const upsertCutoffSQL = ` + "`INSERT INTO kaname.minted_token_revocations (subject) VALUES ($1)`" + `
`)
	statements := map[string]string{}
	if err := check.ScanRevocationStatements("synthetic/decl.go", decls, statements); err != nil {
		t.Fatalf("разбор объявлений: %v", err)
	}
	if len(statements) != 1 {
		t.Fatalf("объявление оператора не прочитано: собрано %d, подано 1", len(statements))
	}

	body := []byte(`package pg

func (r *Repo) RevokeMintedTokens(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, upsertCutoffSQL)
	return err
}
`)
	w, c, err := check.ScanRevocationWriters("synthetic/body.go", body, statements)
	if err != nil {
		t.Fatalf("разбор тела: %v", err)
	}
	if c.Writers != 1 || len(w) != 1 {
		t.Fatalf("писатель через ВЫНЕСЕННЫЙ оператор не опознан: писателей %d", c.Writers)
	}
	if w[0].Table != "minted_token_revocations" {
		t.Errorf("таблица опознана как %q", w[0].Table)
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ формы: функция, НЕ называющая объявления, писателем не
	// становится — иначе ось выше зеленела бы на разборе, метящем всё подряд.
	plain := []byte(`package pg

func (r *Repo) SomethingElse(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, someOtherSQL)
	return err
}
`)
	_, c2, err := check.ScanRevocationWriters("synthetic/plain.go", plain, statements)
	if err != nil {
		t.Fatalf("разбор близнеца: %v", err)
	}
	if c2.Funcs != 1 {
		t.Fatalf("функций осмотрено %d, подана 1 — вход не прочитан", c2.Funcs)
	}
	if c2.Writers != 0 {
		t.Fatalf("посторонняя функция признана писателем: %d", c2.Writers)
	}
}

// TestRevocationWriterPremise_EmptyWalkIsNotAVerdict — обход без предмета
// вердикта не выносит.
func TestRevocationWriterPremise_EmptyWalkIsNotAVerdict(t *testing.T) {
	t.Parallel()
	empty := check.RevocationWriterCensus{Funcs: 10, Tables: map[string]struct{}{}}
	if err := check.RevocationWriterPremise(1000, revocationWriterCensusFloor, empty); err == nil {
		t.Fatal("обход без единой записи отсечки вынес вердикт")
	}

	// Таблицы есть, писателей нет — разбор видит имена и не видит записи.
	namesOnly := check.RevocationWriterCensus{
		Funcs: 10, Tables: map[string]struct{}{"minted_token_revocations": {}},
	}
	if err := check.RevocationWriterPremise(1000, revocationWriterCensusFloor, namesOnly); err == nil {
		t.Fatal("обход с таблицами и нулём писателей вынес вердикт")
	}

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: живой обход предпосылку проходит.
	live := check.RevocationWriterCensus{
		Funcs: 10, Writers: 1, Tables: map[string]struct{}{"minted_token_revocations": {}},
	}
	if err := check.RevocationWriterPremise(1000, revocationWriterCensusFloor, live); err != nil {
		t.Fatalf("предпосылка отвергает ЖИВОЙ обход: %v", err)
	}
	if err := check.RevocationWriterPremise(1, revocationWriterCensusFloor, live); err == nil {
		t.Fatal("обход, разобравший 1 файл при пороге, вынес вердикт")
	}
}
