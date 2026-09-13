// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_algorithm_dictionary_injection_test.go — доказательство того, что
// TestKeyAlgorithmDictionaryMatchesTheCode СПОСОБЕН упасть, и падает он на
// существе (задача #17, семейство `keyalgorithmdictionary`).
//
// Инъекция гоняет ТУ ЖЕ функцию разбора и то же разделение значений, что и
// гейт, а накат подаёт тем же способом, что и он.
//
// Вторая сторона пары обязательна: пустое значение — ЗАКОННЫЙ вход схемы, и
// гейт, считающий его алгоритмом, краснел бы на исправном дереве, а гейт,
// молчащий на его пропаже, пропустил бы исчезновение целого вида клиента.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// algInjectedExtraValue — словарь схемы ШИРЕ перечня кода.
//
// Расширять проще, чем сужать, поэтому расхождение и заводится в эту сторону:
// строка со значением, которого проверяющий не признаёт, вставляется без
// возражений, а клиент, ею заведённый, аутентифицироваться не может.
const algInjectedExtraValue = `-- +goose Up
CREATE TABLE kaname.user_oauth_clients (
    key_algorithm text DEFAULT ''::text NOT NULL,
    CONSTRAINT user_oauth_clients_key_algorithm_check CHECK ((key_algorithm IN ('', 'ES256', 'RS256', 'EdDSA', 'HS256')))
);
-- +goose Down
DROP TABLE kaname.user_oauth_clients;
`

// algInjectedLawful — словарь схемы, совпадающий с перечнем кода.
//
// Соседи, каждый со своим способом обмануть разбор:
//
//   - комментарий, называющий алгоритм, которого в словаре нет: разбор читает
//     ИСПОЛНЯЕМУЮ часть, а не текст, и предикат по подстроке краснел бы на
//     собственном объяснении;
//   - секция отката, объявляющая ДРУГОЙ словарь: она не применяется накатом, и
//     читать её значило бы судить схему по тому, чего в ней нет;
//   - второй столбец с похожим именем и своим словарём.
const algInjectedLawful = `-- +goose Up
CREATE TABLE kaname.user_oauth_clients (
    -- Словарь намеренно не содержит HS256: симметричное семейство здесь
    -- неприменимо, и объяснение это лежит в комментарии, а не в ограничении.
    key_algorithm text DEFAULT ''::text NOT NULL,
    key_algorithm_legacy text DEFAULT ''::text NOT NULL,
    CONSTRAINT user_oauth_clients_key_algorithm_check CHECK ((key_algorithm IN ('', 'ES256', 'RS256', 'EdDSA'))),
    CONSTRAINT user_oauth_clients_key_algorithm_legacy_check CHECK ((key_algorithm_legacy IN ('', 'RS1')))
);
-- +goose Down
ALTER TABLE kaname.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_key_algorithm_check CHECK ((key_algorithm IN ('', 'HS256')));
`

// algInjectedNoEmpty — словарь, из которого пропало пустое значение.
const algInjectedNoEmpty = `-- +goose Up
ALTER TABLE kaname.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_key_algorithm_check CHECK ((key_algorithm IN ('ES256', 'RS256', 'EdDSA')));
`

// algInjectedRedeclared — ограничение снято и объявлено заново.
const algInjectedRedeclared = `-- +goose Up
ALTER TABLE kaname.user_oauth_clients
    DROP CONSTRAINT user_oauth_clients_key_algorithm_check;
ALTER TABLE kaname.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_key_algorithm_check CHECK ((key_algorithm IN ('', 'ES256')));
`

// TestAlgorithmScannerFindsAWiderDictionary — сторона (а): словарь шире кода
// становится находкой, и находка несёт координату.
func TestAlgorithmScannerFindsAWiderDictionary(t *testing.T) {
	t.Parallel()
	found, dropped, census := check.ScanKeyAlgorithmConstraints(
		"synthetic/0046_user_oauth_clients.sql", migrations.MigrationUpSection(algInjectedExtraValue), keyAlgorithmColumn)
	if census.Statements != 1 || len(found) != 1 {
		t.Fatalf("объявлений найдено %d (перепись %d), ожидалось 1: %+v",
			len(found), census.Statements, found)
	}
	if len(dropped) != 0 {
		t.Fatalf("снятий найдено %d, ожидалось 0: %v", len(dropped), dropped)
	}
	c := found[0]
	if c.File == "" || c.Line == 0 {
		t.Errorf("находка без координаты — по такому отказу нечего чинить: %+v", c)
	}
	if c.Name != "user_oauth_clients_key_algorithm_check" {
		t.Errorf("находка не называет ограничение: %+v", c)
	}

	algorithms, hasEmpty := check.SplitAlgorithmValues(c.Values)
	if !hasEmpty {
		t.Errorf("пустое значение синтетики потеряно разбором: %+v", c.Values)
	}
	extra := setDifferenceOf(algorithms, []string{"ES256", "EdDSA", "RS256"})
	if len(extra) != 1 || extra[0] != "HS256" {
		t.Fatalf("расхождение со словарём кода вычислено как %v, ожидалось [HS256] — гейт "+
			"на этом дефекте остался бы зелёным", extra)
	}
}

// TestAlgorithmScannerIsSilentOnAMatchingDictionary — сторона (б).
func TestAlgorithmScannerIsSilentOnAMatchingDictionary(t *testing.T) {
	t.Parallel()
	found, _, census := check.ScanKeyAlgorithmConstraints(
		"synthetic/0046_user_oauth_clients.sql", migrations.MigrationUpSection(algInjectedLawful), keyAlgorithmColumn)
	if census.Statements == 0 {
		t.Fatalf("осмотрено ноль объявлений — разбирается не то дерево")
	}
	// Секция отката объявляет ДРУГОЙ словарь и накатом не применяется: разбор,
	// читающий её, объявил бы находку там, где схема исправна.
	if len(found) != 1 {
		t.Fatalf("объявлений найдено %d, ожидалось 1: %+v.\n\nЛибо прочитана секция отката "+
			"— тогда гейт судит схему по тому, чего в ней нет; либо чужой столбец с похожим "+
			"именем принят за наш.", len(found), found)
	}
	c := found[0]
	algorithms, hasEmpty := check.SplitAlgorithmValues(c.Values)
	if !hasEmpty {
		t.Fatalf("пустое значение не опознано (%v) — гейт объявил бы находкой исправную схему",
			c.Values)
	}
	if len(setDifferenceOf(algorithms, []string{"ES256", "EdDSA", "RS256"})) != 0 ||
		len(setDifferenceOf([]string{"ES256", "EdDSA", "RS256"}, algorithms)) != 0 {
		t.Fatalf("словарь разобран как %v, ожидалось совпадение с кодом — либо комментарий "+
			"прочитан как исполняемая часть, либо пустое значение сложено с алгоритмами",
			algorithms)
	}
}

// TestAlgorithmScannerFindsAMissingEmptyValue — пропажа пустого значения.
//
// Это не «схема стала строже»: на пустом значении стоит целый вид клиента,
// заведённый без ключевого материала.
func TestAlgorithmScannerFindsAMissingEmptyValue(t *testing.T) {
	t.Parallel()
	found, _, _ := check.ScanKeyAlgorithmConstraints(
		"synthetic/0900_narrow.sql", migrations.MigrationUpSection(algInjectedNoEmpty), keyAlgorithmColumn)
	if len(found) != 1 {
		t.Fatalf("объявлений найдено %d, ожидалось 1: %+v", len(found), found)
	}
	algorithms, hasEmpty := check.SplitAlgorithmValues(found[0].Values)
	if hasEmpty {
		t.Fatalf("пустое значение найдено там, где его нет (%v) — гейт молчал бы на "+
			"исчезновении целого вида клиента", found[0].Values)
	}
	// И при этом сами алгоритмы с кодом совпадают: без отдельной проверки на
	// пустое значение находки не было бы вовсе.
	if len(setDifferenceOf(algorithms, []string{"ES256", "EdDSA", "RS256"})) != 0 {
		t.Fatalf("синтетика подобрана неверно: алгоритмы %v расходятся с кодом, и находка "+
			"пришла бы не от пропажи пустого значения", algorithms)
	}
}

// TestAlgorithmScannerReadsTheLastDeclaration — действует ПОСЛЕДНЕЕ объявление,
// а снятое не действует вовсе.
//
// Применённая миграция не правится (ban #5), поэтому словарь меняют новой; гейт,
// читающий первое объявление, стерёг бы словарь, которого в схеме давно нет.
func TestAlgorithmScannerReadsTheLastDeclaration(t *testing.T) {
	t.Parallel()
	found, dropped, census := check.ScanKeyAlgorithmConstraints(
		"synthetic/0900_redeclare.sql", migrations.MigrationUpSection(algInjectedRedeclared), keyAlgorithmColumn)
	if census.Drops != 1 || len(dropped) != 1 {
		t.Fatalf("снятий найдено %d (перепись %d), ожидалось 1: %v",
			len(dropped), census.Drops, dropped)
	}
	if dropped[0] != "user_oauth_clients_key_algorithm_check" {
		t.Fatalf("снятие названо неверно: %q", dropped[0])
	}
	if len(found) != 1 {
		t.Fatalf("объявлений найдено %d, ожидалось 1: %+v", len(found), found)
	}
	algorithms, _ := check.SplitAlgorithmValues(found[0].Values)
	if len(algorithms) != 1 || algorithms[0] != "ES256" {
		t.Fatalf("прочитано не последнее объявление: %v", algorithms)
	}
}

// algInjectedDumpForm — тот же словарь, записанный формой `pg_dump`.
//
// Соседи — способы обмануть разбор именно ЭТОЙ формы:
//
//   - `<> ALL (ARRAY[…])` перечисляет ЗАПРЕЩЁННОЕ, а не допустимое: засчитав
//     его словарём, гейт сравнил бы дополнение множества с самим множеством;
//   - столбец, чьё имя ОКАНЧИВАЕТСЯ на наше, со своим словарём;
//   - приведение типа на каждом литерале — значением оно не является.
const algInjectedDumpForm = `-- +goose Up
CREATE TABLE kaname.user_oauth_clients (
    key_algorithm text DEFAULT ''::text NOT NULL,
    legacy_key_algorithm text DEFAULT ''::text NOT NULL,
    CONSTRAINT user_oauth_clients_key_algorithm_check CHECK ((key_algorithm = ANY (ARRAY[''::text, 'ES256'::text, 'RS256'::text, 'EdDSA'::text]))),
    CONSTRAINT user_oauth_clients_legacy_alg_check CHECK ((legacy_key_algorithm = ANY (ARRAY[''::text, 'RS1'::text]))),
    CONSTRAINT user_oauth_clients_key_algorithm_not_hs CHECK ((key_algorithm <> ALL (ARRAY['HS256'::text, 'HS384'::text])))
);
`

// algInjectedDumpFormWider — форма `pg_dump`, словарь ШИРЕ перечня кода.
const algInjectedDumpFormWider = `-- +goose Up
ALTER TABLE ONLY kaname.user_oauth_clients
    ADD CONSTRAINT user_oauth_clients_key_algorithm_check CHECK ((key_algorithm = ANY (ARRAY[''::text, 'ES256'::text, 'RS256'::text, 'EdDSA'::text, 'HS256'::text])));
`

// TestAlgorithmScannerReadsTheDumpForm — словарь, записанный формой `pg_dump`,
// читается наравне с рукописным.
//
// # Зачем отдельная проба
//
// Форм записи членства ДВЕ, и обе законны: рука пишет `IN (…)`, инструмент —
// `= ANY (ARRAY[…])`. Вторая пришла со сводом миграций iam 2026-09-04 и стала в
// этом сервисе ЕДИНСТВЕННОЙ: свод написан `pg_dump`, и три объявления словаря из
// трёх записаны ею.
//
// Разбор, знавший одну форму, не краснел и не молчал — он ОСЛЕП: находил ноль
// объявлений и сообщал об этом словами «столбец не сужен ничем», то есть
// утверждал о схеме то, что было верно о нём самом.
//
// Обе половины В ОДНОЙ пробе: форма дампа обязана читаться, а её соседи —
// перечень запрещённого и чужой столбец — обязаны в словарь НЕ попасть.
func TestAlgorithmScannerReadsTheDumpForm(t *testing.T) {
	t.Parallel()
	found, _, census := check.ScanKeyAlgorithmConstraints(
		"synthetic/0001_initial.sql", migrations.MigrationUpSection(algInjectedDumpForm), keyAlgorithmColumn)
	if census.Statements != 1 || len(found) != 1 {
		t.Fatalf("объявлений найдено %d (перепись %d), ожидалось 1: %+v.\n\n"+
			"Ноль означает, что форма `= ANY (ARRAY[…])` не читается; больше одного — "+
			"что в словарь попал перечень ЗАПРЕЩЁННОГО (`<> ALL`) либо чужой столбец "+
			"`legacy_key_algorithm`", len(found), census.Statements, found)
	}
	c := found[0]
	if c.Name != "user_oauth_clients_key_algorithm_check" {
		t.Fatalf("находка называет не то ограничение: %+v", c)
	}
	algorithms, hasEmpty := check.SplitAlgorithmValues(c.Values)
	if !hasEmpty {
		t.Fatalf("пустое значение потеряно разбором формы дампа: %+v", c.Values)
	}
	// Приведение типа значением не является: `'ES256'::text` — это `ES256`.
	if len(setDifferenceOf(algorithms, []string{"ES256", "EdDSA", "RS256"})) != 0 ||
		len(setDifferenceOf([]string{"ES256", "EdDSA", "RS256"}, algorithms)) != 0 {
		t.Fatalf("словарь разобран как %v, ожидалось совпадение с кодом — вероятно, "+
			"приведение типа прочитано как значение", algorithms)
	}
}

// TestAlgorithmScannerFindsAWiderDictionaryInTheDumpForm — сторона (а) для формы
// дампа: расхождение в ней обязано находиться так же, как в рукописной.
//
// Без этой половины «форма читается» было бы неотличимо от «форма читается, но
// расхождение в ней не ловится».
func TestAlgorithmScannerFindsAWiderDictionaryInTheDumpForm(t *testing.T) {
	t.Parallel()
	found, _, _ := check.ScanKeyAlgorithmConstraints(
		"synthetic/0900_wider.sql", migrations.MigrationUpSection(algInjectedDumpFormWider), keyAlgorithmColumn)
	if len(found) != 1 {
		t.Fatalf("объявлений найдено %d, ожидалось 1: %+v", len(found), found)
	}
	algorithms, _ := check.SplitAlgorithmValues(found[0].Values)
	extra := setDifferenceOf(algorithms, []string{"ES256", "EdDSA", "RS256"})
	if len(extra) != 1 || extra[0] != "HS256" {
		t.Fatalf("расхождение вычислено как %v, ожидалось [HS256] — гейт на этом дефекте "+
			"остался бы зелёным", extra)
	}
}
