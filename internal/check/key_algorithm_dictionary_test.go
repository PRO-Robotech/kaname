// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_algorithm_dictionary_test.go — ГЕЙТ КЛАССА: словарь зарегистрированного
// алгоритма в СХЕМЕ совпадает с закрытым перечнем КОДА (задача #17, порт
// семейства `keyalgorithmdictionary`).
//
// # Предмет
//
// Одно множество объявлено дважды: ограничением схемы и перечнем проверяющего.
// Совпадение держится ГЕЙТОМ, а не совпадением формулировок. Разойдясь, они
// дают одно из двух — строку, которую схема примет, а проверяющий не признает
// (клиент заведён и аутентифицироваться не может), либо алгоритм, который
// проверяющий считает допустимым, а вставить его нельзя.
//
// # Пустое значение схемы алгоритмом НЕ является
//
// Пропажа пустого значения из словаря — НАХОДКА, а не улучшение: на нём стоит
// целый вид клиента (заведённый без ключевого материала), и его исчезновение
// означает, что состояние, которое читатель считает законным, схема больше не
// допускает. Исключение — ведомость ниже.
//
// Формы словаря, границы разбора и то, чего он НЕ видит, — в шапке
// `key_algorithm_dictionary.go`.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// key_algorithm_dictionary_injection_test.go.
package check_test

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// keyAlgorithmColumn — столбец, чей словарь стережётся.
	keyAlgorithmColumn = "key_algorithm"
	// keyAlgorithmConstraintFloor — сколько действующих ограничений обязано быть
	// найдено. Ноль означал бы, что разбор перестал видеть предмет, и молчание
	// было бы сказано о разборе, а не о схеме.
	keyAlgorithmConstraintFloor = 1
)

// keyAlgorithmKeyRequired — ограничения, у которых пустое значение НЕ законно.
//
// Общее правило («пустое означает ключа нет и обязано допускаться») выведено из
// таблиц клиентов: там ключевой материал есть не у всякой строки. Есть таблицы
// с обратным решением, и у них пустое значение означало бы не «ключа нет», а
// «принимаем без проверки подписи».
//
// Ключ — имя ограничения; значение — причина. Перечень закрыт: ограничение,
// которого здесь нет, судится общим правилом. Запись САМОИСТЕКАЕТ: ограничение,
// которого больше нет либо которое начало допускать пустое, — находка.
var keyAlgorithmKeyRequired = map[string]string{
	"federated_trusted_issuers_alg_ck": "" +
		"перечень доверенных издателей: запись доверия БЕЗ ключа издателя не отвергала бы " +
		"ничего — она принимала бы всё, что называет её пару, то есть доверие издателю " +
		"выродилось бы в доверие строке таблицы. «Ключа нет» здесь не состояние строки, а её " +
		"отсутствие: строки без ключа не существует",
}

// TestKeyAlgorithmDictionaryMatchesTheCode — имя сохранено дословно с монорепо.
func TestKeyAlgorithmDictionaryMatchesTheCode(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	code := append([]string(nil), tokenpolicy.Algorithms()...)
	sort.Strings(code)

	// Предпосылка: перечень кода непуст. Пустой означал бы, что проверяющий не
	// принимает ничего, и «совпадение со схемой» сказано ни о чём.
	if len(code) == 0 {
		t.Fatal("закрытый перечень алгоритмов кода ПУСТ — проверяющий не принимает ни " +
			"одного алгоритма, и сверять со схемой нечего")
	}
	for _, a := range code {
		if strings.TrimSpace(a) == "" {
			t.Fatalf("перечень кода содержит пустое значение (%v). Пустое означает «ключа "+
				"нет», а не «любой алгоритм»: приняв его алгоритмом, проверяющий перестал бы "+
				"сужать вовсе", code)
		}
	}

	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}

	// Обход миграций и его отказ на пустоте держит ОДНА функция —
	// `MigrationCorpus` (задача #17): прежде премиса «не прочитано ни одного
	// файла миграции» стояла в теле пробы и не исполнялась ни разу.
	//
	// Заодно обход стал брать состав ИНДЕКСОМ git, а не каталогом на диске:
	// прежняя редакция читала `os.ReadDir`, то есть судила бы и файл, который
	// в дереве не отслеживается — чужой черновик рядом с миграциями попадал бы
	// в вердикт о схеме.
	migs, err := check.MigrationCorpus(tree)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v — гейт не может назвать схему, "+
			"о которой он говорит", err)
	}
	// Порядок номера — тот же, в котором миграции применяет накат.
	files := migs.Rels()
	sort.Slice(files, func(i, j int) bool {
		return migrationOrdinal(path.Base(files[i])) < migrationOrdinal(path.Base(files[j]))
	})

	var census check.AlgorithmDictionaryCensus
	live := map[string]check.AlgorithmConstraint{}
	for _, rel := range files {
		census.Files++
		found, dropped, c := check.ScanKeyAlgorithmConstraints(
			rel, migrations.MigrationUpSection(migs[rel]), keyAlgorithmColumn)
		census.Statements += c.Statements
		census.Drops += c.Drops
		for _, f := range found {
			live[f.Name] = f
		}
		for _, dn := range dropped {
			delete(live, dn)
		}
	}

	names := make([]string, 0, len(live))
	for n := range live {
		names = append(names, n)
	}
	sort.Strings(names)

	t.Logf("перепись: файлов миграций прочитано %d, объявлений словаря столбца %q найдено %d, "+
		"снятий ограничения %d, действующих ограничений %d (%s); перечень кода: %v",
		census.Files, keyAlgorithmColumn, census.Statements, census.Drops,
		len(live), strings.Join(names, ", "), code)

	// Предпосылка: словарь в схеме ВЫРАЖЕН. Ноль ограничений означает, что
	// столбец больше ничем не сужен, — и это само по себе находка: значение,
	// которое схема не сужает, означает «любое».
	if len(live) < keyAlgorithmConstraintFloor {
		t.Fatalf("действующих объявлений словаря столбца %q в схеме %d при пороге %d "+
			"(найдено объявлений %d, снято %d).\n\n"+
			"Столбец, который схема не сужает, принимает ЛЮБОЕ значение: словарь перестал "+
			"быть выражен, и совпадать с перечнем кода нечему. Молчание гейта здесь было бы "+
			"сказано о разборе, а не о схеме.",
			keyAlgorithmColumn, len(live), keyAlgorithmConstraintFloor,
			census.Statements, census.Drops)
	}

	var problems []string
	seenKeyRequired := map[string]bool{}
	for _, name := range names {
		c := live[name]
		algorithms, hasEmpty := check.SplitAlgorithmValues(c.Values)

		reason, keyRequired := keyAlgorithmKeyRequired[name]
		switch {
		case !hasEmpty && !keyRequired:
			problems = append(problems, fmt.Sprintf(
				"%s:%d %s — словарь БОЛЬШЕ НЕ ДОПУСКАЕТ пустое значение (%v). Пустое значение "+
					"означает «ключа нет», и на нём стоит целый вид клиента, заведённый без "+
					"ключевого материала: его исчезновение означает, что состояние, которое "+
					"читатель считает законным, схема больше не допускает",
				c.File, c.Line, name, c.Values))
		case hasEmpty && keyRequired:
			problems = append(problems, fmt.Sprintf(
				"%s:%d %s — ограничение объявлено требующим ключа, а словарь ДОПУСКАЕТ пустое "+
					"значение (%v). Причина записи: %s",
				c.File, c.Line, name, c.Values, reason))
		case keyRequired:
			seenKeyRequired[name] = true
		}

		extra := setDifferenceOf(algorithms, code)
		missing := setDifferenceOf(code, algorithms)
		if len(extra) == 0 && len(missing) == 0 {
			continue
		}
		var parts []string
		if len(extra) > 0 {
			parts = append(parts, fmt.Sprintf("схема допускает сверх кода: %v", extra))
		}
		if len(missing) > 0 {
			parts = append(parts, fmt.Sprintf("код допускает сверх схемы: %v", missing))
		}
		problems = append(problems, fmt.Sprintf("%s:%d %s — %s (схема %v, код %v)",
			c.File, c.Line, name, strings.Join(parts, "; "), algorithms, code))
	}

	// Запись о требуемом ключе живёт, ПОКА живо её ограничение. Оставленная без
	// предмета, она молча накроет следующее ограничение того же имени.
	for name, reason := range keyAlgorithmKeyRequired {
		if !seenKeyRequired[name] {
			problems = append(problems, fmt.Sprintf(
				"запись о требуемом ключе %q больше нечего исключать: действующего ограничения "+
					"с таким именем в схеме нет. Причина записи: %s", name, reason))
		}
	}

	if len(problems) > 0 {
		t.Fatalf("словарь алгоритма в схеме разошёлся с закрытым перечнем кода — %d находка(и):\n  %s\n\n"+
			"Снятие: НОВАЯ миграция, приводящая ограничение к перечню кода (применённая не "+
			"правится, ban #5), либо правка перечня кода, если решение принято в его пользу.",
			len(problems), strings.Join(problems, "\n  "))
	}

	for _, name := range names {
		c := live[name]
		algorithms, hasEmpty := check.SplitAlgorithmValues(c.Values)
		t.Logf("%s:%d %s — алгоритмы %v, пустое значение допускается: %v",
			c.File, c.Line, name, algorithms, hasEmpty)
	}
}

// migrationOrdinal — числовой префикс имени миграции; им же задан порядок наката.
func migrationOrdinal(base string) int {
	n := 0
	for i := 0; i < len(base); i++ {
		if base[i] < '0' || base[i] > '9' {
			break
		}
		n = n*10 + int(base[i]-'0')
	}
	return n
}

// setDifferenceOf — элементы a, которых нет в b.
func setDifferenceOf(a, b []string) []string {
	have := map[string]bool{}
	for _, x := range b {
		have[x] = true
	}
	var out []string
	for _, x := range a {
		if !have[x] {
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}
