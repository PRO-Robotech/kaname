// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_version_monotonic_test.go — ГЕЙТ КЛАССА: НОВАЯ миграция обязана
// получить номер строго больше каждого уже применённого в своём каталоге.
//
// # Почему гейт заведён ЗДЕСЬ, а не взят у соседа
//
// Имя `TestNewMigrationOutranksEveryAppliedOne` названо README каталога
// миграций этой службы — но сам гейт под этим именем живёт в ДРУГОМ
// репозитории (`PRO-Robotech/kacho:internal/repohygiene/`), и судит он
// каталоги ТОГО дерева. Замер на день заведения:
//
//	kacho $ git ls-files -- '*/migrations/*.sql' | wc -l            → 210
//	kacho $ git ls-files -- '*/migrations/*.sql' | grep -c kaname   → 0
//
// То есть утверждение README было ложным не по тексту, а по области: гейт
// существует, красным бывает, и ни одного файла этой службы он не видит.
// Служба вынесена отдельным продуктом, чужой прогон её дерева не читает —
// значит порядок номеров здесь не держало НИЧТО, кроме самого мигратора,
// то есть он обнаруживался в момент наката, а не в момент правки.
//
// Дом — `internal/check`: это пакет гейтов ДЕРЕВА этой службы (аналог
// `internal/repohygiene` монорепо), здесь уже живёт соседний гейт о
// добавленных миграциях (`migration_not_a_writer_of_module_role_test.go`), и
// отсюда берутся общие для них `trunkRef` и `addedMigrationFiles` — второй
// редакции «что считать добавленным» в дереве не заводится.
//
// # Что гейт судит и чем ограничен его обход
//
// Обход ограничен: каталог `internal/migrations` ЭТОГО модуля, состав берётся
// у ИНДЕКСА git (вердикт обязан быть свойством коммита, а не рабочего каталога
// прогоняющего), предметом признаётся файл `.sql`. Про другие каталоги, другие
// модули и другие репозитории этот гейт не говорит ничего.
//
// Перечень ФОРМ имени не выписан ни здесь, ни в разборе: его выводит обход и
// печатает перепись. Смена состава каталога видна числом, а не правкой кода.
//
// # Исторический остаток — ЧИСЛО, а не находка
//
// Применённую миграцию не переименовывают (запрет #5): переименование меняет
// схему у тех, кто уже мигрировал. Поэтому правило действует ВПЕРЁД — судится
// только добавленное относительно ствола, а прошлое печатается числом.
//
// Способность гейта упасть и способность смолчать доказаны инъекцией —
// migration_version_monotonic_injection_test.go.
package check_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestNewMigrationOutranksEveryAppliedOne(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree := gateTree(t, root)

	// Знаменатель обхода — ВЕСЬ каталог, а не одни только миграции: «рассмотрено
	// 32 из 96» говорит, что обход видел дом целиком. Файл, миграцией не
	// являющийся, предметом не становится и находкой стать не может.
	var dirFiles []string
	for _, rel := range tree.tree.SortedFiles() {
		if strings.HasPrefix(rel, check.MigrationsDirRel+"/") {
			dirFiles = append(dirFiles, rel)
		}
	}
	if len(dirFiles) == 0 {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: индекс дерева %s не назвал НИ ОДНОГО файла "+
			"каталога %s — дом миграций переехал, и гейт стережёт координату, которой "+
			"больше нет. Это отказ ПРЕДПОСЫЛКИ, а не пустой список",
			root, check.MigrationsDirRel)
	}

	// Состав ДОБАВЛЕННОГО. Ствол разрешается ПОСЛЕ переписи дерева: его
	// недостижимость есть отказ предпосылки и обязана прийти отдельно от неё,
	// а не вместо неё.
	base, ok := trunkRef(root)
	if !ok {
		audit := check.AuditMigrationVersions(dirFiles, nil)
		t.Logf("перепись дерева: %s", audit.Census)
		t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): ствол %s в этом клоне не разрешается — "+
			"состав ДОБАВЛЕННОГО установить нечем. Перепись дерева выше снята и остаётся "+
			"верной; о находках вердикта НЕТ ни зелёного, ни красного", trunkRefName)
	}
	added := sortedKeys(addedMigrationFiles(t, root, base))

	audit := check.AuditMigrationVersions(dirFiles, added)

	// Исход печатается ВСЕГДА и ОТДЕЛЬНО от числа находок: «находок ноль» само
	// по себе не отличает гейт, которому нечего сказать, от гейта, который
	// ничего не нашёл.
	t.Logf("относительно %s: исход — %s; %s", base, audit.Outcome, audit.Census)
	// «Нет предмета» ЗЕЛЁНЫМ не бывает. У исхода [check.MigrationVersionNoCorpus]
	// в ЖИВОМ дереве причина одна: дом миграций переехал, а гейт стережёт
	// координату, которой больше нет. Находок при этом ноль — и ровно поэтому
	// код возврата ноль читался бы как здоровое дерево.
	if audit.Outcome == check.MigrationVersionNoCorpus {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %s. Каталог %s назван индексом (%d файл(ов)), "+
			"но миграций в нём НЕТ НИ ОДНОЙ: судить было нечего, и «находок ноль» здесь "+
			"означало бы «прочитано ноль», а не «годно»",
			audit.Outcome, check.MigrationsDirRel, audit.Census.DirFiles)
	}

	if len(audit.Census.Unordered) > 0 {
		t.Logf("миграций с НЕРАЗОБРАННЫМ номером в каталоге %d: %s — их место в цепочке "+
			"неизвестно, и это видно числом, а не молчанием",
			len(audit.Census.Unordered), strings.Join(audit.Census.Unordered, ", "))
	}

	// Встречная перепись: держал ли каталог этот класс ДО заведения гейта.
	// Находкой она быть не может (запрет #5 — применённую не переименовывают),
	// но и молчанием остаться не вправе: ноль здесь и пять здесь — разные
	// утверждения о дереве.
	past, seen := historicalOutOfOrder(t, root, dirFiles)
	t.Logf("исторический остаток: введённых в дерево миграций прослежено %d из %d; "+
		"номер вставал НЕ ВЫШЕ уже лежащего %d раз(а)%s",
		seen, audit.Census.SQL, len(past), joinPast(past))

	if len(audit.Findings) > 0 {
		t.Fatalf("ДОБАВЛЕННАЯ миграция не превосходит применённые — %d находка(и):\n  %s\n\n"+
			"Порядок сегодня держит только сам мигратор, то есть он обнаружится в момент "+
			"наката, а не в момент правки. Форма имени и порядок действий при столкновении "+
			"объявлены одним местом: docs/engineering/architecture/migration-version-namespace.md",
			len(audit.Findings), strings.Join(audit.Findings, "\n  "))
	}
}

// historicalOutOfOrder — сколько раз в ИСТОРИИ СТВОЛА миграция вводилась с
// номером не выше уже лежащего.
//
// Порядок ввода берётся у git (последнее добавление файла), а не у имени:
// именно расхождение этих двух порядков и есть предмет класса. Прослеженное
// число возвращается вторым: история, обрезанная мелким клоном, обязана
// читаться как «прослежено 3 из 32», а не как «нарушений ноль».
//
// ВЕРШИНА — СТВОЛ, и это несущее: остаток есть свойство ПРИЛЕТЕВШЕГО, а не
// рабочей вершины. Спроси рабочую — и собственная добавленная миграция вошла бы
// в исторический остаток, то есть находка о ПРОШЛОМ росла бы от правки,
// которая прошлым ещё не стала. Добавленное этой полосой стволу неизвестно и
// приходит разницей «прослежено 32 из 33», а не молчанием.
func historicalOutOfOrder(t *testing.T, root string, dirFiles []string) (findings []string, seen int) {
	t.Helper()

	present := map[string]bool{}
	for _, rel := range dirFiles {
		if check.IsMigrationFile(rel) {
			present[rel] = true
		}
	}

	// `--no-renames` несущий: переименование файла git отдаёт НЕ добавлением, и
	// файл, приехавший в цепочку под новым именем, выпал бы из прослеженного
	// молча. Видно это было бы только числом «прослежено 32 из 33» — ради
	// которого оно и печатается, — но считать такой файл непрослеженным
	// неверно: в цепочку он встал, и встал именно тогда.
	out, err := gitenv.Command(root, "log", "--reverse", "--diff-filter=A",
		"--no-renames", "--name-only", "--format=%H", trunkRefName, "--",
		check.MigrationsDirRel+"/*.sql").Output()
	if err != nil {
		t.Logf("история каталога миграций не прочитана: %v — исторический остаток "+
			"НЕ ИЗМЕРЕН (это не «ноль»)", err)
		return nil, 0
	}

	// Последовательность ввода: у файла, вводившегося не раз, считается
	// ПОСЛЕДНИЙ ввод — он и поставил в цепочку тот файл, что лежит сейчас.
	type intro struct {
		commit string
		rel    string
	}
	var order []intro
	at := map[string]int{}
	commit := ""
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "":
		case !strings.Contains(line, "/"):
			commit = line
		case present[line]:
			if i, had := at[line]; had {
				order[i].rel = ""
			}
			at[line] = len(order)
			order = append(order, intro{commit: commit, rel: line})
		}
	}

	var (
		max     int64
		pending int64
		prev    string
	)
	for _, it := range order {
		if it.rel == "" {
			continue
		}
		seen++
		if it.commit != prev {
			if pending > max {
				max = pending
			}
			pending, prev = 0, it.commit
		}
		mv, ok := check.MigrationVersionOf(it.rel[strings.LastIndexByte(it.rel, '/')+1:])
		if !ok {
			continue
		}
		if seen > 1 && mv.Value <= max {
			findings = append(findings, fmt.Sprintf("%s — номер %d при уже лежавшем %d",
				it.rel, mv.Value, max))
		}
		if mv.Value > pending {
			pending = mv.Value
		}
	}
	return findings, seen
}

// joinPast — хвост строки переписи. Пустой перечень печатается пустотой, а не
// словом «нет»: число перед ним уже сказано.
func joinPast(past []string) string {
	if len(past) == 0 {
		return ""
	}
	return ":\n  " + strings.Join(past, "\n  ")
}
