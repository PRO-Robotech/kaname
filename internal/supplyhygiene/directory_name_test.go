// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// directory_name_test.go — каталоги службы зовутся именем СВОЕГО продукта.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Служба получила собственное имя продукта — Kaname, — а её внутренние каталоги
// продолжали звать себя именем платформы: `internal/apps/kacho/` и
// `internal/repo/kacho/`. Раскладка каталогов не деталь сборки: README подаёт её
// читателю как структуру ЭТОГО продукта, она стоит в каждом пути импорта, в
// каждой координате приёмки и в каждом предикате замера. То есть это ровно то,
// чем продукт себя называет, — а не код, который он исполняет.
//
// Различение проведено по вопросу владельца: имя, которым продукт себя
// называет, — своё; код, который он исполняет, — берётся у платформы как есть.
// Путь МОДУЛЯ своё имя УЖЕ получил (`github.com/PRO-Robotech/kaname`) — это
// сделала своя полоса, не эта. Пакет контракта (`kaname.cloud.iam.v1`) и общий
// слой проб платформы остаются прежними: их переименование есть предмет других
// полос, и захват их сюда сделал бы вердикт этой непрослеживаемым.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО УТВЕРЖДАЕТСЯ — три вещи, и все три вместе
//
//  1. канонический сегмент ПРИСУТСТВУЕТ в дереве службы — и как имя каталога, и
//     в ссылках на него. Без этого условия отрицание ниже выполнилось бы на
//     дереве, из которого вынесли всё разом: отрицание без положительного
//     близнеца есть вакуумное утверждение;
//  2. отставленного сегмента в дереве службы НЕТ ни в одном виде — ни именем
//     каталога, ни ссылкой в пути импорта, ни координатой в прозе;
//  3. перепись НАЗЫВАЕТСЯ числами: файлов прочитано, сегментов канонических и
//     отставленных, ссылок каждого вида, пропущено по каждой причине. Пустой
//     обход — отказ, иначе «ноль находок» неотличимо от «ноль прочитанного».
//
// ─────────────────────────────────────────────────────────────────────────────
// РАСПОЗНАВАТЕЛЬ ОБЯЗАН ЗНАТЬ СОСЕДЕЙ, ДЕЛЯЩИХ С СЕГМЕНТОМ ИМЯ
//
// Главный способ ошибиться здесь — судить по слову `kacho`. Его несут ТРИ
// соседних предмета, и ни один каталогом этой службы не является:
//
//	kaname.cloud.iam.v1     пакет контракта и порождённые из него стабы;
//	services/nlb/internal/ каталог СОСЕДНЕЙ службы. У неё своего имени продукта
//	  (apps|repo)/kacho    нет, и её каталог законно зовётся именем платформы.
//	kacho-vpc/internal/…   Ссылка на него из нашего дерева — законна;
//	cluster_root,    якорь кластера · метрика · ручка окружения · схема
//	  kacho_quota_refuse,  Postgres. Пространства свои, потребители свои, гейты
//	  KACHO_*              свои. Имя схемы здесь НЕ пишется дословно: его
//	                       отставляет соседняя полоса, и её гейт справедливо
//	                       считает такую цитату находкой.
//
// Все четыре полосы распознаватель ПРОПУСКАЕТ by construction: он судит не
// слово, а ДВУСОСТАВНУЮ форму `apps/kacho` и `repo/kacho` — родительский каталог
// плюс сегмент, — и отдельно сегмент пути как таковой. Ни одна из четырёх полос
// такой формы не имеет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВЕ ПРОПУЩЕННЫЕ ПОЛОСЫ, И ПРИЧИНЫ У НИХ РАЗНЫЕ
//
// ПРИМЕНЁННАЯ МИГРАЦИЯ. Её править запрещено (ban #5), поэтому координата в её
// шапке остаётся отставленной. Это НЕ послабление проверке, а названный остаток:
// полоса считается отдельным числом, и «в миграциях 0» отличимо от «миграции не
// рассматривались». Полоса истечёт вместе с предметом — новой миграцией, которая
// перепишет шапку, либо задачей, снявшей ссылку.
//
// ЗАХВАЧЕННЫЕ ОТЧЁТЫ ПРОГОНОВ. Отчёт замера свидетельствует о том, что было:
// он несёт вывод команды, исполненной на прежнем дереве. Правка обратила бы
// верное утверждение в ложное. Полоса тоже считается отдельным числом.
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРЕТЬЯ ПОЛОСА — САМА ПРОВЕРКА И ЕЁ ДОКАЗАТЕЛЬСТВО
//
// Проверка обязана НАЗЫВАТЬ то, что запрещает: без отставленного сегмента у
// распознавателя нет входа, а у инъекции нет дефекта. Судя себя, проверка
// краснела бы на собственном объяснении — тот же класс, что гейт, ищущий слово
// в сыром тексте и находящий его в комментарии рядом.
//
// Полоса задана ПЕРЕЧНЕМ ФАЙЛОВ, а не признаком формы: признак («файл объявляет
// константу») освободил бы и всякий прод-код, объявивший ту же строку, то есть
// ровно тех, кого проверка и заводилась ловить. Файл ВНЕ перечня судится как
// любой другой, и это доказано инъекцией.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА ПРОВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
// Она судит ДЕРЕВО СЛУЖБЫ и молчит обо всём, что лежит вне его корня: о гейтах
// монорепо, о крае, о провайдере инфраструктуры, о контракте и порождённых из
// него стабах. Там координаты каталогов службы тоже стоят, и правятся они тем же
// изменением, но предикатом этой проверки не удержаны: у неё нет доступа к
// чужому корню.
package supplyhygiene

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
	"github.com/stretchr/testify/require"
)

// canonicalSegment — имя, которым служба зовёт свои каталоги. ОДНО объявление
// на дерево: и проверка, и её инъекция читают отсюда, поэтому «что проверяется»
// и «что объявлено» разойтись не могут.
const canonicalSegment = "kaname"

// retiredSegment — имя, которое каталоги носили, пока служба звалась доменом
// платформы. Оставлено здесь не памяти ради: это ВХОД распознавателя, и без
// него проверка не смогла бы назвать координату находки.
const retiredSegment = "kacho"

// parentDirs — родительские каталоги, чей ребёнок и есть предмет проверки.
// Форма ДВУСОСТАВНА намеренно: одинокое слово `kacho` несут путь модуля, пакет
// контракта, имя схемы и якорь кластера — ни один из них каталогом не является.
var parentDirs = [...]string{"apps", "repo"}

// dirNameCheckOwnFiles — файлы, ПРЕДМЕТ которых есть само переименование: сама
// проверка и её доказательство инъекцией. Каждый обязан называть отставленный
// сегмент, чтобы делать свою работу.
var dirNameCheckOwnFiles = map[string]bool{
	"internal/supplyhygiene/directory_name_test.go":           true,
	"internal/supplyhygiene/directory_name_injection_test.go": true,
}

// appliedMigrationDir — каталог применённых миграций. Их шапки правке не
// подлежат (ban #5), поэтому полоса пропускается и считается отдельно.
const appliedMigrationDir = "internal/migrations/"

// isCapturedReport — файл есть захваченный вывод прогона: отчёт замера либо
// результат нагрузочной пробы. Свидетельствует о том, что было.
func isCapturedReport(rel string) bool {
	rel = filepath.ToSlash(rel)
	return strings.Contains(rel, "/REPORT-") || strings.HasPrefix(rel, "REPORT-") ||
		strings.HasPrefix(rel, "tests/k6/results/")
}

// isForeignService — вхождение принадлежит каталогу СОСЕДНЕЙ службы. У соседей
// своего имени продукта нет, их каталог законно зовётся именем платформы, и
// ссылка на него из нашего дерева переименованию не подлежит.
//
// Судится ПРЕФИКС слева от вхождения: анкер соседа стоит непосредственно перед
// `internal/`, поэтому проза, где имя соседа встретилось раньше в предложении,
// под правило не подпадает.
func isForeignService(line string, at int) bool {
	prefix := line[:at]
	cut := strings.LastIndex(prefix, "internal/")
	if cut < 0 {
		return false
	}
	head := prefix[:cut]
	for _, svc := range [...]string{"vpc", "nlb", "geo", "compute", "storage", "registry"} {
		if strings.HasSuffix(head, "services/"+svc+"/") || strings.HasSuffix(head, "kacho-"+svc+"/") {
			return true
		}
	}
	return false
}

// dirNameCensus — объём осмотренного. Печатается всегда, включая зелёный
// прогон: «ноль находок» обязано быть отличимо от «ноль прочитанного».
type dirNameCensus struct {
	filesRead         int // файлов дерева прочитано
	filesBinary       int // пропущено как двоичные
	canonicalSegments int // путей, чей сегмент есть канонический
	retiredSegments   int // путей, чей сегмент есть отставленный
	canonicalRefs     int // ссылок вида `apps/kaname` · `repo/kaname`
	retiredRefs       int // ссылок вида `apps/kacho` · `repo/kacho` — находки
	skippedForeign    int // пропущено: каталог соседней службы
	skippedMigration  int // пропущено: применённая миграция (ban #5)
	filesMigration    int // файлов применённых миграций пропущено целиком
	skippedReport     int // пропущено: захваченный отчёт прогона
	filesReport       int // файлов отчётов пропущено целиком
	skippedOwn        int // пропущено: сама проверка и её доказательство
	filesOwn          int // файлов перечня «предмет = это переименование»
}

// dirNameFinding — одно вхождение отставленного имени.
type dirNameFinding struct {
	file string
	line int // 0 — находка в самом пути, а не в содержимом
	text string
}

func (f dirNameFinding) String() string {
	if f.line == 0 {
		return fmt.Sprintf("%s: сегмент пути", f.file)
	}
	return fmt.Sprintf("%s:%d: %s", f.file, f.line, strings.TrimSpace(f.text))
}

// isSegmentByte — байт, продолжающий сегмент пути.
func isSegmentByte(b byte) bool {
	return b == '_' || b == '-' || (b >= 'a' && b <= 'z') ||
		(b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// hasSegment — путь несёт РОВНО такой сегмент. Сравнение посегментное, а не
// подстрокой: `kacho-vpc` сегментом `kacho` не является, и засчитывать его
// значило бы судить слово вместо каталога.
func hasSegment(rel, seg string) bool {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == seg {
			return true
		}
	}
	return false
}

// countRefs считает ссылки вида `<parent>/<seg>` в строке, пропуская чужие
// службы. Возвращает найденное и число пропущенных соседей отдельно.
func countRefs(line, seg string, skipForeign bool) (hits []int, foreign int) {
	for _, parent := range parentDirs {
		needle := parent + "/" + seg
		for at := 0; ; {
			idx := strings.Index(line[at:], needle)
			if idx < 0 {
				break
			}
			abs := at + idx
			end := abs + len(needle)
			at = end
			// Правая граница: продолжение сегмента означает другое имя
			// (`apps/kachopg`), и каталогом предмета оно не является.
			if end < len(line) && isSegmentByte(line[end]) {
				continue
			}
			// Левая граница: `xapps/kacho` — не наш родитель.
			if abs > 0 && isSegmentByte(line[abs-1]) {
				continue
			}
			if skipForeign && isForeignService(line, abs) {
				foreign++
				continue
			}
			hits = append(hits, abs)
		}
	}
	return hits, foreign
}

// scanDirectoryNames разбирает ПРОИЗВОЛЬНЫЙ корень: настоящее дерево службы и
// синтетический корень инъекции проходят одну и ту же функцию, поэтому
// доказанное на втором верно для первого.
func scanDirectoryNames(tree *treecorpus.Tree) (dirNameCensus, []dirNameFinding, error) {
	var census dirNameCensus
	var findings []dirNameFinding

	root := tree.Root()
	for _, rel := range tree.SortedFiles() {
		slash := filepath.ToSlash(rel)

		// Ось 1 — САМ ПУТЬ. Судится у каждого файла без исключений: каталог,
		// названный чужим именем, есть находка независимо от содержимого.
		if hasSegment(slash, canonicalSegment) {
			census.canonicalSegments++
		}
		if hasSegment(slash, retiredSegment) {
			census.retiredSegments++
			findings = append(findings, dirNameFinding{file: slash})
		}

		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			return census, nil, fmt.Errorf("каталоги: файл %s не прочитан: %w", rel, err)
		}
		if strings.IndexByte(string(raw), 0) >= 0 {
			census.filesBinary++
			continue
		}
		census.filesRead++

		own := dirNameCheckOwnFiles[slash]
		migration := strings.HasPrefix(slash, appliedMigrationDir)
		report := isCapturedReport(slash)

		var fileRetired int
		for i, line := range strings.Split(string(raw), "\n") {
			canon, _ := countRefs(line, canonicalSegment, false)
			census.canonicalRefs += len(canon)

			hits, foreign := countRefs(line, retiredSegment, true)
			census.skippedForeign += foreign
			if len(hits) == 0 {
				continue
			}
			fileRetired += len(hits)
			switch {
			case own:
				census.skippedOwn += len(hits)
			case migration:
				census.skippedMigration += len(hits)
			case report:
				census.skippedReport += len(hits)
			default:
				census.retiredRefs += len(hits)
				findings = append(findings, dirNameFinding{file: slash, line: i + 1, text: line})
			}
		}
		if fileRetired > 0 {
			switch {
			case own:
				census.filesOwn++
			case migration:
				census.filesMigration++
			case report:
				census.filesReport++
			}
		}
	}

	if census.filesRead == 0 {
		return census, nil, fmt.Errorf("каталоги: обход пуст — вердикт беспредметен (корень %q)", root)
	}
	return census, findings, nil
}

// TestServiceDirectoriesAreNamedForTheirOwnProduct — гейт класса.
func TestServiceDirectoriesAreNamedForTheirOwnProduct(t *testing.T) {
	tree, err := treecorpus.NewTree(serviceRoot)
	require.NoError(t, err, "состав дерева службы не собран — вердикт беспредметен")

	census, findings, err := scanDirectoryNames(tree)
	require.NoError(t, err)

	t.Logf("перепись: файлов прочитано %d · двоичных пропущено %d · "+
		"путей с сегментом %q %d · с сегментом %q %d · "+
		"ссылок на %q %d · на %q %d · "+
		"пропущено соседних служб %d · применённых миграций %d файлов (%d ссылок) · "+
		"отчётов %d файлов (%d ссылок) · файлов самой проверки %d (%d ссылок)",
		census.filesRead, census.filesBinary,
		canonicalSegment, census.canonicalSegments,
		retiredSegment, census.retiredSegments,
		canonicalSegment, census.canonicalRefs,
		retiredSegment, census.retiredRefs,
		census.skippedForeign,
		census.filesMigration, census.skippedMigration,
		census.filesReport, census.skippedReport,
		census.filesOwn, census.skippedOwn)

	require.NotZero(t, census.canonicalSegments,
		"положительный контроль пуст: каталога с именем %q в дереве нет вовсе — "+
			"отрицание ниже выполнилось бы на дереве, из которого вынесли всё", canonicalSegment)
	require.NotZero(t, census.canonicalRefs,
		"положительный контроль пуст: ссылок вида `apps/%s` · `repo/%s` в дереве нет — "+
			"значит распознаватель ссылок не работает вовсе", canonicalSegment, canonicalSegment)

	if len(findings) > 0 {
		shown := findings
		if len(shown) > 20 {
			shown = shown[:20]
		}
		var b strings.Builder
		for _, f := range shown {
			b.WriteString("\n  " + f.String())
		}
		t.Fatalf("каталоги службы зовутся отставленным именем %q в %d местах "+
			"(показаны первые %d):%s\n\nимя каталога — то, чем продукт себя называет; "+
			"канон объявлен константой canonicalSegment в этом файле",
			retiredSegment, len(findings), len(shown), b.String())
	}
}
