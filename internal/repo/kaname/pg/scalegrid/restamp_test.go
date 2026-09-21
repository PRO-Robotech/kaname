// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid_test

// restamp_test.go — ПЕРЕСЧЁТ ШАПКИ БЕЗ ПЕРЕСЪЁМКИ.
//
// # Зачем это вообще нужно
//
// Отпечаток сторожит вопрос «изменилось ли ТО, ЧТО отчёт мерил». Ответ на него
// зависит от двух вещей: от дерева и от ПРЕДИКАТА, которым множество под
// отпечатком отбирается. Гейт сравнивает множества и различить их не может:
// файл, вышедший из предмета из-за сужения предиката, выглядит у него точно так
// же, как файл, исчезнувший из дерева.
//
// Поэтому у сужения предиката есть две цены, и они РАЗНЫЕ:
//
//	дерево двигалось     отчёт несвеж по существу  →  пересъёмка, около 2 часов
//	двигался предикат    отчёт верен как был       →  пересчёт шапки, секунды
//
// Вторая стоит секунд, и отдавать за неё два часа — то же самое, что платить
// пересъёмкой за ложный красный, против которого это сужение и заводилось.
//
// # Когда пересчёт ЗАКОНЕН
//
// Ровно тогда, когда каждый файл, лежащий под отпечатком СЕГОДНЯ, имел на
// момент замера то же содержимое. Условие распадается надвое:
//
//	файл ОСТАВШИЙСЯ  шапка записала его хэш — сверяется здесь, пофайлово;
//	файл ПРИШЕДШИЙ   шапка о нём не знает ничего — сверяется ПО РЕВИЗИИ замера,
//	                 командой `git rev-parse <ревизия>:<путь>`, и результат
//	                 записывается в шапку рядом с пересчётом.
//
// Второе условие этот код проверить не может и не притворяется, что может:
// ревизия отчёта о записи в дереве службы не разрешается вовсе — он снят до
// выноса службы отдельным репозиторием. Поэтому пересчёт ТРЕБУЕТ, чтобы довод
// по пришедшим файлам был передан ему словами, и печатает его в шапку.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// restampNoteMark — строка, которой пересчёт объявляет себя в шапке.
const restampNoteMark = "  пересчёт шапки      "

// restampHeader — текст отчёта с ПЕРЕСЧИТАННЫМ блоком отпечатка.
//
// Возвращает новый текст и перечень отказов. Отказы непусты — текст не менялся:
// пересчёт, сделанный на несошедшихся файлах, записал бы в шапку свежесть,
// которой нет.
func restampHeader(text string, fp scalegrid.Fingerprint, lines, note string) (string, []string) {
	var refusals []string

	recorded := recordedFileHashes(text)
	if len(recorded) == 0 {
		refusals = append(refusals, "в шапке НЕТ пофайлового перечня: сверять пересчёт не с чем, "+
			"и он записал бы утверждение, которого никто не проверял")
	}
	if len(fp.Files) == 0 {
		refusals = append(refusals, "под отпечатком НОЛЬ файлов: пересчитывать нечего")
	}

	// ОСТАВШИЕСЯ файлы: содержимое обязано совпасть пофайлово. Разошлось —
	// предмет замера сдвинулся по существу, и лечится это пересъёмкой.
	var moved, common []string
	for i, id := range fp.Identities {
		was, known := recorded[id]
		if !known {
			continue
		}
		common = append(common, id)
		if now := fileHashInLines(lines, id); now != "" && now != was.hash {
			moved = append(moved, fmt.Sprintf("%s (было %s, стало %s)", id, was.hash, now))
		}
		_ = i
	}
	if len(moved) > 0 {
		refusals = append(refusals, "ОСТАВШИЕСЯ под отпечатком файлы ДВИГАЛИСЬ: "+
			strings.Join(moved, ", ")+
			"\n  Это сдвиг предмета замера по существу, и пересчёт шапки его не лечит: "+
			"нужна пересъёмка")
	}
	if len(common) == 0 && len(recorded) > 0 && len(fp.Files) > 0 {
		refusals = append(refusals, "у шапки и дерева НЕТ НИ ОДНОГО общего файла: "+
			"сверять пересчёт не с чем")
	}
	if strings.TrimSpace(note) == "" {
		refusals = append(refusals, "довод по ПРИШЕДШИМ файлам не передан: пересчёт обязан "+
			"назвать, чем доказано, что новый файл предмета лежал в дереве замера неподвижно")
	}
	if len(refusals) > 0 {
		return text, refusals
	}

	start := strings.Index(text, scalegrid.MarkerComposition)
	listAt := strings.Index(text, scalegrid.MarkerFileList)
	if start < 0 || listAt < 0 {
		return text, []string{"в шапке нет блока отпечатка: заменять нечего"}
	}
	// Прежняя пометка о пересчёте входит в заменяемое: иначе пометки копились
	// бы одна на другой, и шапка несла бы столько доводов, сколько было
	// пересчётов, — каждый о своём, и ни один не отменён.
	if prev := strings.LastIndex(text[:start], restampNoteMark); prev >= 0 {
		start = prev
	}
	// Конец блока — первая строка за перечнем, не начинающаяся с его отступа.
	// Сперва снимается перевод строки САМОГО заголовка перечня: без этого шага
	// обход обрывался на нём, старый перечень оставался в тексте, и шапка
	// получала его ДВАЖДЫ. Дефект был молчаливым — гейт сверяет перечень картой
	// по тождеству, и повтор в ней схлопывается.
	end := listAt + len(scalegrid.MarkerFileList)
	if end < len(text) && text[end] == '\n' {
		end++
	}
	for _, line := range strings.SplitAfter(text[end:], "\n") {
		if !strings.HasPrefix(line, scalegrid.MarkerFile) {
			break
		}
		end += len(line)
	}

	out := text[:start] + restampNoteMark + note + "\n" + lines + text[end:]
	return out, nil
}

// fileHashInLines — хэш файла по тождеству из свежесосчитанного блока.
func fileHashInLines(lines, identity string) string {
	for _, line := range strings.Split(lines, "\n") {
		if !strings.HasPrefix(line, scalegrid.MarkerFile) {
			continue
		}
		f := strings.Fields(strings.TrimSpace(line))
		if len(f) == 3 && f[1] == identity {
			return f[0]
		}
	}
	return ""
}

// TestRestampRefusesWhenTheSubjectItselfMoved — пересчёт ОТКАЗЫВАЕТ там, где
// сдвинулся предмет, и молчит там, где сдвинулся только предикат.
//
// Инъекция на СИНТЕТИКЕ, не на живой шапке: живая шапка сегодня сходится, и
// проба, построенная на ней, проверяла бы совпадение, а не способность отказать.
func TestRestampRefusesWhenTheSubjectItselfMoved(t *testing.T) {
	const identity = "миграции/0001_initial.sql"
	head := "ПРОВЕНАНС\n  снято               2026-09-17 10:58:04 MSK\n\n" +
		"ОТПЕЧАТОК ПРЕДМЕТА ЗАМЕРА\n"
	block := func(hash string) string {
		return scalegrid.MarkerComposition + "aaaaaaaaaaaaaaaa\n" +
			scalegrid.MarkerContent + "bbbbbbbbbbbbbbbb\n" +
			"  файлов под отпечатком 1, таблиц выведено 1 (kaname.users)\n" +
			"  предикат отпечатка    синтетика\n" +
			scalegrid.MarkerFileList + "\n" +
			scalegrid.MarkerFile + hash + "  " + identity + "  services/iam/internal/migrations/0001_initial.sql\n"
	}
	tail := "\nСЕТКА\n  ось N: 100\n"

	fp := scalegrid.Fingerprint{
		Files:      []string{"services/iam/internal/migrations/0001_initial.sql"},
		Identities: []string{identity},
		Tables:     []string{"kaname.users"},
	}

	// (1) ДЕФЕКТ: оставшийся файл двигался — пересчёт обязан отказать.
	_, refusals := restampHeader(head+block("1111111111111111")+tail, fp,
		block("2222222222222222"), "довод есть")
	if len(refusals) == 0 {
		t.Fatal("пересчёт принят на ДВИГАВШЕМСЯ файле: он записал бы в шапку свежесть, " +
			"которой нет, и пересъёмка не состоялась бы там, где она нужна")
	}
	t.Logf("отказ на двигавшемся файле: %s", refusals[0])

	// (2) ЗАКОННЫЙ БЛИЗНЕЦ: тот же файл с ТЕМ ЖЕ хэшем — пересчёт проходит.
	// Отличие от дефекта РОВНО ОДНО: значение хэша.
	out, refusals := restampHeader(head+block("1111111111111111")+tail, fp,
		block("1111111111111111"), "довод есть")
	if len(refusals) != 0 {
		t.Fatalf("пересчёт отвергнут на НЕПОДВИЖНОМ файле: %v", refusals)
	}
	if !strings.Contains(out, restampNoteMark) {
		t.Fatal("пересчёт не объявил себя в шапке: читатель не узнает, что блок пересчитан")
	}
	if !strings.Contains(out, "СЕТКА") || !strings.Contains(out, "ПРОВЕНАНС") {
		t.Fatal("пересчёт съел соседние разделы: он владеет ТОЛЬКО блоком отпечатка")
	}

	// (3) ПЕРЕЧЕНЬ НЕ ЗАДВАИВАЕТСЯ, и пересчёт ИДЕМПОТЕНТЕН.
	//
	// Дефект был ровно здесь и был молчаливым: гейт читает перечень картой по
	// тождеству, и повтор строки в ней схлопывается — шапка выглядела исправной,
	// будучи вдвое длиннее.
	if got := strings.Count(out, "  "+identity+"  "); got != 1 {
		t.Fatalf("тождество %s встречается в пересчитанной шапке %d раз, ожидался 1: "+
			"старый перечень не снят, и шапка несёт две редакции разом", identity, got)
	}
	again, refusals := restampHeader(out, fp, block("1111111111111111"), "довод есть")
	if len(refusals) != 0 {
		t.Fatalf("повторный пересчёт отвергнут: %v", refusals)
	}
	if again != out {
		t.Fatal("пересчёт НЕ идемпотентен: второй проход дал другой текст — значит первый " +
			"оставил в шапке что-то своё")
	}

	// (4) Довод по пришедшим файлам обязателен: без него пересчёт беспредметен.
	if _, r := restampHeader(head+block("1111111111111111")+tail, fp,
		block("1111111111111111"), "   "); len(r) == 0 {
		t.Fatal("пересчёт принят БЕЗ довода о пришедших файлах")
	}

	// (5) Шапка без пофайлового перечня — отказ, а не молчание.
	if _, r := restampHeader(head+tail, fp, block("1111111111111111"), "довод есть"); len(r) == 0 {
		t.Fatal("пересчёт принят на шапке БЕЗ перечня: сверять было не с чем")
	}
}

// TestRestampGuardedReportHeaders — сам пересчёт. Под ручкой, как и съёмка.
//
//	KACHO_SCALEGRID_RESTAMP='<довод по пришедшим файлам>' \
//	  go test ./internal/repo/kaname/pg/scalegrid/ -run TestRestampGuardedReportHeaders -count=1 -v
//
// # Отчёты ВЫВОДЯТСЯ обходом, а не выписываются
//
// Первая редакция брала перечень у `guardedReports()` — и промахнулась мимо
// ЧЕТВЁРТОГО отчёта: полный замер объёма сторожится своим гейтом в соседнем
// пакете, и перечень этого пакета о нём не знает. Выписанный перечень не
// двигался бы и от пятого.
//
// # Что охраняет обход от лишнего
//
// Не всякий отчёт с отпечатком подлежит пересчёту: рядом лежит БАЗОВЫЙ ЗАМЕР,
// снятый на дереве, которого больше нет, — он описывает прошлое НАМЕРЕННО.
// Отличается он не именем, а проверкой: у пересчитываемого отчёта каждый
// оставшийся файл обязан совпасть побайтово, а каждый выбывший — существовать в
// дереве. У базового замера не совпадает ни то ни другое, и он отсеивается САМ.
func TestRestampGuardedReportHeaders(t *testing.T) {
	note := os.Getenv("KACHO_SCALEGRID_RESTAMP")
	if strings.TrimSpace(note) == "" {
		t.Skip("пересчёт шапки не запрошен (KACHO_SCALEGRID_RESTAMP пуст) — " +
			"это ручная операция, как и сама съёмка")
	}
	root, _ := platformtree.RequireCorpus(t)

	reports := reportArtifacts(t, root)
	if len(reports) == 0 {
		t.Fatal("в каталоге сетки НЕ НАЙДЕНО ни одного отчёта с отпечатком: " +
			"обход пуст, и «пересчитано 0» означало бы «читать было нечего»")
	}

	instruments := []struct {
		name string
		f    func(string) (scalegrid.Fingerprint, error)
	}{
		{"чтение", scalegrid.ComputeFingerprint},
		{"запись и удаление", scalegrid.ComputeWriteDeleteFingerprint},
	}

	var done, skipped int
	for _, path := range reports {
		body, err := os.ReadFile(path) // #nosec G304 -- path получен обходом собственного каталога отчётов
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		text := string(body)

		// Прибор ВЫВОДИТСЯ: тот, у кого с записанным перечнем больше общего.
		best, bestName, bestShare := scalegrid.Fingerprint{}, "", 0
		recorded := recordedFileHashes(text)
		for _, inst := range instruments {
			fp, ferr := inst.f(root)
			if ferr != nil {
				t.Fatalf("%s: отпечаток «%s» не вычислен: %v", path, inst.name, ferr)
			}
			share := 0
			for _, id := range fp.Identities {
				if _, ok := recorded[id]; ok {
					share++
				}
			}
			if share > bestShare {
				best, bestName, bestShare = fp, inst.name, share
			}
		}
		if bestShare == 0 {
			t.Logf("%s: ПРОПУЩЕН — ни один прибор не имеет с его перечнем ничего общего",
				shortName(path))
			skipped++
			continue
		}

		out, refusals := restampHeader(text, best, best.FingerprintLines(root), note)
		if len(refusals) == 0 {
			refusals = departedFilesRefusals(root, recorded, best)
		}
		if len(refusals) > 0 {
			t.Logf("%s: ПРОПУЩЕН (прибор «%s», общих файлов %d):\n    %s",
				shortName(path), bestName, bestShare, strings.Join(refusals, "\n    "))
			skipped++
			continue
		}
		if err := os.WriteFile(path, []byte(out), 0o600); err != nil {
			t.Fatalf("%s: запись: %v", path, err)
		}
		done++
		t.Logf("%s: блок отпечатка пересчитан по прибору «%s» — файлов %d, состав %s, содержимое %s",
			shortName(path), bestName, len(best.Files), best.Composition, best.Content)
	}
	t.Logf("ПЕРЕПИСЬ: отчётов с отпечатком %d · пересчитано %d · пропущено %d",
		len(reports), done, skipped)
}

// departedFilesRefusals — выбывшие файлы обязаны ОСТАТЬСЯ В ДЕРЕВЕ.
//
// Файл, вышедший из предмета потому, что предикат сузился, в дереве лежит.
// Файл, вышедший потому, что его удалили, — нет, и тогда отчёт несвеж по
// существу: пересчёт шапки записал бы свежесть, которой нет.
func departedFilesRefusals(root string, recorded map[string]recordedFile, fp scalegrid.Fingerprint) []string {
	stays := map[string]bool{}
	for _, id := range fp.Identities {
		stays[id] = true
	}
	var gone []string
	for id, rec := range recorded {
		if stays[id] {
			continue
		}
		abs, aerr := platformtree.PathUnder(root, rec.path)
		if aerr != nil {
			gone = append(gone, id+" ("+rec.path+": координата не приведена к посадке)")
			continue
		}
		if _, err := os.Stat(abs); err != nil {
			gone = append(gone, id+" ("+rec.path+")")
		}
	}
	if len(gone) == 0 {
		return nil
	}
	sort.Strings(gone)
	return []string{"ВЫБЫВШИЕ файлы в дереве ОТСУТСТВУЮТ: " + strings.Join(gone, ", ") +
		"\n    Это сдвиг дерева, а не предиката, и пересчёт шапки его не лечит: нужна пересъёмка"}
}

// reportArtifacts — отчёты каталога сетки, несущие блок отпечатка.
func reportArtifacts(t *testing.T, root string) []string {
	t.Helper()
	dir := platformtree.RequirePath(t, scalegrid.ReportPath)
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatalf("состав каталога отчётов: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "REPORT-") || !strings.HasSuffix(e.Name(), ".txt") {
			continue
		}
		p := filepath.Join(filepath.Dir(dir), e.Name())
		body, rerr := os.ReadFile(p) // #nosec G304 -- p получен обходом собственного каталога отчётов
		if rerr != nil {
			t.Fatalf("чтение %s: %v", e.Name(), rerr)
		}
		if strings.Contains(string(body), scalegrid.MarkerComposition) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}

func shortName(path string) string { return filepath.Base(path) }
