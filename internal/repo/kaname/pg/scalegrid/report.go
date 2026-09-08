// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scalegrid

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// ПРОВЕНАНС ЗАМЕРА — И ПОЧЕМУ В НЁМ ПОЯВИЛСЯ ПРИЗНАК ЧИСТОТЫ ДЕРЕВА
//
// Ревизию в шапку отчёта кладут все приборы этого дерева. Признак чистоты —
// НИ ОДИН (предикат: `--porcelain` встречается в дереве дважды, и оба раза вне
// Go — в скрипте локального прогона и в Makefile развёртывания).
//
// Цена этого пропуска ровно та же, что у провенанса стенда: на ГРЯЗНОЙ рабочей
// копии `git rev-parse HEAD` называет коммит, который замер НЕ ИСПОЛНЯЛ — в
// дереве лежали несохранённые правки, — и отчёт утверждает про ревизию то, чего
// на ней нет. Через месяц это неотличимо от честного замера: повторить по
// названной ревизии не выйдет, а почему — не написано.
//
// Поэтому провенанс несёт ПАРУ: ревизию и состояние дерева на момент замера.
// Грязное дерево замер не запрещает — оно делает его пометку обязательной.

// Provenance — на чём и когда снят замер.
type Provenance struct {
	// TreeRev — ревизия дерева; TreeDirty — были ли на ней несохранённые
	// правки; DirtyPaths — сколько именно путей разошлось.
	TreeRev    string
	TreeDirty  bool
	DirtyPaths int
	// DirtyPathList — САМИ пути, как их назвал git.
	//
	// Числа мало: «грязных путей 3» не говорит, разошёлся ли ПРЕДМЕТ ЗАМЕРА или
	// рядом лежит артефакт соседнего прогона. Пока пути не названы, шапка обязана
	// оставаться пессимистичной — «не знаю» не выдаётся за «чисто».
	DirtyPathList []string
	When          time.Time
	CPUModel      string
	CPUCores      int
	Postgres      string
	// RunCommand — ДОСЛОВНАЯ команда повторения. Отчёт без неё невалиден: это
	// число, которое нечем проверить через месяц.
	RunCommand string
	// GridDigest / GridText — сетка, на которой снято.
	GridDigest string
	GridText   string
	// Fingerprint — отпечаток ПРЕДМЕТА замера: то, изменение чего делает отчёт
	// утверждением о прошлом, поданным как утверждение о настоящем.
	Fingerprint Fingerprint
	// treeRoot — корень, от которого считан отпечаток.
	treeRoot string
}

// TakeProvenance — провенанс из окружения прогона.
//
// Git зовётся ТОЛЬКО через `pkg/gitenv`: прямой `exec.Command("git", …)` в
// этом дереве — находка гейта, потому что унаследованные `GIT_DIR`/`GIT_INDEX_FILE`
// увели бы команду в чужой репозиторий и ревизия относилась бы не к тому дереву.
func TakeProvenance(runCommand string, grid [][]Point) Provenance {
	p := Provenance{
		When:       time.Now(),
		CPUCores:   runtime.NumCPU(),
		CPUModel:   cpuModel(),
		RunCommand: runCommand,
		GridDigest: Digest(grid),
		GridText:   Describe(grid),
		TreeRev:    "не установлена",
	}
	if out, err := gitenv.Command("", "rev-parse", "HEAD").Output(); err == nil {
		p.TreeRev = strings.TrimSpace(string(out))
	}
	// Чистота дерева — ОТДЕЛЬНЫЙ вопрос, и «команда не выполнилась» не то же
	// самое, что «дерево чисто»: молчание здесь означало бы чистоту, которой
	// никто не проверял.
	if out, err := gitenv.Command("", "status", "--porcelain").Output(); err == nil {
		p.DirtyPathList = ParsePorcelainPaths(out)
		p.DirtyPaths = len(p.DirtyPathList)
		p.TreeDirty = p.DirtyPaths > 0
	} else {
		p.DirtyPaths = -1
		p.TreeDirty = true
	}
	// Отпечаток предмета берётся ТОЙ ЖЕ функцией, какой его пересчитает гейт:
	// вторая реализация разошлась бы с первой молча — и разошлась бы там, где
	// обе печатают «совпало».
	if top, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output(); err == nil {
		root := strings.TrimSpace(string(top))
		p.treeRoot = root
		if fp, ferr := ComputeFingerprint(root); ferr == nil {
			p.Fingerprint = fp
		}
	}
	return p
}

// cpuModel — модель процессора; замер времени без неё — число без машины.
func cpuModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return "неизвестна (" + runtime.GOARCH + ")"
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "model name") {
			if i := strings.IndexByte(line, ':'); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return "неизвестна (" + runtime.GOARCH + ")"
}

// ReportAbsPath — абсолютный путь отчёта, разрешённый от КОРНЯ дерева.
//
// `go test` исполняется в каталоге пакета, поэтому относительный путь лёг бы
// внутрь `relverdict/`, а гейт свежести искал бы его у корня и НЕ НАШЁЛ БЫ —
// то есть печатал бы «полного отчёта нет» при существующем отчёте. Корень
// спрашивается у git, а не собирается из `..`: число шагов вверх зависит от
// того, кто зовёт.
func ReportAbsPath() (string, error) {
	out, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", fmt.Errorf("scalegrid: корень дерева не установлен, писать отчёт некуда: %w", err)
	}
	return strings.TrimSpace(string(out)) + "/" + ReportPath, nil
}

// Header — шапка отчёта.
//
// Отчёт БЕЗ строки воспроизведения считается невалидным, и это не украшение:
// перепись по соседнему прибору того же дерева (`services/iam/tools/authzformbench`,
// 10 отчётов) даёт 7 с командой и 3 без — и эти три невоспроизводимы ничем,
// потому что их писатель строку повторения не печатает вовсе.
func (p Provenance) Header(title string) (string, error) {
	if strings.TrimSpace(p.RunCommand) == "" {
		return "", fmt.Errorf("scalegrid: отчёт без дословной команды повторения невалиден — " +
			"через месяц его число нечем проверить")
	}
	var b strings.Builder
	w := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	w("%s\n%s\n\n", title, strings.Repeat("=", len([]rune(title))))
	w("ПРОВЕНАНС\n")
	w("  снято               %s\n", p.When.Format("2006-01-02 15:04:05 MST"))
	w("  ревизия дерева      %s\n", p.TreeRev)
	switch {
	case p.DirtyPaths < 0:
		w("  состояние дерева    НЕ УСТАНОВЛЕНО — git status не выполнился.\n")
		w("                      Это НЕ «дерево чисто»: чистоту никто не проверял, и\n")
		w("                      ревизия выше может не описывать то, что исполнялось.\n")
	case p.TreeDirty:
		inSubject, outside, judged := p.splitDirtyBySubject()
		switch {
		case !judged:
			w("  состояние дерева    ГРЯЗНОЕ: путей с несохранёнными правками %d.\n", p.DirtyPaths)
			w("                      Принадлежность их предмету замера НЕ УСТАНОВЛЕНА (пути не\n")
			w("                      названы либо файлов под отпечатком ноль), поэтому вердикт\n")
			w("                      пессимистичен: ревизия выше НЕ описывает исполнявшееся\n")
			w("                      дерево целиком — повторение по ней даст другой код. Отчёт\n")
			w("                      остаётся годным как наблюдение и НЕ годится как\n")
			w("                      воспроизводимый замер.\n")
		case len(inSubject) > 0:
			w("  состояние дерева    ГРЯЗНОЕ ПО ПРЕДМЕТУ ЗАМЕРА: путей с несохранёнными\n")
			w("                      правками %d, из них ПОД ОТПЕЧАТКОМ %d.\n", p.DirtyPaths, len(inSubject))
			for _, rel := range namesForHeader(inSubject) {
				w("                        под отпечатком  %s\n", rel)
			}
			w("                      Ревизия выше НЕ описывает исполнявшееся дерево целиком —\n")
			w("                      повторение по ней даст другой код. Отчёт остаётся годным\n")
			w("                      как наблюдение и НЕ годится как воспроизводимый замер.\n")
		default:
			w("  состояние дерева    чистое по предмету замера: несохранённых правок среди\n")
			w("                      файлов под отпечатком нет — ревизия описывает\n")
			w("                      исполнявшийся КОД целиком.\n")
			w("                      Вне предмета правок %d — на измеряемую стоимость они не\n", len(outside))
			w("                      влияют; принадлежность выведена из перечня файлов под\n")
			w("                      отпечатком ниже, а не из выписанного исключения:\n")
			for _, rel := range namesForHeader(outside) {
				w("                        вне предмета    %s\n", rel)
			}
		}
	default:
		w("  состояние дерева    чистое (несохранённых правок нет) — ревизия описывает\n")
		w("                      исполнявшееся дерево целиком\n")
	}
	w("  машина              %s, ядер %d\n", p.CPUModel, p.CPUCores)
	w("  Postgres            %s\n", p.Postgres)
	w("\nОТПЕЧАТОК ПРЕДМЕТА ЗАМЕРА (гейт свежести сверяет его с текущим деревом)\n")
	w("%s", p.Fingerprint.FingerprintLines(p.treeRoot))
	w("\nСЕТКА (константа в коде, ниоткуда не переопределяется)\n%s", p.GridText)
	w("\nВОСПРОИЗВЕДЕНИЕ (дословно)\n  %s\n", p.RunCommand)
	return b.String(), nil
}

// ParsePorcelainPaths — пути из вывода `git status --porcelain`.
//
// Разбор ОТДЕЛЬНОЙ функцией затем, чтобы его можно было прогнать настоящим
// выводом git, не поднимая репозитория. Формат: два знака состояния, пробел,
// путь; у переименования путей два, и предметом является ЦЕЛЬ (то, что лежит в
// дереве сейчас). Пути в этом формате всегда от корня репозитория — тем же
// корнем адресован и перечень файлов под отпечатком, поэтому сравнивать их
// можно дословно.
func ParsePorcelainPaths(out []byte) []string {
	var paths []string
	for _, line := range strings.Split(string(out), "\n") {
		if len(line) < 4 {
			continue
		}
		rel := strings.TrimSpace(line[3:])
		if i := strings.Index(rel, " -> "); i >= 0 {
			rel = rel[i+4:]
		}
		rel = strings.Trim(rel, `"`)
		if rel != "" {
			paths = append(paths, rel)
		}
	}
	return paths
}

// splitDirtyBySubject — разносит грязные пути на «под отпечатком» и «вне».
//
// Третье возвращаемое — СУДИЛИ ЛИ вообще. Ложь означает, что классифицировать
// нечем: пути не названы либо файлов под отпечатком ноль. Молчание здесь
// означало бы чистоту, которой никто не проверял, поэтому вызывающий обязан
// остаться пессимистичным.
//
// Исключение ВЫВОДИТСЯ из предмета, а не выписано: расширится отпечаток —
// расширится и то, о чём шапка предупреждает, без чьей-либо памяти.
//
// ЧЕГО ЭТО НЕ ЗАКРЫВАЕТ — сказано прямо: файл ПОД ОТПЕЧАТКОМ, удалённый и не
// закоммиченный, в перечне отпечатка отсутствует by construction (он снят с
// диска), поэтому попадёт в «вне предмета». Такой сдвиг ловит не эта строка, а
// отпечаток СОСТАВА: он посчитан по тому же диску и разойдётся с деревом на
// первом же прогоне гейта свежести.
func (p Provenance) splitDirtyBySubject() (inSubject, outside []string, judged bool) {
	if len(p.DirtyPathList) == 0 || len(p.Fingerprint.Files) == 0 {
		return nil, nil, false
	}
	under := make(map[string]bool, len(p.Fingerprint.Files))
	for _, rel := range p.Fingerprint.Files {
		under[rel] = true
	}
	for _, rel := range p.DirtyPathList {
		if under[rel] {
			inSubject = append(inSubject, rel)
			continue
		}
		outside = append(outside, rel)
	}
	return inSubject, outside, true
}

// headerPathLimit — сколько путей шапка называет поимённо. Перечень длиннее
// читать перестают, а число остаётся точным: оно печатается отдельно.
const headerPathLimit = 8

// namesForHeader — пути для шапки, с честным хвостом.
func namesForHeader(paths []string) []string {
	if len(paths) <= headerPathLimit {
		return paths
	}
	out := append([]string{}, paths[:headerPathLimit]...)
	return append(out, fmt.Sprintf("… и ещё %d", len(paths)-headerPathLimit))
}
