// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// ErrPostureNotBuilt — посадку собрать не удалось: проверка НЕ ИСПОЛНЯЛАСЬ.
//
// Отдельный признак, а не общий отказ: «клон не собран» и «цель отказала» —
// разные исходы, и первый не вычитается из вердикта и не зачитывается в успех.
var ErrPostureNotBuilt = errors.New("самостоятельная посадка не собрана")

// monorepoMark — пометка, которой рецепт объявляет, что цель зовёт соседей по
// дереву. Читается ДОСЛОВНО той же строкой, которую печатает `make help`:
// перечень там выводится из строк `## `, и второго словаря у пометки нет.
const monorepoMark = "[монорепо]"

// targetLine — строка объявления цели в рецепте: `## <имя> — <что делает>`.
//
// Разделитель — тире, а не дефис, и это не придирка: `help` печатает эти строки
// как есть, а имена целей дефис содержат (`build-migrator`, `model-canon-check`).
// Образец, принявший дефис за разделитель, обрезал бы имя по первому же дефису и
// судил бы цель `build`, которой в перечне нет, — то есть молчал бы о настоящей.
var targetLine = regexp.MustCompile(`^##\s+(\S+)\s+—\s+(.*)$`)

// Target — цель рецепта в том виде, в каком её читает арендатор.
type Target struct {
	// Name — имя цели, которым её зовут.
	Name string
	// Desc — описание из той же строки; в находке оно называется, чтобы
	// читатель не ходил за ним в рецепт.
	Desc string
	// Monorepo — рецепт объявил, что цель зовёт соседей по дереву.
	Monorepo bool
}

// Waiver — цель, которую гейт не зовёт, и НАЗВАННАЯ причина.
//
// Причина обязательна: запись без неё есть «не спрашиваем» без основания —
// ровно тот дефект, который гейты этого дерева ищут. Предмет у каждой записи
// один и тот же по форме — ресурс, которого у пробы нет by construction
// (демон сборки образов, живая база, сеть). Это НЕ отсрочка: такая цель не
// станет проверяемой оттого, что кто-то ею займётся, — её предпосылку создаёт
// не код, а стенд.
//
// Запись, которой больше нечего покрывать (цель исчезла из рецепта либо стала
// помеченной), — НАХОДКА: послабление живёт, пока у него есть предмет.
type Waiver struct {
	Target string
	Reason string
}

// ParseTargets — перечень целей, выведенный из рецепта.
//
// Выводится из ТОГО ЖЕ источника, который печатает `make help` (строки `## `), а
// не из второго списка: выписанный разошёлся бы с рецептом молча, и гейт судил
// бы цели, которых арендатор не видит, пропуская те, что видит.
func ParseTargets(makefile []byte) []Target {
	var out []Target
	for _, ln := range strings.Split(string(makefile), "\n") {
		m := targetLine.FindStringSubmatch(strings.TrimRight(ln, "\r"))
		if m == nil {
			continue
		}
		out = append(out, Target{
			Name:     m[1],
			Desc:     strings.TrimSpace(m[2]),
			Monorepo: strings.Contains(m[2], monorepoMark),
		})
	}
	return out
}

// Census — объём осмотренного. Печатается ВСЕГДА и первым: без него зелёный
// вердикт неотличим от вердикта гейта, не прочитавшего ничего.
type Census struct {
	Declared  int
	Monorepo  int
	Waived    int
	Judged    int
	Findings  int
	Unmet     int
	Posture   string
	StaleWaiv []string
}

func (c Census) String() string {
	return fmt.Sprintf(
		"перепись: целей объявлено %d · помечено %s %d · прощено ведомостью %d · судимых %d · "+
			"находок %d · условие не создано %d · посадка %s",
		c.Declared, monorepoMark, c.Monorepo, c.Waived, c.Judged, c.Findings, c.Unmet, c.Posture)
}

// Judged — цели, которые гейт обязан позвать, и переучёт по ведомости.
//
// Ведомость сверяется В ОБЕ СТОРОНЫ: запись без предмета возвращается в
// StaleWaiv и делает вердикт находкой. Без этого послабление пережило бы свою
// цель и досталось бы следующей, случайно совпавшей по имени.
func Judged(targets []Target, waivers []Waiver) ([]Target, Census) {
	byName := map[string]string{}
	for _, w := range waivers {
		byName[w.Target] = w.Reason
	}

	var judged []Target
	c := Census{Declared: len(targets)}
	used := map[string]bool{}
	for _, t := range targets {
		switch {
		case t.Monorepo:
			c.Monorepo++
		case byName[t.Name] != "":
			c.Waived++
			used[t.Name] = true
		default:
			judged = append(judged, t)
		}
	}
	for _, w := range waivers {
		if !used[w.Target] {
			c.StaleWaiv = append(c.StaleWaiv, w.Target)
		}
	}
	sort.Strings(c.StaleWaiv)
	c.Judged = len(judged)
	return judged, c
}

// ModuleRootFrom поднимается от start до БЛИЖАЙШЕГО каталога с `go.mod`.
//
// Маркер — `go.mod`, а не имя каталога: имя у арендатора выбирает тот, кто
// клонировал (`kaname`, `iam`, `src`), и проба, опознающая корень по имени, у
// половины клонирующих не находит его МОЛЧА. Число `..` не называется вовсе,
// поэтому смена глубины перестаёт быть предметом правки. Та же форма, что у
// соседа по модулю — `deploy/tree_root_test.go`.
func ModuleRootFrom(start string) (string, error) {
	dir := start
	for {
		if st, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil && st.Mode().IsRegular() {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("%w: маркер go.mod не найден подъёмом от %s", ErrPostureNotBuilt, start)
		}
		dir = parent
	}
}

// AssertOutsideAnyRepository — предпосылка фикстуры: каталог, в котором будет
// собран клон, НЕ лежит внутри чужого репозитория.
//
// Несущая, а не гигиеническая. Клон внутри чужого дерева получает при обходе
// вверх ЧУЖОЙ индекс, и цели выносят по нему вердикт — зелёный, отличить его от
// настоящего нечем. Это тот же класс, ради которого написаны tree-root.sh
// (kacho#2145) и резолв канона (kacho#2159); гейт, воспроизводящий его собственной
// фикстурой, судил бы не то, что объявляет.
//
// Проверяется НАЛИЧИЕ каталога `.git` на каждом уровне вверх, а не ответ git:
// ответ git о самом каталоге ничего не скажет, пока каталог ещё не создан.
func AssertOutsideAnyRepository(dir string) error {
	cur := filepath.Clean(dir)
	for {
		if st, err := os.Stat(filepath.Join(cur, ".git")); err == nil && (st.IsDir() || st.Mode().IsRegular()) {
			return fmt.Errorf(
				"%w: каталог фикстуры лежит внутри репозитория\n"+
					"  осмотрено:        %s\n"+
					"  найден признак:   %s\n"+
					"  ожидался признак: ни одного .git на пути вверх от каталога фикстуры\n"+
					"  клон, собранный внутри чужого дерева, получает при обходе вверх ЧУЖОЙ\n"+
					"  индекс — и цели выносят вердикт о нём, а не о модуле; отличить такой\n"+
					"  зелёный от настоящего нечем. Назовите TMPDIR вне всякого репозитория",
				ErrPostureNotBuilt, dir, filepath.Join(cur, ".git"))
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return nil
		}
		cur = parent
	}
}

// Finding — цель, объявленная рабочей вне монорепо, которая в самостоятельном
// клоне отказала.
type Finding struct {
	Target Target
	Code   int
	Tail   string
	// Probes означает подтверждённые именованные отказы текущего запуска.
	Probes     bool
	Diagnostic string
}

func (f Finding) String() string {
	if f.Diagnostic != "" {
		return fmt.Sprintf("цель %q отказала кодом %d: %s\n  preview вывода (последние 25 строк; полный поток по указанному пути):\n%s\n"+
			"  Пометить цель %s исходом НЕ является — это сняло бы проверку самостоятельного клона целиком",
			f.Target.Name, f.Code, f.Diagnostic, f.Tail, monorepoMark)
	}
	return fmt.Sprintf(
		"цель %q объявлена рабочей вне монорепо (пометки %s в её строке нет), а в самостоятельном клоне отказала кодом %d\n"+
			"  объявлено:   ## %s — %s\n"+
			"  хвост вывода (последние 25 строк, при сокращении — явная отметка):\n%s\n"+
			"  исходов два: либо цель работает у арендатора, либо рецепт помечает её %s и\n"+
			"  отказывает СЛОВАМИ, называя, что делать вместо. Молчаливое красное у всякого,\n"+
			"  кто склонирует, исходом не является",
		f.Target.Name, monorepoMark, f.Code, f.Target.Name, f.Target.Desc, f.Tail, monorepoMark)
}

// Читается отдельный документ producer, а не текст Output вложенной пробы.
// Проверка байтов связывает классификацию с сохранённым потоком этого запуска.
func standaloneDiagnostic(output string, invocation *os.Root) (string, bool) {
	const prefix = "Диагностика standalone: "
	var path string
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, prefix) {
			if path != "" {
				return "неизвестный исход: неоднозначный capture", false
			}
			path = strings.TrimPrefix(line, prefix)
		}
	}
	unknown := "неизвестный исход standalone; причина не установлена"
	if invocation == nil || path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != "manifest.json" {
		return unknown, false
	}
	base := invocation.Name()
	rel, err := filepath.Rel(base, path)
	parts := strings.Split(rel, string(os.PathSeparator))
	if err != nil || !filepath.IsAbs(base) || filepath.Clean(base) != base || len(parts) != 2 || !strings.HasPrefix(parts[0], "producer-") || parts[0] == "producer-" || parts[1] != "manifest.json" {
		return unknown + "; capture вне текущего запуска", false
	}
	parent, err := invocation.Stat(".")
	if err != nil || !parent.IsDir() || parent.Mode().Perm() != 0o700 {
		return unknown + "; корень capture не приватен", false
	}
	before, err := invocation.Lstat(parts[0])
	if err != nil || !before.IsDir() || before.Mode().Perm() != 0o700 {
		return unknown + "; capture недоступен", false
	}
	// Producer закрепляется без следования ссылке и далее не открывается повторно по имени.
	directory, err := standaloneOpenNoFollow(invocation, parts[0], true)
	if err != nil {
		return unknown + "; capture недоступен", false
	}
	defer directory.Close()
	pinned, err := directory.Stat()
	if err != nil || !pinned.IsDir() || pinned.Mode().Perm() != 0o700 || !os.SameFile(before, pinned) {
		return unknown + "; capture изменился при открытии", false
	}
	after, afterErr := invocation.Lstat(parts[0])
	if afterErr != nil || !after.IsDir() || after.Mode().Perm() != 0o700 || !os.SameFile(pinned, after) {
		return unknown + "; capture изменился при открытии", false
	}
	data, err := standalonePrivateRead(invocation, directory, parts[0], "manifest.json")
	if err != nil {
		return unknown + "; capture недоступен", false
	}
	var m struct {
		Version       int    `json:"version"`
		Kind          string `json:"kind"`
		Complete      bool   `json:"complete"`
		Outcome       string `json:"outcome"`
		GoRC          *int   `json:"goRC"`
		ParseRC       *int   `json:"parseRC"`
		CaptureRC     *int   `json:"captureRC"`
		HelperRC      *int   `json:"helperRC"`
		CaptureStatus string `json:"captureStatus"`
		CensusStatus  string `json:"censusStatus"`
		Files         map[string]struct {
			Bytes  int64  `json:"bytes"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if standaloneUniqueJSON(data) != nil || json.Unmarshal(data, &m) != nil || m.Version != 1 || m.Kind != "producer" || m.GoRC == nil {
		return unknown + "; manifest некорректен", false
	}
	validated := map[string][]byte{}
	for _, name := range []string{"stdout.jsonl", "stderr.log", "go.rc", "census.json"} {
		body, err := standalonePrivateRead(invocation, directory, parts[0], name)
		entry, ok := m.Files[name]
		sum := sha256.Sum256(body)
		if err != nil || !ok || entry.Bytes != int64(len(body)) || entry.SHA256 != hex.EncodeToString(sum[:]) {
			return unknown + "; capture не подтверждён: " + path, false
		}
		if name != "stderr.log" {
			validated[name] = body
		}
	}
	if !m.Complete || m.CaptureStatus != "complete" || m.CensusStatus != "complete" {
		return unknown + "; неполная диагностика: " + path, false
	}
	if m.ParseRC == nil || *m.ParseRC != 0 || m.CaptureRC == nil || *m.CaptureRC != 0 || m.HelperRC == nil {
		return unknown + "; захват или разбор не подтверждён: " + path, false
	}
	if strings.TrimSpace(string(validated["go.rc"])) != strconv.Itoa(*m.GoRC) {
		return unknown + "; исход Go не подтверждён: " + path, false
	}
	supplied, err := standaloneJSONMap(validated["census.json"])
	if err != nil {
		return unknown + "; перепись некорректна: " + path, false
	}
	c, ok := standaloneCensus(validated["stdout.jsonl"])
	if !ok || c.Events == 0 || c.NonJSON != 0 || len(c.Packages) == 0 || len(c.UnterminatedPackages)+len(c.UnterminatedTests) != 0 {
		return unknown + "; поток неполон: " + path, false
	}
	expectedBody, err := json.Marshal(c)
	if err != nil {
		return unknown + "; перепись не подтверждена: " + path, false
	}
	observed, err := standaloneJSONMap(expectedBody)
	if err != nil || !reflect.DeepEqual(observed, supplied) {
		return unknown + "; перепись расходится с потоком: " + path, false
	}
	buildFailure := false
	for _, status := range c.Builds {
		buildFailure = buildFailure || status == "fail"
	}
	expected := "unknown"
	switch {
	case len(c.Named) > 0 && len(c.PackageOnly) > 0:
		expected = "mixed"
	case len(c.Named) > 0:
		expected = "named"
	case len(c.Failed) > 0 || buildFailure:
		expected = "package"
	case *m.GoRC == 0:
		expected = "pass"
	}
	if expected != m.Outcome {
		return unknown + "; классификация расходится с переписью: " + path, false
	}
	helperRC := 0
	observedFailure := len(c.Named) > 0 || len(c.Failed) > 0 || buildFailure
	if *m.GoRC != 0 || observedFailure {
		helperRC = 1
	}
	if *m.HelperRC != helperRC || (*m.GoRC == 0 && observedFailure) {
		return unknown + "; коды исхода расходятся с потоком: " + path, false
	}
	switch m.Outcome {
	case "named":
		return "именованные отказы проб; полный census и первичный вывод: " + path, true
	case "package":
		return "отказы пакетов без именованных отказов проб; причина не установлена; полный census и первичный вывод: " + path, false
	case "mixed":
		return "смешанный отказ: именованные пробы и пакеты без именованных отказов; полный census и первичный вывод: " + path, true
	default:
		return unknown + "; полный capture: " + path, false
	}
}

// Открывается только конечное имя внутри удерживаемого producer root. NOFOLLOW
// запрещает ссылки при самом open, NONBLOCK не даёт подмене на FIFO остановить чтение.
func standalonePrivateRead(invocation *os.Root, producer *os.File, producerName, name string) ([]byte, error) {
	// Метаданные сравниваются с путём внутри authority; данные читаются только от pinned fd.
	relative := filepath.Join(producerName, name)
	before, err := invocation.Lstat(relative)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0o600 {
		return nil, errors.New("capture не является приватным обычным файлом")
	}
	file, err := standaloneOpenAt(producer, name, false)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 || !os.SameFile(before, opened) {
		return nil, errors.New("capture изменился при открытии файла")
	}
	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	after, err := invocation.Lstat(relative)
	if err != nil || !after.Mode().IsRegular() || after.Mode().Perm() != 0o600 || !os.SameFile(opened, after) {
		return nil, errors.New("capture изменился при чтении файла")
	}
	return data, nil
}

// Повтор ключа запрещён на любой глубине до обычного декодирования документа.
func standaloneUniqueJSON(body []byte) error {
	if !json.Valid(body) {
		return errors.New("некорректный JSON диагностики")
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var visit func() error
	visit = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, nested := token.(json.Delim)
		if !nested {
			return nil
		}
		switch delimiter {
		case '{':
			seen := map[string]bool{}
			for decoder.More() {
				key, err := decoder.Token()
				if err != nil {
					return err
				}
				name, ok := key.(string)
				if !ok || seen[name] {
					return errors.New("повтор имени JSON диагностики")
				}
				seen[name] = true
				if err := visit(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := visit(); err != nil {
					return err
				}
			}
		default:
			return errors.New("некорректная граница JSON диагностики")
		}
		_, err = decoder.Token()
		return err
	}
	return visit()
}

func standaloneJSONMap(body []byte) (map[string]any, error) {
	if err := standaloneUniqueJSON(body); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	var value map[string]any
	err := decoder.Decode(&value)
	return value, err
}

type standaloneTestIdentity struct {
	Package string `json:"package"`
	Test    string `json:"test"`
}

type standaloneEventCensus struct {
	Events               int                      `json:"events"`
	NonJSON              int                      `json:"nonJSON"`
	UnterminatedPackages []string                 `json:"unterminatedPackages"`
	UnterminatedTests    []standaloneTestIdentity `json:"unterminatedTests"`
	Packages             map[string]string        `json:"packages"`
	Failed               []string                 `json:"failedPackages"`
	Named                []standaloneTestIdentity `json:"namedFailures"`
	PackageOnly          []string                 `json:"packageOnlyFailures"`
	PassedTests          int                      `json:"passedTests"`
	FailedTests          int                      `json:"failedTests"`
	TestExecutions       int                      `json:"testExecutions"`
	UnmetSkips           []standaloneTestIdentity `json:"unmetSkips"`
	OtherSkips           int                      `json:"otherSkips"`
	PassedPackages       int                      `json:"passedPackages"`
	SkippedPackages      int                      `json:"skippedPackages"`
	Builds               map[string]string        `json:"builds"`
	FailedBuilds         map[string]string        `json:"failedBuilds"`
}

// Go-потребитель независимо пересчитывает события: корректный hash не доказывает census.
func standaloneCensus(raw []byte) (standaloneEventCensus, bool) {
	c := standaloneEventCensus{
		UnterminatedPackages: []string{}, UnterminatedTests: []standaloneTestIdentity{},
		Packages: map[string]string{}, Failed: []string{}, Named: []standaloneTestIdentity{},
		PackageOnly: []string{}, UnmetSkips: []standaloneTestIdentity{},
		Builds: map[string]string{}, FailedBuilds: map[string]string{},
	}
	seenPackages, openPackages, failedPackages := map[string]bool{}, map[string]bool{}, map[string]bool{}
	seenTests, openTests, failedTests := map[standaloneTestIdentity]bool{}, map[standaloneTestIdentity]bool{}, map[standaloneTestIdentity]bool{}
	output := map[standaloneTestIdentity]string{}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	for _, line := range lines {
		var event map[string]json.RawMessage
		if standaloneUniqueJSON([]byte(line)) != nil || json.Unmarshal([]byte(line), &event) != nil || event == nil {
			return c, false
		}
		values := map[string]string{}
		for _, key := range []string{"Action", "Package", "ImportPath", "Test", "Output", "FailedBuild"} {
			if value, exists := event[key]; exists {
				var decoded string
				if len(value) == 0 || value[0] != '"' || json.Unmarshal(value, &decoded) != nil {
					return c, false
				}
				values[key] = decoded
			}
		}
		action, pkg, test := values["Action"], values["Package"], values["Test"]
		build := action == "build-output" || action == "build-fail"
		if values["FailedBuild"] != "" && (build || test != "" || action != "fail") {
			return c, false
		}
		switch action {
		case "start", "run", "pause", "cont", "output", "pass", "fail", "skip", "build-output", "build-fail":
		default:
			return c, false
		}
		c.Events++
		if build {
			importPath, actualBuild := values["ImportPath"]
			if actualBuild {
				pkg = importPath
			}
			if (!actualBuild && pkg == "") || test != "" {
				return c, false
			}
			if c.Builds[pkg] != "fail" {
				c.Builds[pkg] = "output"
				if action == "build-fail" {
					c.Builds[pkg] = "fail"
				}
			}
			if actualBuild || action != "build-fail" {
				continue
			}
			// Совместимая прежняя форма с Package не меняет семантику ImportPath.
			action = "fail"
		}
		if pkg == "" {
			return c, false
		}
		if action == "start" || !seenPackages[pkg] {
			openPackages[pkg] = true
		}
		seenPackages[pkg] = true
		terminal := action == "pass" || action == "fail" || action == "skip"
		if test != "" {
			key := standaloneTestIdentity{Package: pkg, Test: test}
			if action == "run" {
				openTests[key] = true
				delete(output, key)
			} else if !seenTests[key] {
				openTests[key] = true
			}
			seenTests[key] = true
			if action == "output" {
				const marker = "УСЛОВИЕ НЕ СОЗДАНО"
				text := output[key] + values["Output"]
				if strings.Contains(text, marker) {
					output[key] = marker
				} else if len(text) >= len(marker) {
					output[key] = text[len(text)-len(marker)+1:]
				} else {
					output[key] = text
				}
			} else if terminal {
				delete(openTests, key)
				c.TestExecutions++
				switch action {
				case "fail":
					failedTests[key] = true
					c.FailedTests++
				case "pass":
					c.PassedTests++
				case "skip":
					if strings.Contains(output[key], "УСЛОВИЕ НЕ СОЗДАНО") {
						c.UnmetSkips = append(c.UnmetSkips, key)
					} else {
						c.OtherSkips++
					}
				}
				delete(output, key)
			}
		} else if terminal {
			delete(openPackages, pkg)
			c.Packages[pkg] = action
			switch action {
			case "fail":
				failedPackages[pkg] = true
			case "pass":
				c.PassedPackages++
			case "skip":
				c.SkippedPackages++
			}
			if values["FailedBuild"] != "" {
				c.FailedBuilds[pkg] = values["FailedBuild"]
			}
		}
	}
	for _, build := range c.FailedBuilds {
		if c.Builds[build] != "fail" {
			return c, false
		}
	}
	namedPackages := map[string]bool{}
	for key := range failedTests {
		c.Named = append(c.Named, key)
		namedPackages[key.Package] = true
	}
	for key := range openTests {
		c.UnterminatedTests = append(c.UnterminatedTests, key)
	}
	for pkg := range openPackages {
		c.UnterminatedPackages = append(c.UnterminatedPackages, pkg)
	}
	for pkg := range failedPackages {
		c.Failed = append(c.Failed, pkg)
		if !namedPackages[pkg] {
			c.PackageOnly = append(c.PackageOnly, pkg)
		}
	}
	sort.Strings(c.UnterminatedPackages)
	sort.Strings(c.Failed)
	sort.Strings(c.PackageOnly)
	for _, identities := range [][]standaloneTestIdentity{c.Named, c.UnterminatedTests} {
		sort.Slice(identities, func(i, j int) bool {
			if identities[i].Package != identities[j].Package {
				return identities[i].Package < identities[j].Package
			}
			return identities[i].Test < identities[j].Test
		})
	}
	return c, true
}

// ProbeFailureMark — читаемая метка именованных отказов producer.
// Классификация gate опирается на manifest, а не на эту строку чужого вывода.
const ProbeFailureMark = "ПРОБЫ УПАЛИ:"

// IsProbeFailure — объявила ли цель СВОИМ ТЕКСТОМ, что упали исполненные ею пробы.
//
// Правило распознавания то же, что у третьего исхода, и по той же причине:
// метка обязана стоять ПЕРВОЙ на своей строке. Слова эти живут в прозе, которая
// их объясняет, — в комментарии рецепта, в тексте находки, в этом разборе; поиск
// подстрокой зеленел бы на собственном объяснении и переводил бы в «упали
// пробы» цель, отказавшую по-настоящему.
func IsProbeFailure(output string) bool {
	for _, ln := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimLeft(ln, " \t"), ProbeFailureMark) {
			return true
		}
	}
	return false
}

// UnmetPremiseMark — метка ТРЕТЬЕГО ИСХОДА, которую печатает сама цель.
//
// Написание ОДНО на всё дерево, и это несущее свойство, а не стиль. Ту же
// строку читает шаг сверки каталога прав в `.github/workflows/ci.yml` и перепись
// `scripts/test-standalone.sh`; второе написание сделало бы категорию
// беспредметной у того читателя, который о нём не знает, — молча, потому что
// «не нашёл метку» и «метки нет» выглядят одинаково.
const UnmetPremiseMark = "УСЛОВИЕ НЕ СОЗДАНО"

// IsUnmetPremise — объявила ли цель СВОИМ ТЕКСТОМ, что условия у неё нет.
//
// # Почему текстом, а не кодом возврата
//
// Кодом различить нечем by construction: `make` схлопывает любой отказ рецепта
// в собственную двойку, поэтому «рецепт вышел кодом 2» и «рецепт вышел кодом 1»
// приходят до оболочки ОДНИМ числом. Значит различает ровно то, что цель
// сказала, — тем же способом, каким это уже делает шаг сверки каталога прав в
// конвейере.
//
// # Почему НАЧАЛО СТРОКИ, а не вхождение куда угодно
//
// Слова эти встречаются в прозе, которая их же объясняет: в комментарии
// рецепта, в тексте находки, в разборе класса. Поиск подстрокой зеленел бы на
// собственном объяснении и объявлял бы «условие не создано» у цели, которая
// честно отказала. Поэтому метка обязана стоять ПЕРВОЙ на своей строке:
// эхо-вывод комментария рецепта начинается со знака комментария, а упоминание в
// прозе стоит в середине строки, — ни то, ни другое меткой не становится.
//
// Отступ слева снимается: `make` печатает вывод рецепта как есть, а рецепт
// вправе отступать текст отказа.
func IsUnmetPremise(output string) bool {
	for _, ln := range strings.Split(output, "\n") {
		if strings.HasPrefix(strings.TrimLeft(ln, " \t"), UnmetPremiseMark) {
			return true
		}
	}
	return false
}

// Unmet — цель, у которой НЕ СОЗДАНО УСЛОВИЕ: она сказала это своим текстом.
//
// Отдельный тип, а не поле находки: третий исход не вычитается из вердикта и не
// зачитывается в успех, поэтому и в переписи он стоит своим числом, и в списке
// своим списком. Подмешай его к находкам — и отсутствие внешнего инструмента
// отчитывалось бы дефектом продукта у всякого, кто склонирует.
type Unmet struct {
	Target Target
	Code   int
	Tail   string
}

func (u Unmet) String() string {
	return fmt.Sprintf(
		"цель %q объявила СВОИМ ТЕКСТОМ, что условия у неё нет (код %d): вердикта о ней НЕТ — "+
			"ни зелёного, ни красного\n"+
			"  объявлено:   ## %s — %s\n"+
			"  хвост вывода:\n%s",
		u.Target.Name, u.Code, u.Target.Name, u.Target.Desc, u.Tail)
}

// RunTargets зовёт каждую цель в собранной посадке и РАЗВОДИТ ТРИ ИСХОДА.
//
// Отделено от фикстуры намеренно: посадку строит проба (ей нужен git и
// временный каталог), а СУЖДЕНИЕ живёт здесь — и потому доказуемо инъекцией на
// синтетической посадке, где отказ цели подан нарочно. Гейт, чью способность
// падать нельзя предъявить иначе как поломкой дерева, доказательства не имеет.
//
// Исходов три, и каждый возвращается своим значением:
//
//	годно            — цель вышла кодом 0;
//	находка          — цель вышла ненулевым и метки третьего исхода не печатала;
//	условие не создано — цель вышла ненулевым и НАЗВАЛА предпосылку меткой.
//
// Для test-standalone род отказа берётся из сохранённого manifest.
// Неподтверждённый исход остаётся находкой с неизвестной причиной.
//
// Ошибка ЗАПУСКА (`make` не нашёлся) — четвёртое, и она возвращается ошибкой:
// это «проверка не исполнялась» про весь обход, а не про одну цель.
func RunTargets(dir string, targets []Target, run func(dir, target string) (int, string, error)) ([]Finding, []Unmet, error) {
	return RunTargetsWithCapture(dir, targets, func(dir, target string) (TargetResult, error) {
		code, output, err := run(dir, target)
		return TargetResult{Code: code, Output: output}, err
	})
}

// TargetResult передаёт authority отдельно от недоверенного вывода цели.
// Capture открывает владелец invocation до запуска child; потребитель закрывает его.
type TargetResult struct {
	Code    int
	Output  string
	Capture *os.Root
}

// RunTargetsWithCapture принимает принадлежащий конкретному invocation root handle.
// Старый callback без этого handle сохраняет отказ, но не подтверждает классификацию.
func RunTargetsWithCapture(dir string, targets []Target, run func(dir, target string) (TargetResult, error)) (out []Finding, unmet []Unmet, finalErr error) {
	for _, t := range targets {
		result, err := run(dir, t.Name)
		code, output := result.Code, result.Output
		if result.Capture != nil {
			// Отказ освобождения добавляется к исходу, не стирая находки и ошибку запуска.
			defer func(root *os.Root, target string) {
				if closeErr := root.Close(); closeErr != nil {
					finalErr = errors.Join(finalErr, fmt.Errorf("%w: capture цели %s не закрыт: %w", ErrPostureNotBuilt, target, closeErr))
				}
			}(result.Capture, t.Name)
		}
		if err != nil {
			return out, unmet, fmt.Errorf("%w: цель %s не запустилась: %w", ErrPostureNotBuilt, t.Name, err)
		}
		if code == 0 {
			continue
		}
		if t.Name != "test-standalone" && IsUnmetPremise(output) {
			unmet = append(unmet, Unmet{Target: t, Code: code, Tail: Tail(output, 25)})
			continue
		}
		finding := Finding{Target: t, Code: code, Tail: Tail(output, 25)}
		if t.Name == "test-standalone" {
			finding.Diagnostic, finding.Probes = standaloneDiagnostic(output, result.Capture)
		}
		out = append(out, finding)
	}
	return out, unmet, nil
}

// Tail — последние n строк вывода, с отступом. Находка обязана нести ТЕКСТ
// отказа цели, а не только её имя: имя посылает читателя искать причину, текст
// её называет.
func Tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) > n {
		omitted := len(lines) - n
		lines = append([]string{fmt.Sprintf("… preview сокращён: опущено %d строк; полный поток сохранён раннером", omitted)}, lines[len(lines)-n:]...)
	}
	return "    " + strings.Join(lines, "\n    ")
}
