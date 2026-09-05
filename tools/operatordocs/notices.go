// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// notices.go — ПОРОЖДЕНИЕ перечня третьих сторон из того, что РЕАЛЬНО ЛИНКУЮТ
// поставляемые бинари.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОРОЖДЕНИЕ, А НЕ ВЫПИСАННЫЙ ПЕРЕЧЕНЬ
//
// Перечень зависимостей выписывается один раз и не правится никогда: он не
// компилируется, не импортируется и не роняет ни одной пробы. Первый же
// добавленный модуль делает его ложным МОЛЧА — а ложным он становится в
// документе, которым мы исполняем требование чужой лицензии к распространению.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЕДИНИЦА СЧЁТА НАЗВАНА: то, что линкуют ДВА ПОСТАВЛЯЕМЫХ БИНАРЯ
//
// Не «весь go.mod» и не «всё, что импортирует дерево iam». Замер на этом дереве
// разводит величины втрое:
//
//	go.mod модуля целиком                              — весь монорепозиторий
//	`./services/iam/...` вместе с пробами              — 81 модуль
//	`./cmd/kacho-iam` + `./cmd/migrator` (поставляем)  — 40 модулей
//
// Распространяем мы образ с двумя бинарями, поэтому перечень строится по ним.
// Средства проб (контейнеры, докерный клиент) в образ не попадают: Go собирает
// только импортируемое, и объявлять их распространяемыми значило бы утверждать
// о поставке неправду в сторону «сложнее, чем есть».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ ЭТО НЕ ЯВЛЯЕТСЯ, И ЭТО ГРАНИЦА, А НЕ ПРОПУСК
//
// Здесь опознаётся ЛИЦЕНЗИЯ модуля, а не её СОВМЕСТИМОСТЬ с нашей: «под MIT» и
// «под Apache-2.0» перечисляются одинаково. Совместимость — решение человека, и
// подменять его предикатом значило бы обещать проверку, которой нет.
//
// Гейт дерева `internal/repohygiene/dependencylicense.go` судит ДРУГОЙ предмет —
// ФАКТ наличия лицензии у всякого пина всего монорепозитория. Второго места об
// одном предмете здесь не заводится: тот отвечает «есть ли лицензия», этот —
// «какая именно и у чего из поставляемого». Скопировать его сюда было нельзя и
// по построению: iam отвязан от корневого `internal/`, и вынесенный репозиторий
// его не унесёт.
package operatordocs

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

// Module — одна третья сторона: что линкуется и под чем распространяется.
type Module struct {
	Path    string
	Version string
	// Dir — каталог модуля в кэше. Пустой означает «не извлечён»: такой модуль
	// НЕ считается проверенным и попадает в находки.
	Dir string
	// License — опознанный идентификатор SPDX либо пусто.
	License string
	// Evidence — имя файла, по которому опознано. Координата для читателя.
	Evidence string
}

// ShippedPackages — пакеты, чьи бинари мы распространяем. Перечень закрыт
// намеренно: «всё дерево» втянуло бы средства проб, которых в образе нет.
var ShippedPackages = []string{"./cmd/kacho-iam", "./cmd/migrator"}

// ListModules спрашивает у сборщика, что линкуют поставляемые бинари.
//
// Спрашивает, а не разбирает go.mod: go.mod несёт пины всего модуля, включая
// то, что этими бинарями не линкуется вовсе.
func ListModules(root string) ([]Module, error) {
	args := append([]string{"list", "-C", root, "-deps",
		"-f", "{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}"},
		ShippedPackages...)
	// #nosec G204 -- бинарь — литерал "go"; шаблон аргументов — литерал этой функции;
	// перечень пакетов — закрытый набор уровня пакета (ShippedPackages). Из переменных
	// в строку попадает только root, и попадает значением -C: корень собственного
	// дерева, отвергаемый вызывающим (Run), если в нём нет LICENSE.
	cmd := exec.Command("go", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list по поставляемым пакетам: %w", err)
	}

	seen := map[string]Module{}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 || parts[1] == "" {
			// Модуль без версии — сам разрабатываемый модуль. Своя лицензия
			// объявлена своим файлом; в перечень ТРЕТЬИХ сторон он не идёт.
			continue
		}
		seen[parts[0]] = Module{Path: parts[0], Version: parts[1], Dir: parts[2]}
	}

	mods := make([]Module, 0, len(seen))
	for _, m := range seen {
		mods = append(mods, m)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Path < mods[j].Path })
	return mods, nil
}

// licenseFileNames — основы имён файла лицензии. Сравнение по префиксу основы:
// `LICENSE`, `LICENSE.md`, `LICENSE-MIT`, `COPYING.txt`.
var licenseFileNames = []string{"license", "licence", "copying"}

// licenseSignature — распознаватель одной лицензии: идентификатор SPDX и
// признаки, ВСЕ из которых обязаны встретиться.
//
// Порядок значим: более узкие распознаватели стоят раньше общих, иначе
// трёхпунктовая BSD опозналась бы как двухпунктовая.
var licenseSignatures = []struct {
	SPDX   string
	Needle []string
}{
	// BUSL-1.1 стоит ПЕРВОЙ и заведена не «на всякий случай»: с появлением у
	// службы собственного модуля фундамент платформы стал для неё ВНЕШНЕЙ
	// зависимостью, и его лицензия обязана попасть в перечень уведомлений. Без
	// распознавателя сверка отказывала: «распространять чужой код, не зная его
	// лицензии, нельзя» — верный отказ на верном входе.
	//
	// Что из этого следует для того, кто ставит продукт, СКАЗАНО ПРЯМО, а не
	// спрятано в таблицу: BUSL-1.1 — не свободная лицензия, у неё есть срок
	// перехода и оговорка о дополнительном разрешении на использование. Служба
	// раздаётся под AGPL-3.0-or-later. Совместимость двух — решение владельца, а
	// не вывод этого распознавателя: он только называет то, что нашёл.
	{"BUSL-1.1", []string{"Business Source License 1.1", "Additional Use Grant"}},
	{"Apache-2.0", []string{"Apache License", "Version 2.0"}},
	{"MPL-2.0", []string{"Mozilla Public License", "2.0"}},
	{"BSD-3-Clause", []string{"Redistributions in binary form", "Neither the name"}},
	{"BSD-2-Clause", []string{"Redistributions in binary form"}},
	{"MIT", []string{"Permission is hereby granted, free of charge"}},
	{"ISC", []string{"Permission to use, copy, modify, and/or distribute"}},
}

// scanCap — потолок читаемого файла лицензии. Признаки стоят в начале; читать
// многомегабайтные приложения ради них незачем.
const scanCap = 64 << 10

// Identify опознаёт лицензию модуля по файлу в его корне.
//
// Возвращает модуль с заполненными License и Evidence. Неопознанное остаётся
// пустым — и становится находкой у вызывающего: распространять чужой код, не
// зная его лицензии, нельзя, а «наверное MIT» лицензией не является.
func Identify(m Module) Module {
	if m.Dir == "" {
		return m
	}
	entries, err := os.ReadDir(m.Dir)
	if err != nil {
		return m
	}
	var candidates []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		low := strings.ToLower(e.Name())
		for _, base := range licenseFileNames {
			if strings.HasPrefix(low, base) {
				candidates = append(candidates, e.Name())
				break
			}
		}
	}
	sort.Strings(candidates)

	for _, name := range candidates {
		body, err := readCapped(filepath.Join(m.Dir, name))
		if err != nil {
			continue
		}
		for _, sig := range licenseSignatures {
			all := true
			for _, n := range sig.Needle {
				if !strings.Contains(body, n) {
					all = false
					break
				}
			}
			if all {
				m.License = sig.SPDX
				m.Evidence = name
				return m
			}
		}
	}
	if len(candidates) > 0 {
		// Файл есть, а признаков нет: сказать это прямо. Пустая лицензия при
		// найденном файле и при ненайденном — разные состояния.
		m.Evidence = candidates[0]
	}
	return m
}

func readCapped(path string) (string, error) {
	// #nosec G304,G703 -- путь построен как filepath.Join(m.Dir, name) вызывающим
	// (Identify), где name пришло из os.ReadDir(m.Dir) — то есть это ИМЯ ЗАПИСИ
	// каталога, а оно сепаратора не содержит by construction. Выйти за m.Dir такой
	// join не может; сам m.Dir назван сборщиком (`go list -deps`), а не вводом.
	//
	// filepath.Clean здесь НЕ ставится намеренно, хотя он гасит оба правила: обхода
	// он не предотвращает (Clean("/a/../../etc/passwd") == "/etc/passwd"), то есть
	// снял бы находку, ничего не ограничив, и подавление стало бы подавлением
	// пустоты — ровно тот класс, который стережёт TestNoInertGosecSuppressions.
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, scanCap)
	n, err := bufio.NewReader(f).Read(buf)
	if n == 0 && err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}

// NoticesCensus — объём осмотренного. Печатается ВСЕГДА.
type NoticesCensus struct {
	Modules      int
	Identified   int
	Unresolved   int
	Unidentified int
	ByLicense    map[string]int
}

func (c NoticesCensus) String() string {
	keys := make([]string, 0, len(c.ByLicense))
	for k := range c.ByLicense {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, c.ByLicense[k]))
	}
	return fmt.Sprintf("модулей %d · опознано %d · не извлечено в кэш %d · не опознано %d · по лицензиям: %s",
		c.Modules, c.Identified, c.Unresolved, c.Unidentified, strings.Join(parts, ", "))
}

// BuildNotices собирает перечень и возвращает его вместе с находками и
// переписью.
//
// Находкой является КАЖДЫЙ модуль, чью лицензию назвать не удалось: перечень,
// умалчивающий о части распространяемого, требования к распространению не
// исполняет, а выглядит исполняющим.
func BuildNotices(root string) (text string, findings []string, census NoticesCensus, err error) {
	mods, err := ListModules(root)
	if err != nil {
		return "", nil, census, err
	}
	census.ByLicense = map[string]int{}
	census.Modules = len(mods)

	if len(mods) == 0 {
		return "", []string{"обход пуст: сборщик не назвал НИ ОДНОГО модуля — перечень был бы пуст молча"}, census, nil
	}

	for i := range mods {
		mods[i] = Identify(mods[i])
		switch {
		case mods[i].Dir == "":
			census.Unresolved++
			findings = append(findings, fmt.Sprintf(
				"%s %s — модуль не извлечён в кэш, лицензию прочитать нечем; он НЕ считается проверенным",
				mods[i].Path, mods[i].Version))
		case mods[i].License == "":
			census.Unidentified++
			findings = append(findings, fmt.Sprintf(
				"%s %s — лицензия не опознана (осмотрен файл %q); распространять чужой код, не зная его лицензии, нельзя",
				mods[i].Path, mods[i].Version, mods[i].Evidence))
		default:
			census.Identified++
			census.ByLicense[mods[i].License]++
		}
	}

	return renderNotices(mods), findings, census, nil
}

func renderNotices(mods []Module) string {
	var b strings.Builder
	b.WriteString(noticesHeader)

	byLicense := map[string][]Module{}
	for _, m := range mods {
		key := m.License
		if key == "" {
			key = "лицензия не опознана"
		}
		byLicense[key] = append(byLicense[key], m)
	}
	keys := make([]string, 0, len(byLicense))
	for k := range byLicense {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	b.WriteString("## Сводка\n\n")
	b.WriteString("| Лицензия | Модулей |\n|---|---:|\n")
	for _, k := range keys {
		fmt.Fprintf(&b, "| %s | %d |\n", k, len(byLicense[k]))
	}
	fmt.Fprintf(&b, "| **всего** | **%d** |\n\n", len(mods))

	for _, k := range keys {
		fmt.Fprintf(&b, "## %s\n\n", k)
		b.WriteString("| Модуль | Версия | Файл лицензии в модуле |\n|---|---|---|\n")
		for _, m := range byLicense[k] {
			ev := m.Evidence
			if ev == "" {
				ev = "—"
			}
			fmt.Fprintf(&b, "| `%s` | `%s` | `%s` |\n", m.Path, m.Version, ev)
		}
		b.WriteString("\n")
	}

	b.WriteString(noticesFooter)
	return b.String()
}

const noticesHeader = `<!-- ЭТОТ ФАЙЛ ПОРОЖДЁН. Правки в нём уедут при следующей регенерации.
     Порождает: services/iam/tools/operatordocs — ` + "`make -C services/iam operator-docs`" + `
     Сверяет:   ` + "`make -C services/iam operator-docs-check`" + ` -->

# Уведомления о третьих сторонах

Здесь перечислено ЧУЖОЕ, что линкуют поставляемые бинари ` + "`kacho-iam`" + ` и
` + "`kacho-migrator`" + `, и под какой лицензией оно распространяется. Перечень нужен
затем, что распространение чужого кода разрешает только его лицензия, и часть
лицензий требует передавать уведомление получателю.

**Единица счёта названа:** модули, которые линкуют ДВА поставляемых бинаря, — не
весь ` + "`go.mod`" + ` и не всё, что импортирует дерево вместе с пробами. Средства проб
(контейнеры, докерный клиент) в образ не попадают: сборщик берёт только
импортируемое.

**Границы, названные прямо.** Здесь сказано, ПОД ЧЕМ распространяется каждый
модуль, и не сказано, СОВМЕСТИМО ли это с нашей лицензией: совместимость —
решение человека. Полные тексты лицензий здесь не воспроизводятся; каждый лежит
в самом модуле под названным именем файла и в неизменном виде едет вместе с
зависимостью.

`

const noticesFooter = `---

Собственная лицензия продукта — в файле ` + "`LICENSE`" + ` рядом с этим.
`
