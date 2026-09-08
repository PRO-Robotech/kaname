// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// install_surfaces_test.go — таблица слушателей документа установки называет
// ВСЕ поверхности, которые поднимает процесс.
//
// # Предмет
//
// Документ называл шесть слушателей, процесс поднимал восемь (задача #2341).
// Документ установки — контракт с чужим оператором: по нему он решает, какие
// двери открыть, какие закрыть и что защитить. Две неназванные двери — это
// внешне досягаемый тенантский REST-фронт, о котором оператор не узнает, что
// его надо вывести и защитить, и служебный, о котором он не узнает, что его
// выводить НЕЛЬЗЯ. Столбец «Достижимость» молчал ровно там, где его читают.
//
// # Почему гейт, а не порождение таблицы
//
// Порождать таблицу целиком значило бы вынести объявления поверхностей из
// композиционного корня, где они живут рядом со своими обработчиками, — то есть
// завести второе место об одном предмете. Здесь перечень ЧИТАЕТСЯ оттуда же,
// где его читает процесс, и таблица обязана с ним сходиться: выписанная рукой,
// разойтись молча она больше не может.
//
// # Что здесь утверждается
//
//	Р1  каждая поверхность процесса названа таблицей — по своему порту;
//	Р2  таблица не называет портов, которых процесс не поднимает: строка,
//	    пережившая свой слушатель, посылает оператора открывать дверь, которой
//	    нет;
//	Р3  досягаемость, объявленная документом, сходится с объявленной ПРОЦЕССОМ:
//	    «только внутри кластера» на внешней двери — та же ложь, только тише.
//	    Судится только там, где досягаемость объявляет процесс: у gRPC-ног оси
//	    `Reach` не существует, и сверять документ с собственным утверждением
//	    перечня значило бы проверять себя собой;
//	Р4  перепись печатается ДВУМЯ величинами.
package operatordocs_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/tools/surfaceroster"
)

// installRowRe — строка таблицы слушателей: адрес, назначение, достижимость.
var installRowRe = regexp.MustCompile(`^\|\s*` + "`" + `:(\d+)` + "`" + `\s*\|([^|]*)\|([^|]*)\|`)

// reachWordsInDoc — как документ пишет досягаемость. Написание одно на таблицу;
// второе завелось бы синонимом и разошлось бы молча.
const (
	docReachInternal = "только внутри кластера"
	docReachExternal = "внешне достижим"
)

func TestInstallGuideNamesEverySurfaceTheProcessRaises(t *testing.T) {
	root, err := surfaceroster.IAMRoot("..")
	require.NoError(t, err, "корень дерева службы")
	roster, err := surfaceroster.Read(root)
	require.NoError(t, err, "перечень поверхностей")

	raw, err := os.ReadFile(filepath.Join(root, "INSTALL.md"))
	require.NoError(t, err, "документ установки")

	rows := parseListenerRows(string(raw))
	declared, named, findings := judgeInstallSurfaces(t, roster, rows)

	require.Emptyf(t, findings,
		"поверхностей объявлено %d · названо документом %d; расходится %d:\n  - %s",
		declared, named, len(findings), strings.Join(findings, "\n  - "))
}

// installRow — прочитанная строка таблицы.
type installRow struct {
	port    string
	purpose string
	reach   string
}

// parseListenerRows читает строки таблицы слушателей.
func parseListenerRows(doc string) map[string]installRow {
	out := map[string]installRow{}
	for _, line := range strings.Split(doc, "\n") {
		m := installRowRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		out[m[1]] = installRow{
			port:    m[1],
			purpose: strings.TrimSpace(m[2]),
			reach:   strings.TrimSpace(m[3]),
		}
	}
	return out
}

// judgeInstallSurfaces — само суждение.
func judgeInstallSurfaces(t *testing.T, roster surfaceroster.Roster, rows map[string]installRow) (int, int, []string) {
	t.Helper()
	require.NoError(t, listenerTablePresent(rows), "предпосылка гейта")

	var declared, named int
	var findings []string
	var lines []string
	seen := map[string]bool{}

	for _, s := range roster.Surfaces {
		port := s.DefaultPort
		if port == "" {
			// Умолчания у адреса нет: поверхность поднимает ПОСАДКА. Документ
			// обязан назвать её всё равно — оператор решает, открывать ли дверь,
			// ДО того как поднимет её профилем.
			//
			// Порт ЧИТАЕТСЯ у поставляемого профиля, а не выписывается здесь:
			// выписанный был бы вторым местом об одном предмете и разошёлся бы
			// с профилем молча — ровно тот класс, ради которого гейт заведён.
			port = s.PosturePort
		}
		require.NotEmptyf(t, port,
			"у поверхности %q (%s) не удалось установить порт: гейт судил бы о том, чего не прочитал",
			s.Name, s.SettingKey)
		declared++
		seen[port] = true

		row, ok := rows[port]
		if !ok {
			lines = append(lines, fmt.Sprintf("  :%-5s %-16s НЕ НАЗВАНА документом", port, s.Reach))
			findings = append(findings, fmt.Sprintf(
				"поверхность %q (:%s, %s) не названа таблицей слушателей: оператор не узнает, "+
					"что эта дверь есть, — а решать, открыть её или закрыть, ему",
				s.Name, port, s.Reach))
			continue
		}
		named++
		lines = append(lines, fmt.Sprintf("  :%-5s %-16s → %q", port, s.Reach, row.purpose))

		if !s.ReachFromProcess {
			// Досягаемость этой поверхности объявляет не процесс, а перечень.
			// Сверять текст документа с собственным утверждением значило бы
			// проверять себя собой — и краснеть на верном тексте: публичный
			// gRPC действительно достигается ЧЕРЕЗ КРАЙ оператора, а не прямо,
			// и документ прав, называя это своими словами.
			continue
		}
		wantReach := docReachInternal
		if s.Reach == "external" {
			wantReach = docReachExternal
		}
		if !strings.Contains(row.reach, wantReach) {
			findings = append(findings, fmt.Sprintf(
				"поверхность %q (:%s): процесс объявляет её как %q, а документ пишет %q — "+
					"оператор защитит не то, что надо, и не защитит того, что надо",
				s.Name, port, s.Reach, row.reach))
		}
	}

	for port, row := range rows {
		if !seen[port] {
			findings = append(findings, fmt.Sprintf(
				"таблица называет `:%s` (%q), а процесс такой поверхности не поднимает: "+
					"строка пережила свой слушатель и посылает оператора открывать дверь, которой нет",
				port, row.purpose))
		}
	}

	sort.Strings(lines)
	t.Logf("ПЕРЕПИСЬ слушателей документа установки:\n%s\n"+
		"  строк в таблице %d · прочитано файлов объявлений %d\n"+
		"  поверхностей ОБЪЯВЛЕНО %d · НАЗВАНО ДОКУМЕНТОМ %d",
		strings.Join(lines, "\n"), len(rows), roster.FilesRead, declared, named)
	return declared, named, findings
}

// listenerTablePresent — ПРЕДПОСЫЛКА гейта: таблица вообще прочитана.
func listenerTablePresent(rows map[string]installRow) error {
	if len(rows) == 0 {
		return fmt.Errorf("в документе установки не прочитано ни одной строки таблицы слушателей: " +
			"вердикт «все поверхности названы» был бы о пустоте, и «ноль находок» стало бы " +
			"неотличимо от «ноль прочитанного»")
	}
	return nil
}
