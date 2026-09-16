// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// registration_lanes_test.go — ГЕЙТ КЛАССА: каждая полоса регистрации выдаёт
// сессию, и перечень полос выводится из ОДНОГО объявления нашего кода (приёмка
// Ф4 `docs/engineering/acceptance/registration-and-its-three-consequences.md`,
// Р4, сценарии Ф4-06, Ф4-07, Ф4-08, Ф4-09, Ф4-10; F4d-35; задача kacho#1270).
//
// # Предмет
//
// Полосы одного потока обязаны сходиться в том, ЧЕМ поток заканчивается.
// Разойдясь, они дают состояние, которое не выбирал никто: часть людей заводится
// и входит, часть заводится и остаётся снаружи. Наблюдалось на прежнем носителе
// полос — объявлении чужой конфигурации: полоса пароля доводила регистрацию до
// конца и НЕ ставила печенья сессии, тогда как соседняя выдавала (`kacho#1236`).
//
// # Что судится
//
// ОБЪЯВЛЕНИЕ, а не результат сборки: `registration.Lanes` разбирается как
// исходник, и перепись печатает две величины — «полос N · выдают сессию M».
// Полоса без выдачи сессии — красное с её именем (Ф4-07); все с выдачей —
// молчание (Ф4-08); ноль разобранных полос — отказ «вердикта нет» (Ф4-09):
// «ноль находок» здесь неотличимо от «ноль прочитанного».
//
// Вторая половина — единственность: составной литерал типа полосы ВНЕ файла
// объявления — находка (Ф4-06, «объявление одно»).
//
// # Переезд (Ф4-10)
//
// Предмет гейта переехал из дома платформы (`deploy/…lanes_issue_a_session_test.go`
// там читал чужое объявление по отступам). Здесь читается наше объявление;
// гейт чужого дома снимается вместе с самим чужим объявлением — шаг Ф10
// (`kacho#1276`), и это сказано, а не подразумевается: машинного держателя
// ОТСУТСТВИЯ в чужом дереве в доме службы нет by construction.
//
// Способность упасть и смолчать доказана инъекцией —
// registration_lanes_injection_test.go.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestRegistration_EveryLaneIssuesASession(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}
	goCorpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	// Значение следствия «сессия выдана» — от ПРОИЗВОДИТЕЛЯ, не выписанное.
	sessionValue := string(registration.ConsequenceSession)

	src, ok := goCorpus[check.RegistrationLanesFileRel]
	if !ok {
		t.Fatalf("вердикта НЕТ: файла объявления полос %s в дереве нет — «ноль находок» здесь "+
			"неотличимо от «ноль прочитанного» (Ф4-09)", check.RegistrationLanesFileRel)
	}
	lanes, census, err := check.ScanRegistrationLanes(check.RegistrationLanesFileRel, []byte(src), sessionValue)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: разбор объявления: %v", err)
	}

	// ── единственность объявления ───────────────────────────────────────────
	var (
		filesRead    int
		outsideSites []string
	)
	for _, rel := range goCorpus.Rels() {
		filesRead++
		sites, err := check.ScanRegistrationLaneLiterals(rel, []byte(goCorpus[rel]))
		if err != nil {
			t.Fatalf("разбор %s: %v", rel, err)
		}
		if rel == check.RegistrationLanesFileRel {
			continue
		}
		for _, s := range sites {
			outsideSites = append(outsideSites, s.String())
		}
	}

	t.Logf("перепись: полос регистрации %d · выдают сессию %d · объявлений `%s` в файле %d · "+
		"файлов прод-кода прочитано %d · литералов полосы вне объявления %d",
		census.Lanes, census.IssuingSession, check.RegistrationLanesVar, census.Declarations,
		filesRead, len(outsideSites))

	if census.Declarations != 1 {
		t.Fatalf("вердикта НЕТ: объявлений `%s` в %s — %d при требуемом ровно одном",
			check.RegistrationLanesVar, check.RegistrationLanesFileRel, census.Declarations)
	}
	if census.Lanes == 0 {
		t.Fatal("вердикта НЕТ: полос регистрации не разобрано ни одной — «ноль находок» здесь " +
			"неотличимо от «ноль прочитанного». Либо перечень пуст, либо разбор перестал его видеть (Ф4-09)")
	}
	for _, l := range lanes {
		if l.Name == "" || strings.HasPrefix(l.Name, "?") {
			t.Errorf("полоса на строке %d: имя не разрешилось (%q) — объявление обязано называть полосу "+
				"литералом либо константой того же файла", l.Line, l.Name)
			continue
		}
		if len(l.Consequences) == 0 {
			t.Errorf("полоса %q не объявила ни одного следствия — регистрация по ней ничем не заканчивается", l.Name)
			continue
		}
		if !l.IssuesSession {
			t.Errorf("полоса регистрации %q не выдаёт сессию (следствия: %v). Полосы одного потока "+
				"обязаны сходиться в том, чем поток заканчивается: человек, заведённый по этой полосе, "+
				"остаётся снаружи, тогда как соседняя полоса того же потока сессию выдаёт (Ф4-07, Ф1-24)",
				l.Name, l.Consequences)
		}
	}
	if len(outsideSites) != 0 {
		t.Errorf("полоса регистрации объявлена ВНЕ единственного объявления %s — %d мест:\n  %s\n\n"+
			"Второе место, перечисляющее полосы, разошлось бы с первым молча: гейт судил бы "+
			"перечисленное, а исполнялось бы другое (Ф4-06)",
			check.RegistrationLanesFileRel, len(outsideSites), strings.Join(outsideSites, "\n  "))
	}
}
