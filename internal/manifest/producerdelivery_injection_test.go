// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// producerdelivery_injection_test.go — доказательство того, что сквозная проба
// доставки СПОСОБНА упасть, падает НЕ НА ВСЁМ и молчит на законных близнецах
// (задачи #1901, #1909).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ИНЪЕКЦИЯ ПОДМЕНЯЕТ КОРЕНЬ, А НЕ ДОБАВЛЯЕТ СТЕНД
//
// Инъекция вида «завести ещё один элемент» доказательством не является: новый
// элемент нарушает всё, что требуется от элементов вообще, и красное приходит
// неизвестно от чего (`testing.md` §«Гейт на класс», п. 2в). Поэтому здесь у
// НАСТОЯЩЕГО стенда — с его именем и его цепочкой из таблицы — подменяется
// ровно одно: корень, из которого производитель берёт манифесты. Старое
// свойство стенда (доставку объявляет) остаётся на месте, снимается новое
// (доставленное принимается читателем).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ДОКАЗЫВАЕТСЯ ПРЕЖНЕЙ ФОРМОЙ ПРОБЫ
//
// Прогон «слепота прежней формы» воспроизводит дефект, ради которого проба
// переписана: популяция из ОДНОГО стенда разработки молчит на инъекции в
// БОЕВОЙ стенд. Это и есть измеренная цена приколоченной константы: полоса, на
// которой отказ дороже всего, кругом не проверялась вовсе.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// productionStackName — стенд, чья посадка боевая. Имя, а не цепочка: цепочку
// объявляет ТОЛЬКО таблица, и вторая копия разошлась бы с ней молча.
const productionStackName = "prod"

// syntheticRoot — корень дерева, собранный пробой: `services/<dir>/manifest.yaml`
// с заданным телом на каждый каталог. Настоящего дерева не трогает.
func syntheticRoot(t *testing.T, manifests map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for dir, body := range manifests {
		d := filepath.Join(root, "services", dir)
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("каталог службы %s не заведён: %v", d, err)
		}
		if err := os.WriteFile(filepath.Join(d, "manifest.yaml"), []byte(body), 0o600); err != nil {
			t.Fatalf("манифест %s не записан: %v", dir, err)
		}
	}
	return root
}

// syntheticProfile — профиль умбреллы, объявляющий (или не объявляющий) имя
// объекта доставки.
func syntheticProfile(t *testing.T, name string) string {
	t.Helper()
	body := "kacho-iam: {}\n"
	if name != "" {
		body = "kacho-iam:\n  manifests:\n    configMapName: " + name + "\n"
	}
	p := filepath.Join(t.TempDir(), "values.synthetic.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("синтетический профиль не записан: %v", err)
	}
	return p
}

// withRoot — копия популяции, в которой одному стенду подменён корень.
func withRoot(stacks []deliveryStack, stack, root string) []deliveryStack {
	out := make([]deliveryStack, 0, len(stacks))
	for _, s := range stacks {
		if s.Name == stack {
			s.Root = root
		}
		out = append(out, s)
	}
	return out
}

// onlyStack — популяция из одного стенда: так выглядела ПРЕЖНЯЯ форма пробы,
// приколоченная к одному профилю.
func onlyStack(stacks []deliveryStack, name string) []deliveryStack {
	for _, s := range stacks {
		if s.Name == name {
			return []deliveryStack{s}
		}
	}
	return nil
}

func TestDeliveryRoundTripAuditFallsAndStaysSilentOnItsTwin(t *testing.T) {
	root := repoRootFromTest(t)
	stacks := deliveryStacksOfTree(t, root)
	if len(stacks) < 2 {
		t.Fatalf("в таблице %d стенд(ов) — инъекция «сломан ОДИН из многих» "+
			"непредставима, предпосылка доказательства исчезла", len(stacks))
	}
	if onlyStack(stacks, productionStackName) == nil {
		t.Fatalf("стенда %q в таблице нет — прогон слепоты потерял свой предмет: "+
			"боевая посадка переименована либо снята", productionStackName)
	}

	// ── ПРОГОН 1: КОНТРОЛЬ. Целая популяция — молчит.
	findings, census := auditDeliveryRoundTrip(t, stacks)
	t.Logf("контроль: %s", census.Summary())
	if len(findings) != 0 {
		t.Fatalf("контроль: на целом дереве находок %d: %v", len(findings), findings)
	}
	if census.Declaring == 0 || census.RoundTripped != census.Declaring {
		t.Fatalf("контроль беспредметен: %s", census.Summary())
	}

	// ── ПРОГОН 2: ИНЪЕКЦИЯ НОВОГО ПРЕДМЕТА. У БОЕВОГО стенда доставленный
	// манифест негоден — читатель обязан его отвергнуть, а проба назвать стенд.
	broken := syntheticRoot(t, map[string]string{
		"iam": "apiVersion: iam/v1\n", // модуль не назван — читатель отвергнет
		"vpc": "apiVersion: iam/v1\nmodule: vpc\n",
	})
	f2, c2 := auditDeliveryRoundTrip(t, withRoot(stacks, productionStackName, broken))
	if len(f2) == 0 {
		t.Fatalf("инъекция: доставленный %s манифест негоден, а проба молчит (%s) — "+
			"она не измеряет своего предмета", productionStackName, c2.Summary())
	}
	if !strings.Contains(strings.Join(f2, "\n"), productionStackName+":") {
		t.Errorf("инъекция: находка не называет стенд %q — оператор пойдёт чинить "+
			"не ту посадку: %v", productionStackName, f2)
	}
	// Находка обязана называть ПРИЧИНУ, а не симптом: на неё тратят прогон, а
	// потом снимают пробу как непонятную (`testing.md` §«Гейт на класс», п. 8).
	t.Logf("инъекция «манифест негоден» напечатала:\n%s", strings.Join(f2, "\n"))
	// Роняет ТОЛЬКО проверяемое: стендов столько же, объявляют доставку столько
	// же, круг не прошёл ровно один.
	if c2.Stacks != census.Stacks || c2.Declaring != census.Declaring {
		t.Errorf("инъекция изменила популяцию (%s против %s) — она уронила не то, "+
			"что проверяется", c2.Summary(), census.Summary())
	}
	if c2.RoundTripped != census.RoundTripped-1 {
		t.Errorf("круг не прошли %d стендов, ожидался ровно один (%s)",
			census.RoundTripped-c2.RoundTripped, c2.Summary())
	}

	// ── ПРОГОН 3: СЛЕПОТА ПРЕЖНЕЙ ФОРМЫ. Та же инъекция, популяция из одного
	// стенда разработки — молчит. Это и есть дефект, ради которого проба
	// переписана: боевая полоса была вне наблюдения BY CONSTRUCTION.
	dev := onlyStack(stacks, "dev")
	if dev == nil {
		t.Fatalf("стенда %q в таблице нет — прогон слепоты потерял свой предмет", "dev")
	}
	f3, c3 := auditDeliveryRoundTrip(t, withRoot(dev, productionStackName, broken))
	if len(f3) != 0 {
		t.Fatalf("прежняя форма: популяция из одного стенда дала находки %v — прогон "+
			"слепоты перестал воспроизводить свой предмет (%s)", f3, c3.Summary())
	}
	t.Logf("слепота прежней формы воспроизведена: %s — та же инъекция, ноль находок",
		c3.Summary())

	// ── ПРОГОН 4: ИНЪЕКЦИЯ ВТОРОЙ ОСИ. Манифеста в дереве нет ни одного:
	// производитель отказывается собирать пустой объект.
	empty := syntheticRoot(t, map[string]string{})
	f4, c4 := auditDeliveryRoundTrip(t, withRoot(stacks, productionStackName, empty))
	if len(f4) == 0 {
		t.Fatalf("инъекция: манифестов ноль, а проба молчит (%s)", c4.Summary())
	}
	if !strings.Contains(strings.Join(f4, "\n"), productionStackName+":") {
		t.Errorf("инъекция пустого дерева: находка не называет стенд %q: %v",
			productionStackName, f4)
	}

	// ── БЛИЗНЕЦ 1: стенд доставку НЕ объявляет. Это решение посадки, а не
	// находка: судит его гейт пары, здесь стенд лишь не входит в число
	// прошедших круг — и это видно в переписи.
	silent := make([]deliveryStack, 0, len(stacks))
	for _, s := range stacks {
		if s.Name == productionStackName {
			s.Profiles = []string{syntheticProfile(t, "")}
			s.Root = broken // корень СЛОМАН намеренно: до него не должно дойти
		}
		silent = append(silent, s)
	}
	f5, c5 := auditDeliveryRoundTrip(t, silent)
	if len(f5) != 0 {
		t.Errorf("близнец «доставка не объявлена»: находок %d (%v) — решение посадки "+
			"объявлено находкой (%s)", len(f5), f5, c5.Summary())
	}
	if c5.Declaring != census.Declaring-1 {
		t.Errorf("близнец «доставка не объявлена»: объявивших %d, ожидалось %d (%s)",
			c5.Declaring, census.Declaring-1, c5.Summary())
	}

	// ── БЛИЗНЕЦ 2: цепочка объявляет ДРУГОЕ имя объекта. Имя выбирает посадка;
	// круг от него не зависит, и проба обязана молчать.
	renamed := make([]deliveryStack, 0, len(stacks))
	for _, s := range stacks {
		if s.Name == productionStackName {
			s.Profiles = []string{syntheticProfile(t, "kacho-module-manifests-renamed")}
		}
		renamed = append(renamed, s)
	}
	f6, c6 := auditDeliveryRoundTrip(t, renamed)
	if len(f6) != 0 {
		t.Errorf("близнец «объект переименован»: находок %d (%v) — проба судит имя "+
			"объекта, а её предмет — содержимое (%s)", len(f6), f6, c6.Summary())
	}

	// ── ПРЕЖНИЙ ПРЕДМЕТ ЦЕЛ. Молчание соседней проверки читателя неотличимо от
	// её смерти, пока не показано, что она по-прежнему судит годную доставку.
	report, err := manifest.LoadDelivered(configMapMount(t, deliveredModules()))
	if err != nil || report.ManifestsRead != len(deliveredModules()) {
		t.Fatalf("прежний предмет пострадал: годная доставка отвергнута (%v, прочитано %d) — "+
			"инъекция уронила не только проверяемое", err, report.ManifestsRead)
	}
}
