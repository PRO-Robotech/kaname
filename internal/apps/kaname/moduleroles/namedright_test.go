// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// namedright_test.go — ПОИМЁННОЕ право роли на пути ПРИМЕНИТЕЛЯ (задача
// продукта #1998).
//
// # Предмет: у поимённой формы один законный путь, и применитель шёл мимо него
//
// Форм записи права роли две, и сводится к классу только ПРОВЕРЕННЫЙ перечень:
// сведение требует каталога прав, которого у загрузчика нет. Значит у поимённого
// права ровно один законный производитель — экспортёр
// (`roleexport.ExportRoleRules`), а применитель строил политику из
// `manifest.Rule.DomainRule()`, который поимённое право отдаёт ПУСТЫМ.
//
// Дырой это не было: домен отвергает правило без глаголов, и применитель
// останавливался. Но отказ говорил НЕ О ТОМ — «политика роли не компилируется»,
// то есть о форме правила, тогда как причина в том, что этот путь поимённой
// формы не проходит вовсе. Отказ, не восстанавливающий следующий шаг, — тот же
// класс, что корпус ловит в отказах вообще.
//
// # Что утверждается здесь, а что не здесь
//
// Утверждается ИСХОД ПРИМЕНЕНИЯ: строка роли, произведённая из полного
// поимённого перечня, ПОБАЙТОВО равна строке, произведённой из его класса, — и
// отказ на НЕПОЛНОМ перечне называет недостающие имена. Свойства самого
// экспортёра (единица полноты, пересечение классов, минимальность сведения)
// утверждают пробы `roleexport`; повторять их здесь значило бы завести два места
// об одном предмете.
package moduleroles_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/rightsfixture"
)

// subnetVerbsFull — раздел действий `subnet` целиком. Класс `update` покрывает
// на нём ТРИ действия, и без третьего пара «полный перечень против класса»
// различала бы не то: перечень из одного имени совпал бы с классом тривиально.
const subnetVerbsFull = "" +
	"      - get\n      - list\n      - create\n      - update\n      - delete\n" +
	"      - {name: listOperations,    class: list}\n" +
	"      - {name: addCidrBlocks,     class: update}\n" +
	"      - {name: removeCidrBlocks,  class: update}\n"

// namedRightManifest — манифест с ОДНОЙ ролью КЛАСТЕРНОГО яруса: иного яруса
// применитель не пишет вовсе, и роль проекта дала бы «пропущено», а не вердикт.
func namedRightManifest(t *testing.T, rule string) *manifest.Manifest {
	t.Helper()
	doc := "apiVersion: iam/v1\nmodule: vpc\n" +
		"resources:\n" +
		"  - name: subnet\n    objectType: vpc_subnet\n    parents: [project]\n" +
		"    producer: derived\n    verbs:\n" + subnetVerbsFull +
		"roles:\n" +
		"  - id: vpc.subnet.editor\n    description: Правит подсети модуля.\n" +
		"    tier: {tierType: iam.cluster, tierId: cluster_root}\n" +
		"    rules:\n      - " + rule + "\n"
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("фикстура манифеста отвергнута загрузчиком: %v", err)
	}
	return m
}

// appliedRuleRow — правило записанной роли в том же кодеке, каким его кладёт в
// базу оператор вставки. Своё сравнение полей разошлось бы с ним молча.
func appliedRuleRow(t *testing.T, rule string) []byte {
	t.Helper()
	store := newStore()
	rep, err := applierUnderTest(t, store).Apply(context.Background(), namedRightManifest(t, rule), moduleroles.BootActorID)
	if err != nil {
		t.Fatalf("применение правила %q отвергнуто: %v", rule, err)
	}
	if rep.Written != 1 {
		t.Fatalf("правило %q: записано %d строк, ожидалась одна — сравнивать нечего (%s)",
			rule, rep.Written, rep)
	}
	row, ok := store.rows[domain.SystemRoleID("vpc.subnet.editor")]
	if !ok {
		t.Fatalf("правило %q: строки роли нет", rule)
	}
	return mustEncode(row.Rules)
}

// TestNamedRightReachesTheApplierReducedToItsClass — НЕСУЩЕЕ утверждение
// (#1998): полный поимённый перечень доезжает до строки роли СВЕДЁННЫМ к своему
// классу, и строка получается та же, что у формы классов.
//
// Побайтово, а не «эквивалентно»: §3.6 п. 5 приёмки поимённой формы говорит
// «обе формы дают ровно один и тот же `Rule`», и сравнение по смыслу приняло бы
// `[update, delete]` вместо `[update]` — другое право при том же покрытии.
func TestNamedRightReachesTheApplierReducedToItsClass(t *testing.T) {
	const namedFull = "{module: vpc, resources: [subnet], verbs: [update, addCidrBlocks, removeCidrBlocks]}"
	const classForm = "{module: vpc, resources: [subnet], classes: [update]}"

	fromNamed := appliedRuleRow(t, namedFull)
	fromClass := appliedRuleRow(t, classForm)

	if string(fromNamed) != string(fromClass) {
		t.Fatalf("формы права дали РАЗНЫЕ строки роли:\n  поимённая: %s\n  классов:   %s",
			fromNamed, fromClass)
	}
	// Контроль невакуумности: сравнение выше выполнимо двумя пустыми строками —
	// например применителем, который правил не пишет вовсе.
	if !strings.Contains(string(fromClass), `"update"`) {
		t.Fatalf("строка роли не несёт класса `update` (%s) — сравнение выше зеленело бы "+
			"на применителе, обнуляющем правило", fromClass)
	}
	t.Logf("обе формы дали одну строку: %s", fromClass)
}

// TestIncompleteNamedRightRefusalNamesTheMissingNames — ОТРИЦАТЕЛЬНЫЙ близнец,
// отличающийся от положительного РОВНО ОДНИМ фактом: из перечня вынуты два
// имени того же класса.
//
// Отказ обязан назвать НЕДОСТАЮЩИЕ имена — то есть быть текстом экспортёра, а не
// «политика роли не компилируется»: последнее посылает автора править форму
// правила, тогда как править надо перечень.
func TestIncompleteNamedRightRefusalNamesTheMissingNames(t *testing.T) {
	store := newStore()
	_, err := applierUnderTest(t, store).Apply(context.Background(),
		namedRightManifest(t, "{module: vpc, resources: [subnet], verbs: [addCidrBlocks]}"), moduleroles.BootActorID)
	if err == nil {
		t.Fatal("НЕПОЛНЫЙ поимённый перечень применён без отказа: право выдано ШИРЕ просимого")
	}
	if store.calls != 0 {
		t.Errorf("писатель звался %d раз на отвергнутом манифесте — отказ обязан приходить "+
			"ДО записи", store.calls)
	}
	if !errors.Is(err, moduleroles.ErrNamedRightIncomplete) {
		t.Errorf("отказ не отнесён к своей причине (ожидался ErrNamedRightIncomplete): %v", err)
	}
	if got := moduleroles.RefusalLane(err); got != moduleroles.LaneNamedRightIncomplete {
		t.Errorf("полоса отказа %q, ожидалась %q", got, moduleroles.LaneNamedRightIncomplete)
	}
	// Недостающие имена названы ОБА: одно из двух отправило бы автора на второй
	// круг за тем же отказом.
	for _, want := range []string{"removeCidrBlocks", "update", "vpc.subnet.editor"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}
	// И НЕ называет полосы, к которой предмет не относится: она посылает править
	// форму правила вместо перечня.
	if strings.Contains(err.Error(), "does not compile") {
		t.Errorf("отказ говорит о несворачиваемости политики — это другая полоса: %v", err)
	}
}

// TestApplierWithoutRightsExportRefusesInsteadOfGuessing — производитель правил
// НЕ ПРОВЯЗАН: отказ, а не пропуск.
//
// Пропуск здесь снял бы проверку полноты целиком и молча — поимённое право
// поехало бы несведённым либо пустым, и вызывающий узнал бы об этом отказом о
// форме правила. Текст отдельный: виновата ПРОВЯЗКА, а не вход, и следующий шаг
// у этих двух разный.
func TestApplierWithoutRightsExportRefusesInsteadOfGuessing(t *testing.T) {
	store := newStore()
	_, err := moduleroles.NewApplier(store, nil).Apply(context.Background(),
		namedRightManifest(t, "{module: vpc, resources: [subnet], classes: [update]}"), moduleroles.BootActorID)
	if err == nil {
		t.Fatal("применитель без производителя правил применил манифест: проверка полноты " +
			"снята молча")
	}
	if !errors.Is(err, moduleroles.ErrRightsExportNotWired) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if got := moduleroles.RefusalLane(err); got != moduleroles.LaneRightsExportNotWired {
		t.Errorf("полоса отказа %q, ожидалась %q", got, moduleroles.LaneRightsExportNotWired)
	}
	if store.calls != 0 {
		t.Errorf("писатель звался %d раз без провязанного производителя правил", store.calls)
	}
}

// applierUnderTest — применитель с НАСТОЯЩИМ производителем правил: те же
// каталожный факт и записи каталога прав, что собирает команда обхода дерева.
//
// Подставной производитель здесь запрещён: предмет проб — что применитель идёт
// ЧЕРЕЗ экспортёр, и дублёр, отвечающий «сведено» без проверки полноты, сделал
// бы невидимым ровно тот дефект, ради которого их пишут.
func applierUnderTest(t *testing.T, tx moduleroles.TxRunner) *moduleroles.Applier {
	t.Helper()
	return moduleroles.NewApplier(tx, rightsfixture.Export())
}
