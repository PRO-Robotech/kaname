// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package catalog_test

// live_type_reaches_the_projection_test.go — ЗАВЕДЁННЫЙ в работающем процессе
// тип доезжает до проекции (kacho#1816, эпик #1027 DoD п. 1).
//
// # Чего НЕ утверждали пробы переезда, и почему это не мелочь
//
// Приёмка переезда читателей на строки покрыла ОДНО направление — СНЯТИЕ:
// `IAM-CT-2-06` требует, чтобы снятый в работающем процессе тип пар не давал, а
// `-07` держит к нему отрицательный контроль. Обратного направления —
// ЗАВЕДЕНИЯ — не утверждает ни один из тринадцати сценариев.
//
// Асимметрия не косметическая: у снятия и заведения РАЗНЫЕ производители
// ответа. Снятие видно строкам, потому что строка исчезает; заведение строкам
// НЕ видно, потому что имя типа модели прав в строке не лежит — его отдаёт
// словарь, порождённый СБОРКОЙ. Тип, которого сборка не знала, получает
// `ok=false` на переходнике, и вызывающий пропускает строку. Наблюдается это как
// «прав не выдали»: строки записаны, членство модуля отвечает «да», роль
// создаётся без отказа — и проекция пуста.
//
// Это дословно тот исход, который эпик #1027 назвал блокатором выноса в
// опенсорс: «YAML объявит тип, роль создастся, привязка прочитается как
// действующая, арендатор не получит ничего».

import (
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// appliedModule — модуль, заведённый ПОСЛЕ сборки: ни его имени, ни имени его
// типа в дереве нет ни одним литералом. Проверяется это самой пробой ниже
// (положительный контроль «сборка его действительно не знает»), а не
// объявляется здесь комментарием.
const (
	appliedModule     = "billing"
	appliedResource   = "invoice"
	appliedDotted     = appliedModule + "." + appliedResource
	appliedObjectType = "billing_invoice"
)

// rowsWithAppliedResource — живые строки каталога ПЛЮС ресурс, заведённый
// применением манифеста в работающем процессе.
//
// Строки посева берутся у `seed.LiteralRows()` — того же перечня, которым
// каталог посеян и с которым его сверяет страж старта. Второй производитель того
// же перечня разошёлся бы с первым молча.
func rowsWithAppliedResource() catalog.Rows {
	rows := seed.LiteralRows()
	rows.Modules = append(rows.Modules, appliedModule)
	rows.Resources = append(rows.Resources, catalog.ResourceRow{
		Module:     appliedModule,
		Resource:   appliedResource,
		ObjectType: appliedObjectType,
	})
	for _, verb := range []string{"get", "list", "update", "delete"} {
		rows.Verbs = append(rows.Verbs, catalog.VerbRow{
			Module:    appliedModule,
			Resource:  appliedResource,
			Verb:      verb,
			PerObject: true,
		})
	}
	return rows
}

// TestIAMCT2_14_AppliedTypeReachesTheProjection — `-14`: тип, заведённый
// применением манифеста в РАБОТАЮЩЕМ процессе, даёт пары проекции.
//
// Зеркало `-06`. Тот требует, чтобы СНЯТЫЙ тип пар не давал; этот — чтобы
// ЗАВЕДЁННЫЙ их давал. Порознь каждое утверждение выполнимо портом, который не
// производит пар НИКОГДА (`-06` зеленел бы на нём целиком), поэтому направления
// обязаны утверждаться оба.
func TestIAMCT2_14_AppliedTypeReachesTheProjection(t *testing.T) {
	f, err := catalog.NewFacts(rowsWithAppliedResource())
	if err != nil {
		t.Fatalf("снимок со строкой заведённого ресурса: %v", err)
	}

	// Положительный контроль ПРЕДПОСЫЛКИ: членство модуля живо. Без него
	// «пар нет» было бы неотличимо от «строк не подали вовсе».
	if !f.IsKnownModule(appliedModule) {
		t.Fatalf("модуль %q не признан живым — строки не доехали, вердикт о проекции беспредметен",
			appliedModule)
	}

	// Положительный контроль ПОСАДКИ: набор глаголов ЖИВОГО соседа читается.
	// Без него «пар нет» было бы неотличимо от снимка, сломанного целиком.
	if got := f.VerbsOfType("vpc_network"); len(got) == 0 {
		t.Fatalf("живой сосед vpc_network не даёт глаголов — снимок сломан целиком, "+
			"вердикт о заведённом типе беспредметен (получено %v)", got)
	}

	sel := []domain.RuleSelector{{
		ObjectTypes: []string{appliedDotted},
		Verbs:       []string{"*"},
	}}

	pairs := f.RoleVerbsFromSelectors(sel)
	if len(pairs) == 0 {
		t.Fatalf("проекция по заведённому типу %q пуста: пар 0.\n"+
			"Строки каталога записаны, членство модуля отвечает «да», роль создалась бы без "+
			"отказа — и арендатор не получил бы НИЧЕГО. Имя типа модели прав строка не несёт, "+
			"его отдаёт словарь, порождённый сборкой; типа %q сборка не знала.",
			appliedDotted, appliedObjectType)
	}

	// Набор глаголов проекции — тот, что объявили СТРОКИ, а не тот, что знала
	// сборка. Утверждать только непустоту значило бы принять любой набор.
	want := map[string]bool{"get": true, "list": true, "update": true, "delete": true}
	got := map[string]bool{}
	for _, p := range pairs {
		if p.ObjectType != appliedDotted {
			t.Errorf("пара названа чужим типом %q, ожидался %q", p.ObjectType, appliedDotted)
			continue
		}
		got[p.Verb] = true
	}
	for verb := range want {
		if !got[verb] {
			t.Errorf("глагол %q объявлен строкой и в проекцию не попал (получено %v)", verb, got)
		}
	}
	for verb := range got {
		if !want[verb] {
			t.Errorf("глагол %q в проекции есть, а строкой не объявлен", verb)
		}
	}
}

// TestIAMCT2_14_ControlBuildDoesNotKnowTheAppliedType — предпосылка пробы выше.
//
// Она осмысленна ровно пока сборка этого типа НЕ знает: впиши кто-нибудь
// `billing.invoice` в манифест — и `-14` зеленела бы, ничего не проверяя, а
// отличить это от исправного порта было бы нечем.
func TestIAMCT2_14_ControlBuildDoesNotKnowTheAppliedType(t *testing.T) {
	if buildKnowsDotted(appliedDotted) {
		t.Fatalf("сборка знает %q — предпосылка -14 отпала, и проба зеленела бы вхолостую. "+
			"Возьмите для пробы имя, которого нет ни в одном манифесте", appliedDotted)
	}
}

// buildKnowsDotted — знает ли ЗНАНИЕ СБОРКИ это точечное имя.
//
// Спрашивается перечень посева (`authzmap.CatalogSeedResources`), а не
// переходник имени: переходник — предмет правки, и контроль предпосылки, построенный на
// нём, перестал бы отвечать вместе с ним. Перечень посева же остаётся ответом на
// вопрос «что знала СБОРКА» при любом устройстве переходника.
func buildKnowsDotted(dotted string) bool {
	for _, r := range authzmap.CatalogSeedResources() {
		if r.Dotted == dotted {
			return true
		}
	}
	return false
}
