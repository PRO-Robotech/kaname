// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// proxy_type_owner_test.go — словарь владения типом провязан и согласен со
// словарём написаний модуля (задача продукта #1885).
//
// # Что здесь утверждается
//
//  1. закрытая таблица типов и словарь написаний СОГЛАСНЫ: у каждого её типа
//     владелец — объявленный модуль платформы. Разойдись они — правило отвергало
//     бы живые типы, и наблюдаемо это было бы как «ресурс создан, доступа нет»;
//  2. ПАРА на настоящей таблице: свой тип принимается, чужой отвергается;
//  3. полоса ПРЕВЕНТИВНА, и это измерено, а не заявлено: на сегодняшнем дереве
//     словарь не меняет НИ ОДНОГО вердикта против прежней проверки приставкой.
//     Число печатается вместе со знаменателем — иначе «расхождений ноль»
//     неотличимо от «сравнений ноль».

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/authz/proxytuple"
	"github.com/PRO-Robotech/kacho/pkg/platformmodules"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
)

// TestClosedTypeTableAgreesWithTheModuleVocabulary — предпосылка самого правила.
func TestClosedTypeTableAgreesWithTheModuleVocabulary(t *testing.T) {
	declared := map[string]bool{}
	for _, m := range platformmodules.All() {
		declared[m.CatalogModule] = true
	}

	owner := catalogTypeOwner{}
	var seen, resolved int
	var orphans []string
	for _, e := range authzmap.Catalog() {
		fga, ok := authzmap.ObjectType(e.Module, e.Resource)
		if !ok {
			continue
		}
		seen++
		module, known := owner.CatalogModuleOfObjectType(fga)
		if !known {
			orphans = append(orphans, fga+" — словарь владения его не знает")
			continue
		}
		if !declared[module] {
			orphans = append(orphans, fga+" → модуль "+module+" словарём написаний не объявлен")
			continue
		}
		resolved++
	}

	t.Logf("перепись: типов закрытой таблицы осмотрено %d, владелец объявленным модулем "+
		"разрешён у %d, модулей платформы объявлено %d",
		seen, resolved, len(declared))

	if seen == 0 {
		t.Fatalf("осмотрено ноль типов — обход беспредметен, и его «ноль находок» получено даром")
	}
	sort.Strings(orphans)
	if len(orphans) > 0 {
		t.Fatalf("закрытая таблица типов разошлась со словарём написаний — %d тип(ов):\n  %s\n\n"+
			"Правило проксируемой записи спрашивает владельца у первой и сверяет со второй. "+
			"Разойдясь, они отвергают ЖИВОЙ тип, и наблюдаемо это как «ресурс создан, "+
			"доступа нет».", len(orphans), strings.Join(orphans, "\n  "))
	}
}

// TestOwnTypeIsAcceptedAndForeignRefusedOnTheRealTable — ПАРА, обе стороны.
//
// Балансировщик стоит здесь не для полноты: у него три написания различны
// (`nlb` / `loadbalancer` / `nlb_listener`), и предикат «имя службы == модуль
// каталога» не совпал бы для него НИКОГДА.
func TestOwnTypeIsAcceptedAndForeignRefusedOnTheRealTable(t *testing.T) {
	for _, c := range []struct {
		caller, object string
		refused        bool
		why            string
	}{
		{"vpc", "vpc_network:net-1", false, "свой тип"},
		{"nlb", "nlb_listener:lsn-1", false, "свой тип при ТРЁХ различных написаниях"},
		{"compute", "vpc_network:net-1", true, "чужой тип"},
		{"vpc", "nlb_listener:lsn-1", true, "чужой тип с чужой приставкой"},
	} {
		err := validateProxyTuple(c.caller, "user:u1", "owner", c.object)
		if c.refused {
			if err == nil {
				t.Fatalf("%s → %s (%s): принято, а обязано быть отвергнуто", c.caller, c.object, c.why)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s → %s (%s): отвергнуто (%v) — проверка отняла живое право",
				c.caller, c.object, c.why, err)
		}
	}
}

// TestTheDictionaryChangesNoVerdictToday — ПОЛОСА ПРЕВЕНТИВНА, и это ИЗМЕРЕНО.
//
// Перебираются все пары «писатель × тип закрытой таблицы», и вердикт со словарём
// сверяется с вердиктом по приставке. Расхождение сегодня означало бы, что
// изменение отняло либо выдало право прямо сейчас, — а задача заведена не ради
// этого: предмет её в том, что совпадение приставки с именем домена оставалось
// УСЛОВИЕМ работы.
func TestTheDictionaryChangesNoVerdictToday(t *testing.T) {
	var compared int
	var diverged []string
	for _, m := range platformmodules.All() {
		for _, e := range authzmap.Catalog() {
			fga, ok := authzmap.ObjectType(e.Module, e.Resource)
			if !ok {
				continue
			}
			object := fga + ":obj-1"
			withDict := validateProxyTuple(m.Service, "user:u1", "owner", object)
			byPrefix := proxytuple.ValidateTuple(m.Service, "user:u1", "owner", object)
			compared++
			if (withDict == nil) == (byPrefix == nil) {
				continue
			}
			verdict := "отвергнут"
			if withDict == nil {
				verdict = "принят"
			}
			diverged = append(diverged, fmt.Sprintf("%s → %s: со словарём %s, по приставке иначе",
				m.Service, fga, verdict))
		}
	}

	t.Logf("перепись: пар «писатель × тип» сравнено %d, вердиктов разошлось %d",
		compared, len(diverged))

	if compared == 0 {
		t.Fatalf("сравнено ноль пар — «расхождений ноль» получено даром")
	}
	sort.Strings(diverged)
	if len(diverged) > 0 {
		t.Fatalf("словарь изменил %d вердикт(ов) на сегодняшнем дереве:\n  %s\n\n"+
			"Полоса объявлена превентивной. Разошедшийся вердикт означает, что право "+
			"отобрано либо выдано ПРЯМО СЕЙЧАС, и такое изменение обязано приезжать своим "+
			"предметом, а не следствием.", len(diverged), strings.Join(diverged, "\n  "))
	}
	// Контроль в обратную сторону: обе стороны сравнения обязаны быть способны
	// отвергнуть. Иначе «расхождений ноль» вышло бы у двух проверок, принимающих всё.
	// Отказ этой стороны приезжает СТАТУСОМ: транспорт приводит вердикт правила к
	// PermissionDenied в одном месте, поэтому здесь утверждается непустота, а не
	// сигнальная ошибка — сравнение с ней зеленело бы всегда и молча.
	if err := validateProxyTuple("compute", "user:u1", "owner", "vpc_network:net-1"); err == nil {
		t.Fatalf("сторона со словарём ничего не отвергает")
	}
	if err := proxytuple.ValidateTuple("compute", "user:u1", "owner", "vpc_network:net-1"); !errors.Is(err, proxytuple.ErrRefused) {
		t.Fatalf("сторона по приставке ничего не отвергает: %v", err)
	}
}
