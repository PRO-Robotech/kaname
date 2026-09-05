// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleroles

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// reconcile.go — сверка «объявлено манифестом против живого в базе» (приёмка
// §3.4; сценарии MOD-RD-19 и MOD-RD-20).
//
// # Раскол живых строк идёт ПО ВЛАДЕЛЬЦУ имени, а не по возрасту строки
//
// Классов три, и различает их ПЕРВЫЙ СЕГМЕНТ имени:
//
//	роль модуля, у которого есть манифест  → сверяется здесь
//	роль модуля, у которого манифеста нет  → его манифест её и сверит
//	роль БЕЗ модуля-владельца              → владельца нет by construction
//
// Признак третьего класса — ЧЛЕНСТВО в наборе модулей платформы, каким его
// объявляет КАНОН (`authzmap.CatalogSeedModules`), а НЕ число сегментов. Разница не педантская:
// `kacho-system.admin` и `kacho-system.viewer` точку несут, и по признаку
// «односегментное» уехали бы во второй класс — то есть числились бы ждущими
// манифеста модуля, которого не существует, и ждали бы его вечно.
//
// # Почему сверка ЧИСТАЯ функция
//
// Ей нечего решать о состоянии: она называет расхождение, а исход выбирает
// человек — дописать объявление либо снять роль отдельным изменением (#1913;
// снятие есть ПОМЕТКА, а не удаление строки — запись решения
// `services/iam/docs/engineering/architecture/role-withdrawal-is-a-mark.md`).
// Применитель ничего не удаляет, поэтому автоматического исхода у находки нет
// by construction.

// DiscrepancyKind — вид расхождения.
type DiscrepancyKind int

const (
	// LiveNotDeclared — строка живёт, а объявления у неё нет. НАХОДКА: манифест
	// обязан описывать действующее состояние целиком, иначе «расхождений нет»
	// означает «половину не смотрели».
	LiveNotDeclared DiscrepancyKind = iota
	// DeclaredNotLive — объявлено и не заведено. До применения это норма, после
	// — след того, что применитель до строки не дошёл. Названо отдельным видом,
	// а не смешано с первым: смешав, мы получили бы «расхождений нет» на дереве,
	// где не сработал ни один писатель.
	DeclaredNotLive
)

// String — вид расхождения словом.
func (k DiscrepancyKind) String() string {
	if k == LiveNotDeclared {
		return "живёт, не объявлена"
	}
	return "объявлена, не заведена"
}

// Discrepancy — одно расхождение.
type Discrepancy struct {
	Name domain.RoleName
	Kind DiscrepancyKind
}

// String — расхождение одной строкой: обе стороны названы.
func (d Discrepancy) String() string { return fmt.Sprintf("%s — %s", d.Name, d.Kind) }

// ReconcileCensus — объём осмотренного. Печатается всегда: «ноль расхождений»
// обязано быть отличимо от «ноль осмотренного».
type ReconcileCensus struct {
	// Module — модуль, чьё объявление сверялось.
	Module string
	// LiveExamined — живых системных строк осмотрено.
	LiveExamined int
	// Declared — объявлено кластерных ролей этого модуля.
	Declared int
	// OfThisModule — живых строк, принадлежащих этому модулю.
	OfThisModule int
	// OtherModule — живых строк чужих модулей: их сверит их собственный манифест.
	OtherModule int
	// WithoutOwner — живых строк БЕЗ модуля-владельца: первый сегмент не член
	// закрытого набора модулей платформы либо точки в имени нет вовсе.
	WithoutOwner int
}

// String — перепись одной строкой.
func (c ReconcileCensus) String() string {
	return fmt.Sprintf("модуль %s · живых осмотрено %d · из них его %d · чужих модулей %d · "+
		"без модуля-владельца %d · объявлено %d",
		c.Module, c.LiveExamined, c.OfThisModule, c.OtherModule, c.WithoutOwner, c.Declared)
}

// Void — обход беспредметен: сверять было нечего. Отдельным вопросом, а не
// выводом из нулевого числа находок: молчание сверки, которой ничего не подали,
// неотличимо от молчания сверки, не нашедшей расхождений.
func (c ReconcileCensus) Void() bool { return c.LiveExamined == 0 && c.Declared == 0 }

// Reconcile сверяет живые системные роли модуля с объявленными манифестом.
//
// Возвращает расхождения обоих видов и перепись осмотренного. Порядок
// расхождений детерминирован (по имени, затем по виду): недетерминированный
// порядок сделал бы вывод несравнимым между прогонами.
func Reconcile(module string, declared []manifest.Role, live []domain.Role) ([]Discrepancy, ReconcileCensus) {
	census := ReconcileCensus{Module: module}
	// Набор — канон ПЛЮС сверяемый модуль. Сверка отвечает на вопрос «есть ли у
	// этого имени модуль-владелец вообще», и роль СНЯТОГО модуля владельца не
	// теряет — её объявление по-прежнему принадлежит его манифесту (#1927).
	//
	// Сверяемый модуль добавлен вместе с размыканием набора (`manifest`,
	// moduleset.go): его в порождённой сборкой таблице может не быть вовсе, а
	// без него живая роль модуля оператора попадала в «без владельца» и
	// ПРОПУСКАЛАСЬ — расхождение «живая, но не объявлена» не находилось никогда,
	// и снять устаревшую роль оператора было нечем.
	//
	// ОСТАТОК НАЗВАН, а не умолчан: роль ТРЕТЬЕГО модуля оператора при сверке
	// этого попадёт в «без владельца» вместо «другого модуля». Это разряд
	// ПЕРЕПИСИ, а не решение — ни одна ветвь ниже на нём не ветвится, — и его
	// точный ответ дают живые строки каталога, чья опора переезжает задачей
	// #1861.
	known := domain.ModuleSetOf(append(authzmap.CatalogSeedModules(), module)...)

	declaredSet := make(map[domain.RoleName]struct{}, len(declared))
	for i := range declared {
		d := &declared[i]
		if d.Tier == nil || d.Tier.TierType != domain.ScopeTypeClusterDotted {
			continue
		}
		if owner, _, ok := strings.Cut(d.ID, "."); !ok || owner != module {
			continue
		}
		declaredSet[domain.RoleName(d.ID)] = struct{}{}
	}
	census.Declared = len(declaredSet)

	liveSet := make(map[domain.RoleName]struct{}, len(live))
	var found []Discrepancy
	for _, r := range live {
		if !r.IsSystemDerived() {
			continue
		}
		census.LiveExamined++
		owner, _, hasDot := strings.Cut(string(r.Name), ".")
		switch {
		case !hasDot || !known.IsKnownModule(owner):
			census.WithoutOwner++
			continue
		case owner != module:
			census.OtherModule++
			continue
		}
		census.OfThisModule++
		liveSet[r.Name] = struct{}{}
		if _, ok := declaredSet[r.Name]; !ok {
			found = append(found, Discrepancy{Name: r.Name, Kind: LiveNotDeclared})
		}
	}
	for name := range declaredSet {
		if _, ok := liveSet[name]; !ok {
			found = append(found, Discrepancy{Name: name, Kind: DeclaredNotLive})
		}
	}
	sort.Slice(found, func(i, j int) bool {
		if found[i].Name != found[j].Name {
			return found[i].Name < found[j].Name
		}
		return found[i].Kind < found[j].Kind
	})
	return found, census
}
