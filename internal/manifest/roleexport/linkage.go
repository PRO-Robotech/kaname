// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package roleexport

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// linkage.go — соединение «имя действия манифеста ↔ запись каталога прав»
// (задача PRO-Robotech/kacho#1844).
//
// # Чего здесь НЕ заводится: второго правила написания
//
// Правило одно и объявлено в attribution.go (`splitFQN`): служба называет
// ресурс, метод — действие, приставка `internal` добавляется к имени метода КАК
// ЕСТЬ. Генератор раздела `resources` (#1092) обязан звать ТО ЖЕ объявление —
// `Attribute` — и эмитить `Resource`/`Verb` дословно. Второе правило,
// написанное здесь «по образцу», разошлось бы с первым на первом же методе,
// чьё имя не подошло под образец, и разошлось бы МОЛЧА: обе стороны отвечают
// одинаково там, где правило совпадает.
//
// # Сверка ДВУСТОРОННЯЯ, и односторонней быть не может
//
// Действие манифеста без записи каталога — право, которое никто не спрашивает:
// выдав его, арендатор не получает ничего. Проверив одну сторону, мы объявили бы
// соединение полным, имея половину, и вторая половина оказалась бы вне
// наблюдения — не нарушением, а невидимостью.
//
// # Но стороны НЕ СИММЕТРИЧНЫ, и симметричной сверка быть не может
//
// Здесь стояло «запись каталога без действия манифеста — гейт, которого раздел
// не описывает: право существует, а выдать его нечем», и обратная сторона по
// этой посылке отвергала КАЖДУЮ такую запись. Посылка неверна: на настоящем
// дереве так отвергались бы 127 записей из 127, и ни одна не была бы дефектом.
//
// Прямая сторона биективна by construction: действие рендерится в ровно одно
// `define v_<действие>`. Обратная — нет, и это свойство КАТАЛОГА:
//
//   - одно отношение гейтит несколько записей (`AddCidrBlocks`,
//     `RemoveCidrBlocks` и `Update` — все три `v_update` на `vpc_subnet`);
//   - часть записей гейтится ЯРУСОМ ОБЛАСТИ (`Create` — `editor` на `project`),
//     и кортеж туда пишет ярусная роль платформы, а не действие модуля;
//   - часть не гейтится вовсе (`required_relation` пуст).
//
// Потребовать действия на каждую запись нельзя и by construction: названный
// `addCidrBlocks` породил бы `define v_addcidrblocks`, которого в каноне нет, —
// и побайтовая сверка модели его отвергла бы. Две проверки одного дерева не
// вправе требовать несовместимого.
//
// Поэтому обратная сторона ОТНОСИТ запись к её состоянию, а находкой оставляет
// ровно одно: гейт спрашивает отношение ресурса, которого не порождает НИ ОДНО
// объявленное действие. Право на него выдать нечем ни действием, ни ярусом —
// вот это дефект.
//
// Числа замера и разбор прежнего предиката — задача PRO-Robotech/kacho#1091.
//
// # Популяция ограничена `producer: derived`, и это НЕ послабление
//
// Ключ `producer` объявляет, чем являются ключи записи: `derived` — порождены
// из аннотаций контрактов, `authored` — написаны человеком, потому что
// аннотаций у ресурса нет вовсе. У авторского ресурса записи каталога нет BY
// CONSTRUCTION (его глаголы живут на внутреннем слушателе, якоря области его
// тип не несут), поэтому требовать от него пары значило бы требовать того,
// чего не бывает. Записи вне популяции НАЗЫВАЮТСЯ числом, а не отбрасываются
// молча: иначе «ноль несопоставленных» стало бы неотличимо от «ноль
// осмотренных».

var (
	// ErrActionUnknownToCatalog — действие раздела не имеет записи каталога.
	ErrActionUnknownToCatalog = errors.New(
		"roleexport: действие манифеста не имеет записи в каталоге прав")
	// ErrActionMissingFromManifest — гейт записи каталога спрашивает отношение
	// ресурса, которого не порождает ни одно объявленное действие: право на
	// него выдать нечем ни действием, ни ярусом области.
	//
	// НЕ «запись без одноимённого действия»: таких на дереве 127, и все они
	// имеют счёт (едут на объявленном отношении · гейтятся ярусом · без гейта).
	ErrActionMissingFromManifest = errors.New(
		"roleexport: гейт спрашивает отношение, которого не порождает ни одно действие манифеста")
	// ErrActionPlaneDisagrees — манифест и каталог расходятся о ПЛОСКОСТИ
	// исполнения действия. Два объявления одного предмета, из которых верно
	// одно; молчаливое расхождение здесь означает право, выданное арендатору на
	// внутреннюю поверхность либо наоборот.
	ErrActionPlaneDisagrees = errors.New(
		"roleexport: манифест и каталог расходятся о плоскости исполнения действия")
)

// LinkageFinding — находка сверки. Единица здесь — ДЕЙСТВИЕ, а не правило роли
// и не класс, поэтому у находки свой тип: `Finding` несёт роль, `ClassFinding` —
// класс, и втискивание третьего предмета в чужую структуру заставило бы
// вызывающего гадать, какие поля этой находки осмысленны.
type LinkageFinding struct {
	// Kind — вид находки; сравнивается через errors.Is.
	Kind error
	// Module, Resource, Verb — координаты действия в написании манифеста.
	Module   string
	Resource string
	Verb     string
	// FQN — запись каталога, когда она есть. Пуста у действия, записи не
	// имеющего: называть несуществующую координату нечем.
	FQN string
	// Detail — отказ целиком: что не сошлось, почему это важно и чем чинится.
	Detail string
}

func (f LinkageFinding) Error() string { return f.Detail }

// Unwrap отдаёт вид находки, чтобы errors.Is отвечал по сентинелу.
func (f LinkageFinding) Unwrap() error { return f.Kind }

// ActionLinkageCensus — объём, осмотренный сверкой.
//
// Величин десять, и печатаются они порознь: сумма скрыла бы перенос действия из
// одного состояния в другое, а именно перенос здесь и интересен.
type ActionLinkageCensus struct {
	// ResourcesDerived — записей раздела с ключами, порождёнными аннотациями.
	ResourcesDerived int
	// ResourcesAuthored — авторских записей: пары у них нет by construction.
	ResourcesAuthored int
	// ManifestVerbs — действий порождённых ресурсов осмотрено.
	ManifestVerbs int
	// CatalogActions — записей каталога, привязанных к порождённым ресурсам
	// ЭТОГО модуля.
	CatalogActions int
	// Matched — сопоставлено парой.
	Matched int
	// WithoutCatalogEntry — действий манифеста без записи каталога.
	WithoutCatalogEntry int
	// WithoutManifestVerb — записей каталога БЕЗ СЧЁТА: гейт спрашивает
	// отношение `v_*`, которого не порождает ни одно объявленное действие
	// ресурса. Право на такой гейт выдать нечем — это находка.
	WithoutManifestVerb int
	// RidesDeclaredRelation — записей, которых раздел не называет действием и
	// которые едут на отношении УЖЕ объявленного: `AddCidrBlocks`,
	// `RemoveCidrBlocks` и `Update` все три гейтятся `v_update`. Назвать такую
	// запись действием НЕЛЬЗЯ — она породила бы `define v_addcidrblocks` сверх
	// канона, и побайтовая сверка модели её отвергла бы.
	RidesDeclaredRelation int
	// GatedAtScopeTier — записей, чей гейт спрашивает ЯРУС ОБЛАСТИ (`editor` на
	// `project`, `system_admin` на `cluster`), а не отношение ресурса. Такое
	// право выдаёт ярусная роль платформы, а не действие раздела.
	GatedAtScopeTier int
	// UnnamedExempt — записей без гейта вовсе (`required_relation` пуст): их
	// получает всякий аутентифицированный, и действием они не выдаются.
	UnnamedExempt int
	// OutsidePopulation — записей каталога этого модуля, чей ресурс раздел не
	// объявляет вовсе либо объявляет авторским. Не находка, но и не ноль.
	OutsidePopulation int
	// PlaneDisagrees — пар, разошедшихся о плоскости исполнения.
	PlaneDisagrees int
}

// Summary — перепись строкой. Печатается ВСЕГДА: молчание сверки, не
// прочитавшей ни одного действия, неотличимо от молчания сверившей все.
func (c ActionLinkageCensus) Summary() string {
	return fmt.Sprintf(
		"ресурсов порождённых %d · авторских %d · действий манифеста %d · "+
			"записей каталога %d · сопоставлено %d · без записи каталога %d · "+
			"едет на объявленном отношении %d · гейтится ярусом области %d · "+
			"без гейта вовсе %d · БЕЗ СЧЁТА %d · вне популяции %d · "+
			"расхождений плоскости %d",
		c.ResourcesDerived, c.ResourcesAuthored, c.ManifestVerbs, c.CatalogActions,
		c.Matched, c.WithoutCatalogEntry, c.RidesDeclaredRelation,
		c.GatedAtScopeTier, c.UnnamedExempt, c.WithoutManifestVerb,
		c.OutsidePopulation, c.PlaneDisagrees)
}

// verbRelationPrefix — приставка отношения, порождаемого действием.
//
// ВЫВЕДЕНА из единственного объявления правила (`manifest.VerbRelationName`), а
// не написана литералом: литерал здесь был бы вторым объявлением одного
// предмета, и разошёлся бы он молча — обе стороны отвечают одинаково ровно до
// той правки, которая приставку меняет.
var verbRelationPrefix = manifest.VerbRelationName("")

// CheckActionLinkage сверяет действия раздела `resources` с записями каталога
// прав В ОБЕ СТОРОНЫ и возвращает ВСЕ находки.
//
// Все, а не первую: названная первая заставила бы автора чинить их по одной, по
// прогону на каждую, и скрыла бы, сколько их всего.
func CheckActionLinkage(m *manifest.Manifest, actions []Action) ([]error, ActionLinkageCensus) {
	var census ActionLinkageCensus
	if m == nil {
		return nil, census
	}

	// Порождённые ресурсы модуля и их действия, по написанию манифеста.
	derived := map[string]*manifest.Resource{}
	for i := range m.Resources {
		r := &m.Resources[i]
		if r.Producer == "authored" {
			census.ResourcesAuthored++
			continue
		}
		census.ResourcesDerived++
		derived[r.Name] = r
	}

	// Сторона каталога: только действия ЭТОГО модуля и только порождённых
	// ресурсов. Чужой модуль здесь не судится — его раздел объявляет он сам.
	catalogOf := map[string]Action{}
	for _, a := range actions {
		if a.Module != m.Module {
			continue
		}
		if _, ok := derived[a.Resource]; !ok {
			census.OutsidePopulation++
			continue
		}
		census.CatalogActions++
		catalogOf[a.Resource+"."+a.Verb] = a
	}

	var faults []error
	seen := map[string]bool{}

	// Отношения, которые ПОРОЖДАЮТ объявленные действия ресурса. Имя строит
	// `manifest.VerbRelationName` — единственное объявление правила; второе,
	// написанное здесь «по образцу», разошлось бы с первым молча ровно на
	// действии, чьё имя не в нижнем регистре (`addTargets` → `v_addtargets`).
	renderedOf := map[string]map[string]bool{}
	for name, r := range derived {
		set := make(map[string]bool, len(r.Verbs))
		for _, v := range r.Verbs {
			set[manifest.VerbRelationName(v.Name)] = true
		}
		renderedOf[name] = set
	}

	// Порядок обхода — порядок документа: отказ на одном и том же манифесте
	// читается одинаково от прогона к прогону.
	for i := range m.Resources {
		r := &m.Resources[i]
		if r.Producer == "authored" {
			continue
		}
		for _, v := range r.Verbs {
			census.ManifestVerbs++
			key := r.Name + "." + v.Name
			seen[key] = true
			a, ok := catalogOf[key]
			if !ok {
				census.WithoutCatalogEntry++
				faults = append(faults, LinkageFinding{
					Kind: ErrActionUnknownToCatalog, Module: m.Module, Resource: r.Name,
					Verb: v.Name,
					Detail: fmt.Sprintf(
						"ресурс %q модуля %q: каталог прав не знает действия %q — право, "+
							"выданное на него, не спрашивает НИ ОДИН гейт, и выдача выглядит "+
							"действующей, ничего не давая. Каталог называет действие по методу "+
							"службы: `<Служба>/<Метод>`, приставка `internal` добавляется к "+
							"имени метода как есть (`InternalNetworkService/GetNetwork` → "+
							"`internalGetNetwork`, не `internalGet`)%s",
						r.Name, m.Module, v.Name, nearestHint(catalogOf, r.Name, v.Name)),
				})
				continue
			}
			census.Matched++
			if v.Internal != a.Internal {
				census.PlaneDisagrees++
				faults = append(faults, LinkageFinding{
					Kind: ErrActionPlaneDisagrees, Module: m.Module, Resource: r.Name,
					Verb: v.Name, FQN: a.FQN,
					Detail: fmt.Sprintf(
						"ресурс %q модуля %q, действие %q: манифест объявляет плоскость "+
							"%s, каталог — %s (%s). Два объявления одного предмета, из которых "+
							"верно одно: признак порождается из аннотаций, и расходиться с "+
							"записью каталога он не вправе",
						r.Name, m.Module, v.Name, planeName(v.Internal), planeName(a.Internal), a.FQN),
				})
			}
		}
	}

	// Обратная сторона. Без неё соединение объявлялось бы полным, имея
	// половину: гейт, которого раздел не описывает, остался бы вне наблюдения.
	//
	// Запись, которую раздел не называет действием, ОТНОСИТСЯ к своему
	// состоянию, а не отвергается оптом. Оптовый отказ был бы неверен на
	// настоящем дереве ЦЕЛИКОМ — 127 записей из 127, — и неверен по существу:
	// он утверждает «выдать право на него нечем» там, где право выдаётся
	// объявленным действием (`AddCidrBlocks` гейтится `v_update`, а `update`
	// объявлен) либо ярусом области (`Create` гейтится `editor` на `project`).
	//
	// Требовать действия на КАЖДУЮ запись нельзя и by construction: действие
	// рендерится в `define v_<действие>`, поэтому названный `addCidrBlocks`
	// породил бы `define v_addcidrblocks`, которого в каноне нет, — и побайтовая
	// сверка модели (`make -C services/iam model-canon-check`) отвергла бы его.
	// Две проверки одного дерева не вправе требовать несовместимого.
	keys := make([]string, 0, len(catalogOf))
	for k := range catalogOf {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if seen[k] {
			continue
		}
		a := catalogOf[k]
		switch {
		case a.Exempt():
			// Гейта нет вовсе: действие получает всякий аутентифицированный, а
			// не участник роли. Правом оно не выдаётся ни при каком разделе.
			census.UnnamedExempt++
		case !strings.HasPrefix(a.Relation, verbRelationPrefix):
			// Гейт спрашивает ЯРУС ОБЛАСТИ (`editor` на `project`,
			// `system_admin` на `cluster`), а не отношение ресурса. Кортеж на
			// область пишет ярусная роль платформы; раздел модуля к этому
			// отношения не имеет.
			census.GatedAtScopeTier++
		case renderedOf[a.Resource][a.Relation]:
			// Едет на отношении УЖЕ объявленного действия: право выдаётся, и
			// второго объявления ему не нужно.
			census.RidesDeclaredRelation++
		default:
			// ЕДИНСТВЕННЫЙ вид находки обратной стороны: гейт спрашивает
			// отношение ресурса, которого не порождает ни одно объявленное
			// действие. Право на него выдать НЕЧЕМ — ни действием, ни ярусом.
			census.WithoutManifestVerb++
			faults = append(faults, LinkageFinding{
				Kind: ErrActionMissingFromManifest, Module: m.Module, Resource: a.Resource,
				Verb: a.Verb, FQN: a.FQN,
				Detail: fmt.Sprintf(
					"ресурс %q модуля %q: каталог несёт действие %q (%s), гейт которого "+
						"спрашивает отношение %q, а раздел `resources` не объявляет НИ ОДНОГО "+
						"действия, порождающего %q — право на этот гейт выдать нечем ни "+
						"действием, ни ярусом области, и отсутствие видно только отсюда: ни "+
						"одна проверка формы такого пропуска не заметит",
					a.Resource, m.Module, a.Verb, a.FQN, a.Relation, a.Relation),
			})
		}
	}
	return faults, census
}

// planeName — плоскость исполнения словом. Признак булев, а «true/false» в
// отказе заставил бы читателя вспоминать, что из них внутреннее.
func planeName(internal bool) string {
	if internal {
		return "внутреннюю"
	}
	return "внешнюю"
}

// nearestHint — подсказка о действии того же ресурса, отличающемся ТОЛЬКО
// приставкой плоскости.
//
// Заведена ради самой частой ошибки написания: черновик пишет `internalGet`
// там, где каталог называет `internalGetNetwork`. Отказ, называющий предмет и
// молчащий о соседе, отправляет читателя сверять перечень вручную.
func nearestHint(catalogOf map[string]Action, resource, verb string) string {
	prefix := resource + "."
	var near []string
	for key := range catalogOf {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		candidate := strings.TrimPrefix(key, prefix)
		if strings.HasPrefix(candidate, verb) || strings.HasPrefix(verb, candidate) {
			near = append(near, candidate)
		}
	}
	if len(near) == 0 {
		return ""
	}
	sort.Strings(near)
	return fmt.Sprintf("; каталог того же ресурса несёт близкое: %s", strings.Join(near, ", "))
}
