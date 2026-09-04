// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package catalog

import (
	"fmt"
	"sort"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Facts — НЕИЗМЕНЯЕМЫЙ каталожный факт на один момент времени.
//
// Значение собирается один раз и после этого не правится: обновление снимка
// строит НОВОЕ значение и подменяет указатель. Поэтому вызывающий, взявший факт,
// держит согласованное множество до конца своего вычисления — половины
// обновления он не увидит ни при какой конкуренции.
type Facts struct {
	// verbsByFGAType — набор глаголов ЖИВОГО типа, в имени словаря МОДЕЛИ
	// (`vpc_network`), отсортированный. Ключ переведён здесь, один раз, а не у
	// каждого вызывающего: соединение колонок разных словарей не совпадает
	// никогда и молча.
	verbsByFGAType map[string][]string
	common         []string
	all            []string
	// modules — ЖИВЫЕ строки `catalog_module`, индекс членства. Хранится
	// отдельным набором, а не выводится из `verbsByFGAType`: приставка имени
	// типа МОДЕЛИ модулю не равна (`nlb_listener` против модуля
	// `loadbalancer`), и вывод оттуда дал бы третий словарь имени модуля.
	modules map[string]struct{}
	// moduleOrder — тот же набор в порядке чтения, для переписей и текстов
	// отказа. Копия отдаётся наружу, чтобы вызывающий не испортил снимок
	// сортировкой на месте.
	moduleOrder []string
	// fgaTypeByDotted — переходник «точечное имя каталога → имя типа МОДЕЛИ»,
	// собранный ИЗ ЖИВЫХ СТРОК.
	//
	// Раньше это спрашивалось у `authzmap.FGAObjectType`, то есть у словаря,
	// ПОРОЖДЁННОГО СБОРКОЙ. Направление СНЯТИЯ такой переходник закрывал (строка
	// исчезла — читатель её не видит), а направление ЗАВЕДЕНИЯ не закрывал ничем:
	// тип, которого сборка не знала, получал «не найдено», и строка пропускалась
	// МОЛЧА — при живом членстве модуля и роли, созданной без отказа (#1816,
	// IAM-CT-2-14).
	//
	// Вторым переходником это не является: соответствие здесь не вычисляется, а
	// читается из строки, куда его положил манифест модуля. Согласие с таблицей
	// сборки на посеянных строках держит страж старта.
	fgaTypeByDotted map[string]string
	// resources — ЖИВЫЕ пары каталога в порядке точечного ключа.
	//
	// Хранится перечнем, а не выводится из `fgaTypeByDotted` обходом карты:
	// обход карты в Go не упорядочен, а порядок здесь — часть контракта витрины
	// разрешений, которая эти пары показывает арендатору.
	//
	// Пара хранится РАЗОБРАННОЙ, хотя точечный ключ её и определяет: разбор по
	// первой точке — правило, знать которое есть работа сборщика факта, а не
	// каждого читателя. Второе место, знающее это правило, разошлось бы с первым
	// на ресурсе, чьё имя содержит точку.
	resources []ResourceEntry
}

// ResourceEntry — одна ЖИВАЯ пара каталога вместе с именем её типа в словаре
// МОДЕЛИ ПРАВ.
//
// Три величины отдаются ВМЕСТЕ намеренно. Имя типа не выводится из пары
// (правила `<модуль>_<ресурс>`, верного на всех строках, не существует — см.
// `ResourceRow.ObjectType`), поэтому читатель, получивший пару без имени, пошёл
// бы за ним к словарю, ПОРОЖДЁННОМУ СБОРКОЙ, — то есть ровно туда, откуда его
// уводит этот перечень.
type ResourceEntry struct {
	Module   string
	Resource string
	// ObjectType — имя типа в словаре МОДЕЛИ ПРАВ (`vpc_network`, `account`).
	ObjectType string
}

// NewFacts собирает факт из живых строк каталога.
//
// ПУСТОЕ МНОЖЕСТВО ОТВЕРГАЕТСЯ, и это не перестраховка. Пустой снимок отверг бы
// ВСЕ правила арендатора разом, и снаружи это читалось бы как «продукт сломан»,
// а не как «миграции не применены». На старте до этого не доходит — страж
// отказывает в пуске раньше, — но обновление снимка идёт БЕЗ стража, и пустой
// ответ там обязан быть отказом обновления, а не новым снимком.
func NewFacts(rows Rows) (*Facts, error) {
	if len(rows.Modules) == 0 || len(rows.Resources) == 0 || len(rows.Verbs) == 0 {
		return nil, fmt.Errorf("каталог модуля пуст: строк модулей/ресурсов/глаголов %d/%d/%d — "+
			"пустой снимок отверг бы ВСЕ правила разом, и это читалось бы как поломка продукта, "+
			"а не как непринятые миграции (kacho#1816, IAM-CT-2-02)",
			len(rows.Modules), len(rows.Resources), len(rows.Verbs))
	}

	modules := make(map[string]struct{}, len(rows.Modules))
	moduleOrder := make([]string, 0, len(rows.Modules))
	for _, m := range rows.Modules {
		if _, dup := modules[m]; dup {
			continue
		}
		modules[m] = struct{}{}
		moduleOrder = append(moduleOrder, m)
	}
	sort.Strings(moduleOrder)

	live := make(map[string]bool, len(rows.Resources))
	fgaTypeByDotted := make(map[string]string, len(rows.Resources))
	resources := make([]ResourceEntry, 0, len(rows.Resources))
	for _, r := range rows.Resources {
		dotted := r.Module + "." + r.Resource
		live[dotted] = true
		// Строка БЕЗ имени типа — ОТКАЗ, а не пропуск. Пропуск здесь и есть тот
		// дефект, ради снятия которого колонка заведена: ресурс существует,
		// членство модуля отвечает «да», роль создаётся без отказа — и проекция
		// по нему пуста, о чём не говорит ни одна полоса.
		//
		// Схема такой строки не производит (`object_type NOT NULL` плюс
		// грамматика), поэтому предмет отказа — читатель, собравший строки в
		// ПАМЯТИ: деривация манифеста и фикстуры. Там ключа нет by construction,
		// и молчание отличалось бы от исправной работы только числом пар, которое
		// никто не смотрит.
		if r.ObjectType == "" {
			return nil, fmt.Errorf("строка каталога %s не несёт имени типа модели прав: "+
				"проекция «роль → тип × глагол» по ней была бы ПУСТА при роли, созданной "+
				"без отказа, и ни одна полоса об этом не сказала бы (kacho#1816, IAM-CT-2-14)",
				dotted)
		}
		fgaTypeByDotted[dotted] = r.ObjectType
		resources = append(resources, ResourceEntry(r))
	}
	sort.Slice(resources, func(i, j int) bool {
		if resources[i].Module != resources[j].Module {
			return resources[i].Module < resources[j].Module
		}
		return resources[i].Resource < resources[j].Resource
	})

	byDotted := make(map[string][]string, len(rows.Resources))
	for _, v := range rows.Verbs {
		dotted := v.Module + "." + v.Resource
		// Глагол СНЯТОГО ресурса не считается. В базе согласие держит внешний
		// ключ, но читатель обязан быть верен и на строках, пришедших из будущей
		// формы снятия: ресурс без живой строки глаголов не объявляет.
		if !live[dotted] {
			continue
		}
		// ЯРУСНАЯ строка в набор типа НЕ ВХОДИТ, и это несущее место, а не
		// фильтр для порядка. Набор типа — то, по чему материализуются кортежи
		// (`GrantedVerbs` → `role_verb` → реконсайлер); пропустить сюда
		// авторский глагол без пообъектного отношения значило бы вернуть
		// `v_create`, снятый с 23 типов осознанно (#1863, замер снятия — в
		// `verb-create-withdrawal.md`).
		//
		// Строка при этом ОСТАЁТСЯ в `rows.Verbs` и остаётся живой: по ней
		// резолвится ключ объявления правила, и в этом смысл разделения — ключ
		// судит авторский словарь, набор типа остаётся пообъектным.
		if !v.PerObject {
			continue
		}
		byDotted[dotted] = append(byDotted[dotted], v.Verb)
	}

	f := &Facts{
		verbsByFGAType:  make(map[string][]string, len(byDotted)),
		modules:         modules,
		moduleOrder:     moduleOrder,
		fgaTypeByDotted: fgaTypeByDotted,
		resources:       resources,
	}
	for dotted, verbs := range byDotted {
		// Имя типа есть у КАЖДОЙ живой строки: строка без него отвергнута выше,
		// а глагол снятого ресурса отсеян отбором `live` до сюда. Значит промах
		// здесь невозможен by construction, и ветви «не нашлось» тут больше нет —
		// она объявляла бы состояние, которого не бывает.
		fgaType := fgaTypeByDotted[dotted]
		sort.Strings(verbs)
		f.verbsByFGAType[fgaType] = verbs
	}
	f.common, f.all = vocabularies(f.verbsByFGAType)
	return f, nil
}

// vocabularies — ПЕРЕСЕЧЕНИЕ и ОБЪЕДИНЕНИЕ наборов живых типов.
//
// Вопросы разные, и путать их нельзя: «что даёт ЛЮБОЙ ресурс» против «что бывает
// вообще». Первый спрашивает публичное поле каталога, второй — запасной набор
// для якоря без собственного (кластер). Пока наборы типов совпадали, обе
// величины были одним числом, и вызывающему, которому нужно «всё», доставалось
// пересечение — по совпадению, а не по существу.
func vocabularies(byType map[string][]string) (common, all []string) {
	var inter map[string]bool
	union := map[string]bool{}
	for _, set := range byType {
		if len(set) == 0 {
			continue
		}
		in := make(map[string]bool, len(set))
		for _, v := range set {
			in[v] = true
			union[v] = true
		}
		if inter == nil {
			inter = in
			continue
		}
		for v := range inter {
			if !in[v] {
				delete(inter, v)
			}
		}
	}
	common = make([]string, 0, len(inter))
	for v := range inter {
		common = append(common, v)
	}
	all = make([]string, 0, len(union))
	for v := range union {
		all = append(all, v)
	}
	sort.Strings(common)
	sort.Strings(all)
	return common, all
}

// IsKnownModule — членство модуля в ЖИВОМ каталоге. Реализует
// `domain.ModuleSet`: домен набора не знает и получает его отсюда.
//
// # Почему ответ берётся у снимка, а не у запроса к базе
//
// Каталог мал и меняется реже всего в схеме, а спрашивают его на горячем пути
// создания и правки роли. Запрос на каждом обращении оплачивался бы запросом
// арендатора. Отставание при этом ОГРАНИЧЕНО и НАЗВАНО — оно равно периоду
// обновления снимка, задаваемому профилем развёртывания (см. [Snapshot]), а не
// сроку жизни процесса: снятие модуля доезжает до пути запроса за один период,
// без перезапуска.
//
// Подстановочный знак `*` модулем НЕ является: строки с таким именем в каталоге
// нет и быть не может (`catalog_module_nonempty` плюс грамматика имени), а
// разрешает его политика правила, а не набор.
func (f *Facts) IsKnownModule(module string) bool {
	_, ok := f.modules[module]
	return ok
}

// Modules — ЖИВЫЕ модули каталога, отсортированно. Возвращается КОПИЯ: снимок
// вызывающему не принадлежит.
func (f *Facts) Modules() []string {
	out := make([]string, len(f.moduleOrder))
	copy(out, f.moduleOrder)
	return out
}

// FGAObjectType — имя типа МОДЕЛИ ПРАВ для точечного имени каталога
// («vpc.network» → «vpc_network»), по ЖИВЫМ строкам; ok=false у ресурса, чья
// строка снята либо которого в каталоге нет вовсе.
//
// Это тот же вопрос, что задавал `authzmap.FGAObjectType`, и та же закрытость:
// незнакомая пара обязана дать ok=false, а НЕ произвольный тип модели. Отличие
// одно и оно несущее — ИСТОЧНИК. Порождённая сборкой таблица закрывала
// направление СНЯТИЯ и не закрывала ЗАВЕДЕНИЕ: тип, которого сборка не знала,
// получал «не найдено», и вызывающий пропускал его молча при роли, созданной без
// отказа (#1816, IAM-CT-2-14).
//
// Вторым переходником это не является: соответствие не вычисляется, а читается
// из строки, куда его положил манифест модуля.
// Resources — ЖИВЫЕ пары каталога в порядке точечного ключа.
//
// Отдаётся КОПИЯ по той же причине, что и у `Modules`: перечень принадлежит
// неизменяемому факту, и сортировка на месте у вызывающего испортила бы снимок
// для всех остальных.
func (f *Facts) Resources() []ResourceEntry {
	out := make([]ResourceEntry, len(f.resources))
	copy(out, f.resources)
	return out
}

func (f *Facts) FGAObjectType(dotted string) (string, bool) {
	fgaType, ok := f.fgaTypeByDotted[dotted]
	return fgaType, ok
}

// VerbsOfType — ГЛАГОЛЫ, объявленные ЖИВЫМ типом, отсортированно; nil у типа,
// чья строка снята либо которого в каталоге нет вовсе (`cluster`).
//
// Возвращается КОПИЯ: значение снимка вызывающему не принадлежит, а испортить
// его он мог бы одной сортировкой на месте.
func (f *Facts) VerbsOfType(fgaType string) []string {
	set := f.verbsByFGAType[fgaType]
	if len(set) == 0 {
		return nil
	}
	out := make([]string, len(set))
	copy(out, set)
	return out
}

// CommonVerbVocabulary — глаголы, общие ДЛЯ ВСЕХ живых глагольных типов.
func (f *Facts) CommonVerbVocabulary() []string {
	out := make([]string, len(f.common))
	copy(out, f.common)
	return out
}

// AllVerbVocabulary — глаголы, которые объявляет ХОТЬ ОДИН живой глагольный тип.
func (f *Facts) AllVerbVocabulary() []string {
	out := make([]string, len(f.all))
	copy(out, f.all)
	return out
}

// GrantedVerbs — глаголы, которые правило с авторскими глаголами `authored` даёт
// НА ТИПЕ `fgaType`.
//
// Предикат ОДИН на обе стороны и живёт у владельца правила
// (`authzmap.GrantedVerbsWithDeclared`); отсюда приходит единственный факт,
// который зависит от каталога, — объявляет ли ЖИВОЙ тип набор глаголов вообще.
// Повторить вычисление здесь значило бы завести второе место об одном предмете:
// ровно так роль-администратор однажды давала движку всё, а проекции — ничего.
// RolePreviewLookup — резолв набора глаголов ПАРЫ каталога для превью роли
// (#1994).
//
// Пара переводится в имя типа МОДЕЛИ по ЖИВОЙ строке, и набор берётся у неё же.
// Прежде перевод делала таблица, ПОРОЖДЁННАЯ СБОРКОЙ: тип, заведённый применением
// манифеста в работающем процессе, она не резолвила, и вызывающий брал запасной
// набор — глаголы ВСЕЙ платформы.
//
// # Запасной набор ОСТАЁТСЯ, и он тут же
//
// Правило, не адресующее ни одного типа (форма `*.*` роли-суперпользователя),
// своего набора не имеет by construction: перечислить ресурсы подстановки домену
// нечем. Пустое превью читалось бы как «роль ничего не даёт», поэтому такая пара
// получает ОБЪЕДИНЕНИЕ наборов живых типов.
//
// Объединение, а НЕ пересечение: пересечение сужается, когда какой-нибудь тип
// снимает у себя глагол, — и роль `*.*` начинала бы обещать меньше, чем даёт, от
// правки, к ней не относящейся (наблюдалось при #1189).
//
// Оба ответа приходят из ОДНОГО факта: взяв набор типа отсюда, а запасной у
// другого источника, вызывающий получил бы превью, собранное из двух снимков.
func (f *Facts) RolePreviewLookup() domain.TypeVerbLookup {
	return domain.WithCommonFallback(
		func(module, resource string) ([]string, bool) {
			fgaType, ok := f.FGAObjectType(module + "." + resource)
			if !ok {
				return nil, false
			}
			verbs := f.VerbsOfType(fgaType)
			if len(verbs) == 0 {
				return nil, false
			}
			return verbs, true
		},
		f.AllVerbVocabulary(),
	)
}

func (f *Facts) GrantedVerbs(fgaType string, authored, typeVerbs []string) []string {
	return authzmap.GrantedVerbsWithDeclared(fgaType, len(f.verbsByFGAType[fgaType]) > 0,
		authored, typeVerbs)
}

// RoleVerbsFromSelectors — проекция «тип × глагол» из тех же селекторов,
// которыми роль материализуется, по ЖИВОМУ каталогу.
//
// Тип в проекции остаётся ТОЧЕЧНЫМ — тем же, каким он назван в селекторах и
// каким его читает вердикт (`role_verb.object_type`); набор глаголов
// спрашивается по имени МОДЕЛИ, поэтому перевод делается здесь ровно один раз.
//
// НАПРАВЛЕНИЙ ДВА, и оба обязаны быть верны по живым строкам:
//
//   - СНЯТИЕ: тип, чья строка снята, пар не даёт. Пара по снятому типу дошла бы
//     до внешнего ключа `role_verb_type_fk` и была бы им отвергнута, то есть
//     отказ пришёл бы ЧУЖОЙ полосой (IAM-CT-2-06);
//   - ЗАВЕДЕНИЕ: тип, заведённый применением манифеста в РАБОТАЮЩЕМ процессе,
//     пары даёт. Пока переходник спрашивался у таблицы, порождённой сборкой,
//     этого не было: незнакомый ей тип пропускался молча, и арендатор не получал
//     ничего при роли, созданной без отказа (IAM-CT-2-14).
//
// Порознь каждое направление выполнимо портом, который не производит пар
// НИКОГДА, — поэтому утверждаются оба.
func (f *Facts) RoleVerbsFromSelectors(selectors []domain.RuleSelector) []domain.RoleVerb {
	seen := make(map[domain.RoleVerb]bool)
	out := make([]domain.RoleVerb, 0, len(selectors))
	for _, sel := range selectors {
		for _, dotted := range sel.ObjectTypes {
			if dotted == "" {
				continue
			}
			fgaType, ok := f.FGAObjectType(dotted)
			if !ok {
				continue
			}
			for _, verb := range f.GrantedVerbs(fgaType, sel.Verbs, f.VerbsOfType(fgaType)) {
				pair := domain.RoleVerb{ObjectType: dotted, Verb: verb}
				if seen[pair] {
					continue
				}
				seen[pair] = true
				out = append(out, pair)
			}
		}
	}
	return out
}
