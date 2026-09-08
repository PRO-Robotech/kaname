// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modulecatalog

// rows.go — ДЕРИВАЦИЯ «манифест → строки каталога модуля».
//
// # Что здесь объявлено, а что выведено
//
// Объявлены модуль оболочки, имена ресурсов (`resources[].name` дословно) и имена
// действий (`resources[].verbs[].name`). Выведены точечная форма ресурса,
// каноническое написание действия и ярусные строки.
//
// # Каноническое написание действия — НЕ косметика, оно требуется схемой
//
// `catalog_verb` несёт `CHECK (verb = lower(btrim(verb)))`, потому что глагол
// каталога — тот же токен, каким говорит `role_verb.verb`, а отношение модели
// прав пишется `v_<токен>` строчными. Манифест же пишет действие тем словом,
// каким его называет суффикс REST-пути (`addTargets`), — и это ПРАВИЛЬНО: там оно
// адресует метод, а не отношение.
//
// Значит словаря два, и переход между ними ОДИН — здесь. Замер по шести
// доставляемым манифестам: расходятся ровно два действия
// (`loadbalancer.targetGroups.addTargets` / `removeTargets`), обе — верблюжьи в
// манифесте и строчные в каталоге; остальные 107 совпадают как есть.
//
// # Приведение НЕ имеет права схлопывать два действия в одно
//
// `addTargets` и `addtargets` каноничны одинаково. Схлопнув их молча, деривация
// потеряла бы одно объявленное действие и записала бы каталог, которого манифест
// не объявлял. Поэтому столкновение токенов — ОТКАЗ, а не выбор победителя.
// Сегодня столкновений ноль, и это утверждает проба, а не эта строка.
//
// # Ярусная строка не объявляется манифестом и не может им объявляться
//
// Класс `create` пообъектного отношения не имеет by construction: в момент
// решения объекта ещё нет, и вопрос задают родителю. Каталог тем не менее обязан
// нести строку — иначе правило, называющее `create`, не резолвится ничем. Набор
// таких классов объявлен ОДИН раз (`authzmap.TierOnlyVerbClasses`), и здесь он
// ЗОВЁТСЯ: второй перечень разошёлся бы с первым молча.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

var (
	// ErrVerbTokenCollision — два объявленных действия одного ресурса дают один
	// канонический токен. Отдельный отказ: чинится он правкой манифеста, а не
	// состоянием базы, и приходит ДО писателя.
	ErrVerbTokenCollision = errors.New("modulecatalog: two declared verbs share one canonical token")
	// ErrVerbNameEmpty — действие объявлено пустым именем. Загрузчик такое
	// отвергает, но деривация обязана быть годной и на манифесте, собранном в
	// памяти: молча выброшенное действие есть каталог, которого никто не объявлял.
	ErrVerbNameEmpty = errors.New("modulecatalog: declared verb has an empty canonical token")
	// ErrResourceNameEmpty — ресурс объявлен пустым именем, по той же причине.
	ErrResourceNameEmpty = errors.New("modulecatalog: declared resource has an empty name")
	// ErrObjectTypeEmpty — ресурс не назвал типа модели прав. Загрузчик такое
	// отвергает (`manifest.ErrObjectTypeRequired`), и деривация обязана быть
	// годной по той же причине, что и у двух отказов выше: на манифесте,
	// собранном В ПАМЯТИ, загрузчика нет by construction.
	//
	// Без него безымянный ресурс доехал бы до писателя и отвергся бы схемой —
	// то есть отказ пришёл бы ЧУЖОЙ полосой, фразой Postgres про имя
	// ограничения, и автор манифеста искал бы дефект в базе, а не в своём файле.
	ErrObjectTypeEmpty = errors.New("modulecatalog: declared resource has an empty objectType")
)

// Declared — каталог ОДНОГО модуля, выведенный из его манифеста.
//
// Форма — та же `catalog.Rows`-словарём, что у живого множества, и это не
// совпадение: обе стороны применения обязаны быть выражены одинаково, иначе
// сравнение начинает зависеть от того, кто как разложил свою сторону.
type Declared struct {
	// Module — модуль оболочки манифеста. Один: применитель применяет один
	// манифест, а не сводит несколько.
	Module string
	// Resources — грантуемые пары в порядке точечного ключа.
	Resources []catalog.ResourceRow
	// Verbs — пары «ресурс × действие» ОБЕИХ половин словаря: сначала
	// пообъектные ресурса (отсортированно), затем ярусные.
	Verbs []catalog.VerbRow
	// InternalExcluded — действий ВНУТРЕННЕЙ плоскости, не давших строки.
	//
	// Число печатается рядом с выведенным, а не подразумевается: без него
	// «расхождений с литералом ноль» неотличимо от «исключено всё, сравнивать
	// было нечего». Исключение объявлено доводом (см. RowsOf), и величина его
	// наблюдаема.
	InternalExcluded int
}

// RowsOf выводит строки каталога из манифеста домена.
//
// Порядок детерминирован (ресурсы по имени, действия внутри ресурса по токену):
// применитель кладёт строки в этом порядке, поэтому недетерминированный вход дал
// бы недетерминированный порядок операторов и сделал бы отказ на конкурентном
// применении зависящим от прогона.
func RowsOf(m *manifest.Manifest) (Declared, error) {
	out := Declared{Module: m.Module}

	resources := make([]manifest.Resource, len(m.Resources))
	copy(resources, m.Resources)
	sort.Slice(resources, func(i, j int) bool { return resources[i].Name < resources[j].Name })

	tierOnly := authzmap.TierOnlyVerbClasses()

	for i := range resources {
		r := &resources[i]
		if strings.TrimSpace(r.Name) == "" {
			return Declared{}, fmt.Errorf("%w: модуль %s", ErrResourceNameEmpty, m.Module)
		}
		if strings.TrimSpace(r.ObjectType) == "" {
			return Declared{}, fmt.Errorf("%w: %s.%s", ErrObjectTypeEmpty, m.Module, r.Name)
		}
		// `objectType` переносится ДОСЛОВНО, а не выводится из имени: правило
		// вывода `<модуль>_<ресурс>` в дереве снято целиком, и манифест объявляет
		// имя типа сам (`manifest.Resource.ObjectType`, поле обязательное).
		// Потеряй деривация это поле — ресурс доехал бы до строки безымянным, и
		// читатель пропустил бы его молча при действующей на вид роли (#1816).
		out.Resources = append(out.Resources, catalog.ResourceRow{
			Module: m.Module, Resource: r.Name, ObjectType: r.ObjectType,
		})

		// declaredBy — токен → имя, каким его написал манифест. Нужен ИМЕННО для
		// отказа: без исходного написания столкновение читалось бы как «два
		// одинаковых действия», и автор искал бы дубликат, которого в файле нет.
		declaredBy := make(map[string]string, len(r.Verbs))
		tokens := make([]string, 0, len(r.Verbs))
		for _, v := range r.Verbs {
			// Действие, не порождающее отношения, строки каталога НЕ ДАЁТ, и
			// правило это объявлено один раз (manifest.VerbProducesRelation) —
			// здесь оно применяется, а не переписывается.
			//
			// ПОЧЕМУ ИМЕННО ЗДЕСЬ, А НЕ ИСКЛЮЧЕНИЕМ В СВЕРКЕ. Строка каталога
			// существует затем, чтобы правило роли, назвавшее действие,
			// РЕЗОЛВИЛОСЬ в отношение `v_<токен>`. У внутреннего действия
			// такого отношения нет: замер по каталогу прав (101 запись) не дал
			// ни одной, чей гейт спрашивал бы отношение, которое породило бы
			// только она. Значит строка обещала бы автору выдачу, которой не
			// будет, — ровно тот довод, по которому строк не даёт и тип с
			// НЕобъявленным набором действий (`authzmap.CatalogSeedVerbs`).
			//
			// Сверка «манифесты описывают тот же каталог, что литерал» после
			// этого сравнивает ПОЛНЫЕ множества и никаких исключений не знает:
			// обе стороны выводят одно и то же by construction.
			if !manifest.VerbProducesRelation(v) {
				out.InternalExcluded++
				continue
			}
			token := canonicalVerb(v.Name)
			if token == "" {
				return Declared{}, fmt.Errorf("%w: %s.%s", ErrVerbNameEmpty, m.Module, r.Name)
			}
			if prev, dup := declaredBy[token]; dup {
				return Declared{}, fmt.Errorf("%w: %s.%s: %q и %q дают %q",
					ErrVerbTokenCollision, m.Module, r.Name, prev, v.Name, token)
			}
			declaredBy[token] = v.Name
			tokens = append(tokens, token)
		}
		sort.Strings(tokens)
		for _, token := range tokens {
			out.Verbs = append(out.Verbs, catalog.VerbRow{
				Module: m.Module, Resource: r.Name, Verb: token, PerObject: true,
			})
		}

		// Ресурс, не объявивший ни одного действия, ярусных строк НЕ получает:
		// у него нет ни одного отношения `v_*`, правило на него не резолвится
		// ничем, и ярусная строка обещала бы автору выдачу, которой не будет.
		if len(tokens) == 0 {
			continue
		}
		for _, class := range tierOnly {
			// Тип, объявивший этот класс ПООБЪЕКТНО, второй строки не получает:
			// первичный ключ у тройки один, и вторая строка отвергалась бы схемой.
			if _, declared := declaredBy[class]; declared {
				continue
			}
			out.Verbs = append(out.Verbs, catalog.VerbRow{
				Module: m.Module, Resource: r.Name, Verb: class,
			})
		}
	}
	return out, nil
}

// canonicalVerb — переход из словаря МАНИФЕСТА в словарь КАТАЛОГА.
//
// Выражение то же, каким его выражает схема (`lower(btrim(verb))`), и записано
// оно здесь ровно один раз: второе место разошлось бы с первым молча — и
// разошлось бы там, где расхождение невидимо, потому что на 107 действиях из 109
// обе формы совпадают.
func canonicalVerb(name string) string { return strings.ToLower(strings.TrimSpace(name)) }
