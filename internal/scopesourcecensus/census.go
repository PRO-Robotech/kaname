// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package scopesourcecensus строит ЗАПРОС переписи источников звена цепи
// областей — по типам, ВЫВЕДЕННЫМ из дерева, а не выписанным рядом.
//
// # Зачем генератор, а не запрос в теле скрипта
//
// Перепись обязана высказаться о КАЖДОМ типе, чей структурный предок выводим из
// строки iam, — включая тип, у которого сегодня ноль объектов с обеих сторон.
// Прежняя редакция строила перепись полным внешним соединением с группировкой,
// поэтому тип с нулями в вывод не попадал ВОВСЕ: «о нём не сказано» было
// неотличимо от «у него всё хорошо». Единственный цикл при этом шёл по списку
// послаблений оператора, а не по каталогу типов, — то есть перечень типов
// задавал тот, кто прощает расхождения.
//
// Здесь перечень берётся у владельца — `authzcascade.DerivableTypes`, — а
// предикат «у этого объекта источник предка законно пуст» у второго владельца —
// плана чтения материализации (`pg.IAMDirectContainments`). Выписанный перечень
// не сдвинулся бы от нового типа и продолжал бы сторожить прежние; выписанный
// предикат стал бы третьим местом об одном предмете.
//
// # Единица счёта — ОБЪЕКТ, а не строка журнала
//
// У объекта бывает несколько указателей (у проекта их два — аккаунт и кластер),
// и счёт строк завысил бы стороны по-разному. Так же считает и вопрос о
// доступе: цепь поднимается по объектам.
//
// # Категорий исхода ПЯТЬ, и три из них — не находки
//
// Прежняя перепись знала две («потеряно» и «лишних») и потому обязана была
// назвать находкой всё, что в них не помещалось. Категории:
//
//	в цепи        — у строки есть звено. Норма;
//	без предка    — у строки звена нет И источник предка законно пуст:
//	                системная роль (ни аккаунта, ни проекта — и она НЕ ДОЛЖНА
//	                становиться достижимой ни из одного аккаунта), привязка с
//	                областью вне закрытого набора, учётка с пустым аккаунтом.
//	                НЕ находка: посчитать их потерями значит показать предмет
//	                хуже, чем он есть, и следующий читатель начнёт «чинить»
//	                законное;
//	потеряно      — у строки звена нет, А ИСТОЧНИК ПРЕДКА НАЗЫВАЕТ. Находка
//	                всегда: форма отказывает там, где решатель разрешает, и
//	                отказ неотличим от честного;
//	лишних        — звено есть, а предка не называет НИ источник, НИ журнал.
//	                Обратная полярность: форма разрешает там, где решатель
//	                отказывает. Тише первой и потому опаснее;
//	нет строки    — объект назван журналом либо цепью, а СТРОКИ У НЕГО НЕТ.
//	                Отдельная категория, а не потеря цепи: идентификатор объекта
//	                И ЕСТЬ первичный ключ строки, поэтому объекта без строки не
//	                существует, и «цепь не дала ему предка» — верный ответ, а не
//	                пропуск. Это предмет #782 (объекты, живущие в графе прав и
//	                отсутствующие в собственной таблице), и он ПЕЧАТАЕТСЯ с
//	                атрибуцией, а не растворяется ни в находках, ни в тишине.
//
// # Почему «нет строки» не прощается послаблением, а выносится категорией
//
// Послабление прощает РАСХОЖДЕНИЕ, у которого есть предмет, и обязано истекать
// вместе с ним. У этой категории предмет чужой и живёт своей задачей; прощать её
// как расхождение значило бы завести запись, снять которую нельзя ничем, что
// делает эта под-фаза, — то есть бессрочное послабление под видом срочного.
package scopesourcecensus

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho-iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// TypePlan — что перепись знает об одном типе, и откуда.
type TypePlan struct {
	// ModelType — имя типа в словаре МОДЕЛИ (`iam_group`): им названы
	// `relation_fact.object_type` и `resource_scope_edge.object_type`.
	ModelType string
	// CatalogType — то же имя в словаре КАТАЛОГА (`iam.group`): им назван план
	// чтения материализации. Хранится рядом, чтобы перевод был виден, а не
	// подразумевался.
	CatalogType string
	// Table, Join, ParentExpr — план чтения материализации. ParentExpr —
	// СКЛЕЙКА обоих её выражений: источник считается называющим предка, если
	// непусто хотя бы одно.
	Table      string
	Join       string
	ParentExpr string
}

// parentExprOverride — типы, у которых «источник называет предка» спрашивается
// НЕ у плана чтения материализации.
//
// ПОЧЕМУ ПЕРЕОПРЕДЕЛЕНИЕ, А НЕ ПРАВКА МАТЕРИАЛИЗАЦИИ. План чтения отвечает на
// вопрос «что содержит объект» и у привязки с областью «кластер» предка НЕ ДАЁТ
// НАМЕРЕННО — оба его выражения на такой строке пусты, и его собственный
// комментарий это оговаривает. Цепь областей предка такой привязке ДАЁТ, и
// модель на её стороне: у типа объявлены все три области. Расхождение законно и
// ведётся поимённо (legalDifferences в scopeedgesource_gate_test.go).
//
// Перепись, спрашивавшая план чтения, объявляла такую строку «лишней» — то есть
// красила ВЕРНУЮ реализацию. Пока в дереве не было ни одной привязки с областью
// «кластер», нуль получался не от свойства, а от пустоты этого класса: первая же
// такая строка сделала бы инструмент постоянным ложным сигналом — и на прогоне,
// и на стенде, где та же перепись гоняется скриптом.
//
// НАБОР ОБЛАСТЕЙ БЕРЁТСЯ У ВЛАДЕЛЬЦА (domain.BindableScopes), а не выписывается
// здесь: тот же набор решает, будет ли у привязки звено, и второй его копии
// заводить нельзя — она разошлась бы молча ровно там, где расхождение и опасно.
func parentExprOverride(catalogType string) (string, bool) {
	if catalogType != "iam.accessBinding" {
		return "", false
	}
	scopes := domain.BindableScopes()
	quoted := make([]string, 0, len(scopes))
	for _, s := range scopes {
		quoted = append(quoted, "'"+s+"'")
	}
	return "(o.resource_type IN (" + strings.Join(quoted, ", ") + "))", true
}

// Plans выводит план переписи: по одной записи на КАЖДЫЙ выводимый тип.
//
// Возвращает ошибку, если у выводимого типа нет плана чтения материализации:
// это не «пропустить тип», а расхождение двух перечней, которое обязано быть
// названо — иначе перепись молча перестанет высказываться о типе, чей предок
// объявлен выводимым.
func Plans() ([]TypePlan, error) {
	byCatalog := map[string]pg.IAMDirectContainment{}
	for _, c := range pg.IAMDirectContainments() {
		byCatalog[c.ObjectType] = c
	}

	modelTypes := make([]string, 0, len(authzcascade.DerivableTypes))
	for ty := range authzcascade.DerivableTypes {
		modelTypes = append(modelTypes, ty)
	}
	sort.Strings(modelTypes)

	out := make([]TypePlan, 0, len(modelTypes))
	var missing []string
	for _, modelType := range modelTypes {
		catalogType := authzmap.CatalogTypeName(modelType)
		c, ok := byCatalog[catalogType]
		if !ok {
			missing = append(missing, modelType+" ("+catalogType+")")
			continue
		}
		// Аккаунт спрашивается НЕПУСТОТОЙ НАБОРА, а не непустотой скаляра: у
		// личности он не свойство строки, а связь, и скалярной формы у неё нет
		// вовсе (#1172). Спрашивать «колонка непуста» значило бы для личности
		// подставить в SQL пустую строку и получить синтаксический отказ, а до
		// #1172 — числа, снятые с колонки, которую цепь областей уже не читает.
		parentExpr := "(COALESCE(array_length(" + c.ParentAccountsExpr + ", 1), 0) > 0 OR COALESCE(" +
			c.ParentProjectExpr + ", '') <> '')"
		if override, ok := parentExprOverride(catalogType); ok {
			parentExpr = override
		}
		out = append(out, TypePlan{
			ModelType:   modelType,
			CatalogType: catalogType,
			Table:       c.Table,
			Join:        c.Join,
			ParentExpr:  parentExpr,
		})
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf(
			"у выводимых типов нет плана чтения материализации: %s.\n"+
				"Перечни разошлись: authzcascade.DerivableTypes объявляет предка выводимым, а "+
				"pg.IAMDirectContainments не знает, из какой колонки его брать. Перепись обязана "+
				"назвать это, а не промолчать о типе",
			strings.Join(missing, ", "))
	}
	return out, nil
}

// SQL строит запрос переписи: по строке на тип, ВСЕГДА — включая тип с нулями с
// обеих сторон.
//
// Идентификаторы подставляются из ЗАКРЫТЫХ перечней дерева (имя таблицы и
// выражения — литералы плана чтения, имя типа — ключ карты выводимых), снаружи
// сюда не приходит ничего, поэтому подстановка безопасна.
func SQL() (string, error) {
	plans, err := Plans()
	if err != nil {
		return "", err
	}
	arms := make([]string, 0, len(plans))
	for _, p := range plans {
		arms = append(arms, arm(p))
	}
	return strings.Join(arms, "\nUNION ALL\n") + "\n ORDER BY 1;", nil
}

// pointerFacts — прямые факты журнала, являющиеся УКАЗАТЕЛЯМИ на предка.
//
// Дискриминатор СТРУКТУРНЫЙ, а не списочный: отношение НАЗЫВАЕТ ТИП своего
// субъекта (`project --account--> account:acc-1`). Прямые факты, указателями не
// являющиеся (`owner`, `admin`, `system_admin`), его не удовлетворяют — их
// субъект человек или служебная учётка, а не предок. Перечня пар здесь нет
// намеренно: список был бы вторым местом об одном предмете и разошёлся бы с
// моделью прав молча, при заведении первого же нового звена.
//
// Субъект-userset (`group:grp-1#member`) объектом не является и предком быть не
// может.
const pointerFacts = `
    SELECT DISTINCT object_type, object_id
      FROM kacho_iam.relation_fact
     WHERE relation = split_part(subject, ':', 1)
       AND position('#' in subject) = 0`

func arm(p TypePlan) string {
	ty := "'" + p.ModelType + "'"
	from := p.Table + " o"
	if p.Join != "" {
		from += " " + p.Join
	}
	// noEdge — у строки нет ни одного звена в цепи.
	noEdge := `NOT EXISTS (SELECT 1 FROM kacho_iam.resource_scope_edge e
                    WHERE e.object_type = ` + ty + ` AND e.object_id = o.id)`
	hasRow := `EXISTS (SELECT 1 FROM ` + p.Table + ` r WHERE r.id = x.object_id)`

	return `  SELECT ` + ty + `::text AS ty,
         (SELECT count(*) FROM ` + from + `) AS rows_total,
         (SELECT count(*) FROM ` + from + ` WHERE NOT (` + noEdge + `)) AS in_chain,
         (SELECT count(*) FROM ` + from + ` WHERE ` + noEdge + ` AND NOT ` + p.ParentExpr + `) AS no_parent_ok,
         (SELECT count(*) FROM ` + from + ` WHERE ` + noEdge + ` AND ` + p.ParentExpr + `) AS lost,
         (SELECT count(*) FROM (SELECT DISTINCT object_id FROM kacho_iam.resource_scope_edge
                                 WHERE object_type = ` + ty + `) x
            WHERE ` + hasRow + `
              AND NOT EXISTS (SELECT 1 FROM (` + pointerFacts + `) j
                               WHERE j.object_type = ` + ty + ` AND j.object_id = x.object_id)
              AND NOT EXISTS (SELECT 1 FROM ` + from + ` WHERE o.id = x.object_id AND ` + p.ParentExpr + `)
         ) AS extra,
         (SELECT count(*) FROM (
                  SELECT object_id FROM kacho_iam.resource_scope_edge WHERE object_type = ` + ty + `
                  UNION
                  SELECT object_id FROM (` + pointerFacts + `) j WHERE j.object_type = ` + ty + `) x
            WHERE NOT ` + hasRow + `
         ) AS no_row`
}
