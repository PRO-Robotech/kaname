// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender

import (
	"errors"
	"strings"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// render.go — порождение блока типа из ресурса манифеста (Н-01 приёмки).
//
// # Что порождается, а что объявляется человеком
//
// Раздел `resources` неоднороден (см. шапку manifest/resources.go), и рендер
// наследует это различие дословно:
//
//	порождается    указатели · super_admin · ярусы · v_<глагол>
//	объявляется    notes[] (проза с якорем) · relations[] (текст определения —
//	               ДОСЛОВНО) вместе с их местом · cascade[] · источники яруса и
//	               действия
//
// Текст авторского отношения здесь НЕ разбирается: его грамматика принадлежит
// модели прав, и второй её разборщик разошёлся бы с первым МОЛЧА — на той самой
// форме, которой не знает.
//
// # Ярус выводится от ПРЕДЫДУЩЕГО яруса, а не от постоянной
//
// Замер по канону: у `vpc_gateway` цепочка `admin → super_admin`,
// `editor → admin`, `viewer → editor`; у `vpc_address_pool` ярусов ДВА, и цепочка
// та же со снятым звеном — `admin → super_admin`, `viewer → admin`. Постоянная
// «viewer от editor» породила бы у второго ссылку на ярус, которого у него нет.
//
// Цепочкой дело не исчерпывается: ярус вправе назвать СВОИ источники ключом
// `from`, и тогда они заменяют звено цепочки целиком. Замер: `account` несёт
// `or owner or super_admin`, `iam_user` — `or subject or editor`.
//
// # Каскад супер-доступа тоже приходит ИЗ МАНИФЕСТА
//
// Написаний каскада в каноне четыре сверх умолчания, и восемь модульных блоков
// несут не умолчание. Форма структурная (`cascade[]` — пары `<relation> from
// <parent>`), а не текстовая: разбор строки завёл бы второй разборщик грамматики
// модели прав.
//
// # Субъекты сужают ЯРУСЫ и не трогают глаголы — это замер, а не симметрия
//
// У `vpc_address_pool` ярусы несут `[user, service_account]`, а его же `v_get`
// несёт полный набор с `group#member`. Сузив заодно глаголы, рендер отнял бы
// живое право у групп — молча, при действующей на вид привязке.
var (
	// ErrObjectTypeEmpty — рендерить нечего: тип объекта не назван.
	ErrObjectTypeEmpty = errors.New("modelrender: resource objectType is empty")
	// ErrParentEmpty — указателей нет ни одного; указатель — первая строка блока,
	// и каскад супер-доступа выводится от его имени.
	ErrParentEmpty = errors.New("modelrender: resource has no parents")
)

// Умолчания состава субъектов и цепочки ярусов объявлены У ЗАГРУЗЧИКА и берутся
// оттуда: на них ссылается его проверка источников яруса, и вторая копия здесь
// разошлась бы с первой молча — обе стороны отвечают одинаково ровно там, где
// совпадают.
var (
	defaultSubjects = manifest.DefaultSubjects()
	defaultTiers    = manifest.DefaultTiers()
)

// Render порождает блок типа модели из ресурса манифеста.
//
// Возвращает байты единицы A: от строки `type X` до последнего перевода строки
// включительно, БЕЗ завершающей пустой строки — разделитель принадлежит файлу, а
// не блоку.
func Render(r manifest.Resource) ([]byte, error) {
	if r.ObjectType == "" {
		return nil, ErrObjectTypeEmpty
	}
	if len(r.Parents) == 0 {
		return nil, ErrParentEmpty
	}

	var b strings.Builder
	b.WriteString("type " + r.ObjectType + "\n")
	b.WriteString("  relations\n")

	// Примечание печатается ПЕРЕД своим якорем, поэтому строку отношения пишет
	// один вызов на всех: место прозы приходит из манифеста, и второй путь записи
	// строки разошёлся бы с первым молча — на том отношении, о котором не знает.
	notes := notesByAnchor(r)
	define := func(name, definition string) {
		for _, line := range noteLines(notes[name]) {
			b.WriteString("    " + line + "\n")
		}
		b.WriteString("    define " + name + ": " + definition + "\n")
	}

	// Указателей бывает больше одного, и порядок их — порядок манифеста: канон
	// ставит у `iam_access_binding` `project`, затем `account`, затем `cluster`, и
	// сортировка дала бы другой блок.
	for _, p := range r.Parents {
		define(p.Name, "["+p.Type+"]")
	}
	define(manifest.SuperAdminRelation(), cascadeOf(r))
	writeAuthoredRelations(r, "beforeTiers", define)

	subjects := r.Subjects
	if len(subjects) == 0 {
		subjects = defaultSubjects
	}
	tiers := r.Tiers
	if len(tiers) == 0 {
		tiers = make([]manifest.ResourceTier, 0, len(defaultTiers))
		for _, name := range defaultTiers {
			tiers = append(tiers, manifest.ResourceTier{Name: name})
		}
	}

	// Каждый следующий ярус выводится от ПРЕДЫДУЩЕГО, а первый — от super_admin;
	// ярус, назвавший свои источники, берёт их вместо цепочки. Замер: `account`
	// несёт `or owner or super_admin`, `iam_user` — `or subject or editor`, и
	// постоянная цепочка не даёт ни того, ни другого.
	previous := manifest.SuperAdminRelation()
	for _, tier := range tiers {
		sources := tier.From
		if len(sources) == 0 {
			sources = []string{previous}
		}
		define(tier.Name, "["+strings.Join(subjects, ", ")+"] or "+strings.Join(sources, " or "))
		previous = tier.Name
	}
	writeAuthoredRelations(r, "beforeVerbs", define)

	// Порядок глаголов задаёт КАНОН, а не манифест: перестановка ресурсов и
	// глаголов в YAML рендер не меняет (B-04). Субъекты здесь умолчательные —
	// сужение ключом `subjects` РЕСУРСА трогает ярусы и не трогает глаголы, —
	// а своим составом и своими источниками действие распоряжается САМО.
	for _, verb := range verbsInCanonOrder(r.Verbs) {
		// Плоскость решает, ПОРОЖДАЕТ ли действие отношение, и правило это
		// объявлено ОДИН раз (manifest.VerbProducesRelation) — здесь оно
		// применяется, а не переписывается. Внутреннее действие отношения не
		// порождает: его не спрашивает ни один гейт, а канон такой строки не
		// несёт, и побайтовая сверка отвергла бы её.
		if !manifest.VerbProducesRelation(verb) {
			continue
		}
		subjects := defaultSubjects
		sources := []string{manifest.SuperAdminRelation()}
		if len(verb.Subjects) > 0 {
			subjects = verb.Subjects
		}
		if len(verb.From) > 0 {
			sources = verb.From
		}
		define(manifest.VerbRelationName(verb.Name),
			"["+strings.Join(subjects, ", ")+"] or "+strings.Join(sources, " or "))
	}
	writeAuthoredRelations(r, "afterVerbs", define)

	return []byte(b.String()), nil
}

// writeAuthoredRelations — авторские отношения ОДНОГО места, в порядке манифеста.
//
// Отношение воспроизводится ДОСЛОВНО: грамматика определения принадлежит модели
// прав, и второй её разборщик разошёлся бы с первым молча.
//
// Место приходит из манифеста, а не задаётся телом этой функции: раскладок в
// каноне ТРИ (перед ярусами · после ярусов · после действий), и постоянная
// объявляла расхождением то, о чём никто не решал.
func writeAuthoredRelations(r manifest.Resource, place string, define func(name, definition string)) {
	for _, rel := range r.Relations {
		at := rel.Position
		if at == "" {
			at = manifest.DefaultRelationPosition()
		}
		if at != place {
			continue
		}
		define(rel.Name, rel.Definition)
	}
}

// cascadeOf — правая часть отношения супер-доступа.
//
// Умолчание — `super_admin from <первый указатель>`: так написаны 19 модульных
// блоков канона из 27. Остальные восемь несут иные написания, и они приходят из
// манифеста ключом `cascade`.
func cascadeOf(r manifest.Resource) string {
	terms := r.Cascade
	if len(terms) == 0 {
		terms = []manifest.CascadeTerm{{
			Relation: manifest.SuperAdminRelation(), From: r.Parents[0].Name,
		}}
	}
	parts := make([]string, 0, len(terms))
	for _, t := range terms {
		parts = append(parts, t.Relation+" from "+t.From)
	}
	return strings.Join(parts, " or ")
}

// notesByAnchor — примечания ресурса по имени отношения, перед которым они стоят.
// Якорь у каждого свой: два примечания на одном отвергает загрузчик, потому что
// порядок между ними ничем не задан.
func notesByAnchor(r manifest.Resource) map[string]string {
	if len(r.Notes) == 0 {
		return nil
	}
	out := make(map[string]string, len(r.Notes))
	for _, n := range r.Notes {
		out[n.Before] = n.Text
	}
	return out
}

// noteLines — строки примечания ДОСЛОВНО, без хвостовой пустой.
//
// Знак комментария принадлежит ТЕКСТУ, а не рендеру, и это замер: отступ у всех
// 634 строк прозы модульных блоков — четыре пробела, формы `#текст` без пробела
// нет ни одной, голых решёток 76. Значит рендер строки есть чистое склеивание
// `"    " + строка`, и правила «добавить решётку» заводить не нужно.
//
// Отвергнутая альтернатива названа с ценой: хранить текст БЕЗ решётки и
// добавлять её здесь. Тогда 76 голых решёток становятся пустыми строками YAML, и
// правило «пустая строка означает решётку» живёт В ДВУХ местах — у загрузчика и
// у рендера, — а два места об одном предмете расходятся молча. Строку без
// решётки отвергает загрузчик, называя якорь и номер строки внутри текста.
func noteLines(text string) []string {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	return strings.Split(strings.TrimRight(text, "\n"), "\n")
}

// canonicalVerbOrder — порядок глаголов канона. Замер по дереву: у 24 блоков из 27
// порядок `get list update delete`, у одного добавлен `create` третьим, у одного
// — два глагола управления составом ПОСЛЕ операций над объектом.
var canonicalVerbOrder = []string{"get", "list", "create", "update", "delete"}

// CanonicalVerbOrder возвращает позиции канонических глаголов как множество
// «имя → позиция». Экспортирована ради пробы согласия с набором загрузчика
// (TestCanonicalVerbOrderAgreesWithTheClassRule): без перечислителя согласие
// проверялось бы в одну сторону, и шестой глагол загрузчика уехал бы в хвост молча.
func CanonicalVerbOrder() map[string]int {
	out := make(map[string]int, len(canonicalVerbOrder))
	for i, v := range canonicalVerbOrder {
		out[v] = i
	}
	return out
}

// verbsInCanonOrder — действия ресурса в порядке канона: сперва канонические в
// объявленном порядке, затем прочие в порядке манифеста. Возвращается САМО
// действие, а не его имя: состав субъектов и источники вывода принадлежат ему.
//
// Прочие идут ПОСЛЕ и в порядке документа, а не отсортированно: канон ставит
// `v_addtargets`/`v_removetargets` последними, и сортировка поставила бы первым
// `addtargets` — то есть рендер разошёлся бы с каноном на единственном блоке,
// который эту форму несёт.
func verbsInCanonOrder(verbs []manifest.Verb) []manifest.Verb {
	byName := make(map[string]manifest.Verb, len(verbs))
	for _, v := range verbs {
		if v.Name != "" {
			byName[v.Name] = v
		}
	}
	var out []manifest.Verb
	for _, canonical := range canonicalVerbOrder {
		if v, ok := byName[canonical]; ok {
			out = append(out, v)
			delete(byName, canonical)
		}
	}
	for _, v := range verbs {
		if kept, ok := byName[v.Name]; ok {
			out = append(out, kept)
			delete(byName, v.Name)
		}
	}
	return out
}
