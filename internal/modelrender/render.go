// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package modelrender

import (
	"errors"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// render.go — порождение блока типа из ресурса манифеста (Н-01 приёмки).
//
// # Что порождается, а что объявляется человеком
//
// Раздел `resources` неоднороден (см. шапку manifest/resources.go), и рендер
// наследует это различие дословно:
//
//	порождается    указатель якоря · super_admin · ярусы · v_<глагол>
//	объявляется    doc · relations[] (текст определения — ДОСЛОВНО)
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
// # Субъекты сужают ЯРУСЫ и не трогают глаголы — это замер, а не симметрия
//
// У `vpc_address_pool` ярусы несут `[user, service_account]`, а его же `v_get`
// несёт полный набор с `group#member`. Сузив заодно глаголы, рендер отнял бы
// живое право у групп — молча, при действующей на вид привязке.
var (
	// ErrObjectTypeEmpty — рендерить нечего: тип объекта не назван.
	ErrObjectTypeEmpty = errors.New("modelrender: resource objectType is empty")
	// ErrParentEmpty — якорь области не назван; указатель якоря — первая строка блока.
	ErrParentEmpty = errors.New("modelrender: resource parent is empty")
)

// defaultSubjects — набор субъектов, который канон несёт у ярусов и у глаголов
// по умолчанию. Ресурс вправе СУЗИТЬ его у ярусов ключом `subjects`.
var defaultSubjects = []string{"user", "service_account", "group#member"}

// defaultTiers — ярусы по умолчанию, в порядке убывания прав. Порядок несущий:
// каждый следующий ярус выводится от предыдущего.
var defaultTiers = []string{"admin", "editor", "viewer"}

// Render порождает блок типа модели из ресурса манифеста.
//
// Возвращает байты единицы A: от строки `type X` до последнего перевода строки
// включительно, БЕЗ завершающей пустой строки — разделитель принадлежит файлу, а
// не блоку.
func Render(r manifest.Resource) ([]byte, error) {
	if r.ObjectType == "" {
		return nil, ErrObjectTypeEmpty
	}
	if r.Parent == "" {
		return nil, ErrParentEmpty
	}

	var b strings.Builder
	b.WriteString("type " + r.ObjectType + "\n")
	b.WriteString("  relations\n")

	// Авторский комментарий стоит СРАЗУ ПОСЛЕ `relations`, и позиция эта ОДНА.
	// Канон располагает прозу и в других местах блока; выразить это манифест
	// сегодня не может — `doc` есть один текст без координаты, и формы для
	// позиционированной прозы (Н-04 приёмки) в схеме нет. Позиция названа здесь,
	// а остаток сосчитан переписью, чтобы «выражено не всё» не выглядело «всё».
	for _, line := range docLines(r.Doc) {
		b.WriteString("    " + line + "\n")
	}

	b.WriteString("    define " + r.Parent + ": [" + r.Parent + "]\n")
	b.WriteString("    define super_admin: super_admin from " + r.Parent + "\n")

	subjects := r.Subjects
	if len(subjects) == 0 {
		subjects = defaultSubjects
	}
	tiers := r.Tiers
	if len(tiers) == 0 {
		tiers = defaultTiers
	}

	// Каждый следующий ярус выводится от ПРЕДЫДУЩЕГО, а первый — от super_admin.
	previous := "super_admin"
	for _, tier := range tiers {
		b.WriteString("    define " + tier + ": [" + strings.Join(subjects, ", ") + "] or " + previous + "\n")
		previous = tier
	}

	// Авторское отношение воспроизводится ДОСЛОВНО: грамматика определения
	// принадлежит модели прав, и второй её разборщик разошёлся бы с первым молча.
	for _, rel := range r.Relations {
		b.WriteString("    define " + rel.Name + ": " + rel.Definition + "\n")
	}

	// Порядок глаголов задаёт КАНОН, а не манифест: перестановка ресурсов и
	// глаголов в YAML рендер не меняет (B-04). Субъекты здесь умолчательные —
	// сужение ключом `subjects` трогает ярусы и не трогает глаголы.
	for _, verb := range verbsInCanonOrder(r.Verbs) {
		b.WriteString("    define " + manifest.VerbRelationName(verb) + ": [" +
			strings.Join(defaultSubjects, ", ") + "] or super_admin\n")
	}

	return []byte(b.String()), nil
}

// docLines — строки авторского комментария без хвостовой пустой.
//
// Пустая строка внутри блока разделила бы его надвое: единица блока есть тело до
// ПЕРВОЙ пустой строки, и комментарий, несущий её, породил бы два блока из одного.
func docLines(doc string) []string {
	if strings.TrimSpace(doc) == "" {
		return nil
	}
	out := strings.Split(strings.TrimRight(doc, "\n"), "\n")
	for i, l := range out {
		if strings.TrimSpace(l) == "" {
			out[i] = "#"
		}
	}
	return out
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

// verbsInCanonOrder — глаголы ресурса в порядке канона: сперва канонические в
// объявленном порядке, затем прочие в порядке манифеста.
//
// Прочие идут ПОСЛЕ и в порядке документа, а не отсортированно: канон ставит
// `v_addtargets`/`v_removetargets` последними, и сортировка поставила бы первым
// `addtargets` — то есть рендер разошёлся бы с каноном на единственном блоке,
// который эту форму несёт.
func verbsInCanonOrder(verbs []manifest.Verb) []string {
	present := make(map[string]bool, len(verbs))
	for _, v := range verbs {
		if v.Name != "" {
			present[v.Name] = true
		}
	}
	var out []string
	for _, canonical := range canonicalVerbOrder {
		if present[canonical] {
			out = append(out, canonical)
			delete(present, canonical)
		}
	}
	for _, v := range verbs {
		if present[v.Name] {
			out = append(out, v.Name)
			delete(present, v.Name)
		}
	}
	return out
}
