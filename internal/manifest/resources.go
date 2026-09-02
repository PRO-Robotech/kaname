// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package manifest

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
)

// resources.go — раздел `resources` (приёмка
// services/iam/docs/engineering/acceptance/module-manifest-resources-roles-deprecated.md,
// §1.3, §2.2 … §2.5; сценарии MOD-MR-01 … MOD-MR-09, MOD-MR-27).
//
// # Раздел НЕОДНОРОДЕН, и это главное о нём
//
// Решение эпика #1087 (исход B) говорит две вещи сразу, и вторая обычно теряется
// при пересказе: раздел ПОРОЖДАЕТСЯ из аннотаций контрактов и объявлением права
// не является — но руками в нём объявляется ровно то, чего аннотации не несут.
// То есть у одних ключей записи есть производитель в дереве, у других автор-
// человек, и перегенерация обязана сохранить вторые.
//
//	порождается    name · objectType · parent · verbs[]
//	объявляется    doc · relations[] · subjects[] · tiers[]
//
// Вид ключей записи называет сама запись — ключом `producer` из закрытого набора
// `derived | authored`. Он не порождается и ресурс не описывает: он говорит, чем
// являются ОСТАЛЬНЫЕ ключи, и без него вопрос «пережил ли авторский ключ
// перегенерацию» даже не формулируется.
//
// # Почему ДВА ресурса объявляются авторски — и обе причины постоянны
//
// Типов закрытой таблицы, не встречающихся ни в одном `scope_extractor.
// object_type` каталога, ровно два: `vpc_address_pool` (ресурс admin-only, его
// глаголы живут на внутреннем слушателе — ban #6) и `registry_repository`
// (объект составной, резолвится в обработчике, якорю нечего извлекать из поля
// запроса — анти-BOLA). Ни то, ни другое не пропуск, и порождение их не
// восстановит: без `producer: authored` цепочка «аннотации → resources →
// таблицы» потеряла бы две грантуемые записи МОЛЧА.
//
// # Правило вывода `objectType ← <module>_<resource>` СНЯТО целиком
//
// Оно покрывает 17 записей закрытой таблицы из 27 (без нормализации регистра —
// 8 из 27), то есть автор всё равно обязан знать, попадает ли его ресурс в
// исключение, — а это и есть та работа, которую вывод обещал снять. Раздел к
// тому же порождается, и у генератора нет причины опускать ключ, значение
// которого он уже держит в руках: опущение экономит байты файла и платит
// правилом, живущим в двух местах — в генераторе (когда опускать) и в
// загрузчике (как восстановить). Поэтому `objectType` обязателен у каждого
// ресурса, а его значение резолвится закрытой таблицей `authzmap`.
//
// # Форм у глагола ДВЕ, а правило класса ОДНО
//
// Короткая форма — строка (`get`), длинная — отображение (`{name:
// addCidrBlocks, class: update}`). Класс короткой выводит единственная
// экспортируемая функция ClassOfCanonicalVerb; второе объявление того же правила
// стережёт гейт дерева (internal/repohygiene TestVerbClassRuleIsDeclaredOnce),
// потому что единственность — свойство ДЕРЕВА, а не пакета.

// Виды находок различаются не ради красоты: «тип объекта не назван», «якорь вне
// набора», «класс не выводится» чинятся разными правками, и вызывающий (цель
// сборки, читающая дерево) вправе их различать.
var (
	// ErrResourceNameRequired — ресурс не назвал себя.
	ErrResourceNameRequired = errors.New("manifest: resource name is required")
	// ErrResourceNameDuplicated — два ресурса под одним именем. Отказ называет
	// ОБА индекса: названный первый заставил бы чинить по одному.
	ErrResourceNameDuplicated = errors.New("manifest: two resources share one name")
	// ErrObjectTypeRequired — тип объекта модели прав не назван. Правило вывода
	// из имени СНЯТО (см. шапку), поэтому восстановить его нечем.
	ErrObjectTypeRequired = errors.New("manifest: resource objectType is required")
	// ErrObjectTypeUnknown — тип объекта вне закрытой таблицы authzmap.
	ErrObjectTypeUnknown = errors.New("manifest: resource objectType is outside the closed table")
	// ErrParentRequired — якорь области не назван.
	ErrParentRequired = errors.New("manifest: resource parent is required")
	// ErrParentUnknown — якорь области вне закрытого набора.
	ErrParentUnknown = errors.New("manifest: resource parent is outside the closed set")
	// ErrProducerRequired — запись не сказала, чем являются её ключи.
	ErrProducerRequired = errors.New("manifest: resource producer is required")
	// ErrProducerUnknown — вид ключей вне закрытого набора.
	ErrProducerUnknown = errors.New("manifest: resource producer is outside the closed set")
	// ErrVerbNameRequired — глагол не назвал себя.
	ErrVerbNameRequired = errors.New("manifest: verb name is required")
	// ErrVerbClassNotDerivable — класс не выводится из имени, и он не назван.
	ErrVerbClassNotDerivable = errors.New("manifest: verb class is not derivable from the name")
	// ErrVerbClassUnknown — класс вне закрытого набора.
	ErrVerbClassUnknown = errors.New("manifest: verb class is outside the closed set")
	// ErrRelationShadowsVerb — объявленное отношение занимает имя, порождаемое
	// глаголом. Два объявления одного предмета, из которых верно одно.
	ErrRelationShadowsVerb = errors.New("manifest: authored relation shadows a generated verb relation")
	// ErrRelationNameRequired — отношение не назвало себя.
	ErrRelationNameRequired = errors.New("manifest: relation name is required")
)

// canonicalVerbClasses — ЕДИНСТВЕННОЕ в дереве объявление правила «класс из
// имени»: имя глагола, ТОЧНО совпавшее с одним из этих пяти, и есть свой класс.
//
// Набор одновременно служит закрытым перечнем принимаемых значений ключа
// `class` — и это не совпадение, а построение: класс, которого нельзя вывести
// ни из одного канонического имени, никем не производился бы.
//
// Правило живёт ЗДЕСЬ, а не в authzmap рядом с verbClass, и это отступление от
// §6 приёмки названо вместе с замером: `authzmap.verbClass` — классификатор
// ЯРУСА (чтение · запись · администрирование) по 30 токенам, а не правило
// класса действия по пяти. Экспортировав его, задача экспортировала бы другое
// правило; предикат — `sed -n '/^func verbClass/,/^}/p'
// services/iam/internal/authzmap/permissions_to_relations.go`, в теле три
// возвращаемых яруса и ни одного класса.
var canonicalVerbClasses = []string{"get", "list", "create", "update", "delete"}

// ClassOfCanonicalVerb возвращает класс действия, выводимый из ИМЕНИ глагола, и
// ok=false, когда имя не совпадает ни с одним каноническим точно.
//
// Экспортирована, потому что импортёров у неё двое: загрузчик (восстанавливает
// класс короткой формы) и генератор раздела (#1092 — эмитит короткую форму ровно
// тогда, когда эта функция вернула ok). Тогда правило нельзя рассогласовать by
// construction, а не по договорённости.
func ClassOfCanonicalVerb(name string) (string, bool) {
	if contains(canonicalVerbClasses, name) {
		return name, true
	}
	return "", false
}

// CanonicalVerbs возвращает КОПИЮ закрытого набора канонических классов действия
// в объявленном порядке.
//
// Импортёров три, и каждый назван, потому что без перечислителя каждый держал бы
// ВТОРУЮ копию набора: рендер блоков модели (#1089) · отказ о пустом классе
// (`manifest/roleexport`, #1090), который обязан назвать автору пригодные классы
// ресурса · сам разбор. Правило членства (`ClassOfCanonicalVerb`) отвечает про
// одно имя и перечислить набор не даёт.
//
// Набор здесь один, а ПОРЯДОК блоков модели принадлежит канону и объявлен у
// рендера отдельно — их согласие держит проба равенства множеств
// (modelrender: TestCanonicalVerbOrderAgreesWithTheClassRule), а не совпадение,
// на которое никто не смотрит.
//
// Отдаётся копией, чтобы вызывающий не переписал набор на месте.
func CanonicalVerbs() []string {
	out := make([]string, len(canonicalVerbClasses))
	copy(out, canonicalVerbClasses)
	return out
}

// resourceParents — закрытый набор якорей области ресурса.
var resourceParents = []string{"project", "account", "cluster"}

// resourceProducers — закрытый набор видов ключей записи.
var resourceProducers = []string{"derived", "authored"}

// Resource — один ресурс модуля.
//
// Порождённые и авторские ключи лежат В ОДНОЙ структуре намеренно: они
// описывают один предмет, и разнесение их по двум сообщениям заставило бы
// вызывающего склеивать записи по имени — ровно та работа, которую ключ
// `producer` снимает одним словом.
type Resource struct {
	// Name — имя ресурса в написании закрытой таблицы типов (единственное
	// число, camelCase): `securityGroup`, а не `security_groups`.
	Name string `yaml:"name"`
	// ObjectType — тип объекта модели прав. ОБЯЗАТЕЛЕН: правило вывода из имени
	// снято целиком (см. шапку файла).
	ObjectType string `yaml:"objectType"`
	// Parent — якорь области, под которым живёт ресурс.
	Parent string `yaml:"parent"`
	// Producer — чем являются ОСТАЛЬНЫЕ ключи записи: `derived` (порождены из
	// аннотаций) либо `authored` (написаны человеком, аннотаций у ресурса нет).
	Producer string `yaml:"producer"`
	// Doc — АВТОРСКИЙ комментарий блока модели. Перегенерация обязана его
	// сохранить: производителя у него нет.
	Doc string `yaml:"doc"`
	// Subjects — АВТОРСКИЙ состав субъектов, когда он уже общего. Умолчание
	// здесь расширило бы доступ молча.
	Subjects []string `yaml:"subjects"`
	// Tiers — АВТОРСКИЙ набор ярусов, когда он уже общего.
	Tiers []string `yaml:"tiers"`
	// Relations — АВТОРСКИЕ отношения модели, не выводимые ни из одного
	// действия: RPC под них нет.
	Relations []Relation `yaml:"relations"`
	// Verbs — действия ресурса. Обе формы записи принимаются (см. Verb).
	Verbs []Verb `yaml:"verbs"`
}

// Relation — отношение модели прав, объявленное человеком.
//
// Текст определения здесь НЕ разбирается: его грамматика принадлежит модели
// прав, и второй её разборщик разошёлся бы с первым молча. Рендер блоков модели
// — предмет #1104 → #1089.
type Relation struct {
	Name       string `yaml:"name"`
	Definition string `yaml:"definition"`
}

// Verb — действие ресурса. Записывается ДВУМЯ формами:
//
//   - get                                   короткая: класс выводится из имени
//   - {name: addCidrBlocks, class: update}   длинная: класс назван
//
// Обычной структурой Go это не разбирается («cannot unmarshal !!str `get` into
// verb»), поэтому у типа свой UnmarshalYAML.
type Verb struct {
	Name  string `yaml:"name"`
	Class string `yaml:"class"`
}

// UnmarshalYAML принимает обе формы и НЕ теряет свойство, которое держит
// `Decoder.KnownFields(true)`.
//
// Библиотека не проносит строгость внутрь собственного UnmarshalYAML: узел
// разбирается умолчательно, и ключ `clazz` уехал бы молча — то есть контракт
// обещал бы возможность, которой нет. Поэтому ключи сверяются здесь, до разбора,
// и отказ называет ключ и номер строки ровно как это делает библиотека.
func (v *Verb) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag != "!!str" {
			return fmt.Errorf("line %d: a verb written as a scalar must be a string, got %s",
				node.Line, node.Tag)
		}
		v.Name = node.Value
		return nil
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Value != "name" && key.Value != "class" {
				return fmt.Errorf("line %d: field %s not found in type verb", key.Line, key.Value)
			}
		}
		var raw struct {
			Name  string `yaml:"name"`
			Class string `yaml:"class"`
		}
		if err := node.Decode(&raw); err != nil {
			return err
		}
		v.Name, v.Class = raw.Name, raw.Class
		return nil
	default:
		return fmt.Errorf("line %d: a verb is a string or a mapping, got %s",
			node.Line, nodeKindName(node.Kind))
	}
}

// validateResources — форма и связность раздела `resources`.
//
// Класс короткой формы ВОССТАНАВЛИВАЕТСЯ здесь, а не в UnmarshalYAML: правило
// «класс из имени» обязано иметь одно место вызова, иначе оно поедет вслед за
// разбором и в генератор, и в загрузчик по отдельности.
//
// Находки собираются ВСЕ: названная первая заставила бы автора манифеста чинить
// их по одной, по прогону на каждую, и скрыла бы, сколько их всего.
func validateResources(m *Manifest, doc *yaml.Node) []error {
	var faults []error
	seen := map[string][]int{}

	for i := range m.Resources {
		r := &m.Resources[i]

		switch r.Name {
		case "":
			faults = append(faults, linkFault{
				kind:   ErrResourceNameRequired,
				coord:  locate(doc, "resources", i),
				detail: "ресурс не назвал себя: имя связывает его со строками каталога и с ролями",
			})
		default:
			seen[r.Name] = append(seen[r.Name], i)
		}

		faults = append(faults, validateResourceAnchors(r, doc, i)...)
		faults = append(faults, validateResourceVerbs(r, doc, i)...)
		faults = append(faults, validateResourceRelations(r, doc, i)...)
	}

	// Дубли называются ОБА, и в порядке документа: отказ, зависящий от обхода
	// карты, читался бы по-разному от прогона к прогону.
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		idx := seen[name]
		if len(idx) < 2 {
			continue
		}
		where := make([]string, 0, len(idx))
		for _, i := range idx {
			where = append(where, fmt.Sprintf("resources[%d]", i))
		}
		faults = append(faults, linkFault{
			kind:  ErrResourceNameDuplicated,
			coord: locate(doc, "resources", idx[0]),
			detail: fmt.Sprintf("имя %q объявлено %d раза: %s — имя ресурса адресует его в ролях, "+
				"и два адресата у одного имени делают выдачу невыразимой",
				name, len(idx), strings.Join(where, ", ")),
		})
	}
	return faults
}

// validateResourceAnchors — тип объекта, якорь области и вид ключей записи.
func validateResourceAnchors(r *Resource, doc *yaml.Node, i int) []error {
	var faults []error

	switch r.ObjectType {
	case "":
		faults = append(faults, linkFault{
			kind:  ErrObjectTypeRequired,
			coord: locate(doc, "resources", i, "objectType"),
			detail: "тип объекта модели прав обязан быть назван дословно: правило «тип = " +
				"<модуль>_<ресурс>» снято, оно не действует у 10 записей закрытой таблицы из 27",
		})
	default:
		if _, ok := authzmap.DottedType(r.ObjectType); !ok {
			faults = append(faults, linkFault{
				kind:  ErrObjectTypeUnknown,
				coord: locate(doc, "resources", i, "objectType"),
				detail: fmt.Sprintf("типа %q нет в закрытой таблице типов iam: селектор роли "+
					"адресовал бы тип, которого не существует, и не дал бы НИ ОДНОГО "+
					"пообъектного права — молча, при действующей на вид привязке", r.ObjectType),
			})
		}
	}

	switch {
	case r.Parent == "":
		faults = append(faults, linkFault{
			kind:  ErrParentRequired,
			coord: locate(doc, "resources", i, "parent"),
			detail: fmt.Sprintf("якорь области не назван; принимаются: %s",
				strings.Join(resourceParents, ", ")),
		})
	case !contains(resourceParents, r.Parent):
		faults = append(faults, linkFault{
			kind:  ErrParentUnknown,
			coord: locate(doc, "resources", i, "parent"),
			detail: fmt.Sprintf("якорь %q вне закрытого набора; принимаются: %s",
				r.Parent, strings.Join(resourceParents, ", ")),
		})
	}

	switch {
	case r.Producer == "":
		faults = append(faults, linkFault{
			kind:  ErrProducerRequired,
			coord: locate(doc, "resources", i, "producer"),
			detail: fmt.Sprintf("запись не сказала, чем являются её ключи; принимаются: %s. "+
				"Без этого перегенерация не знает, что сохранять, и вопрос «пережил ли "+
				"авторский ключ» не формулируется вовсе", strings.Join(resourceProducers, ", ")),
		})
	case !contains(resourceProducers, r.Producer):
		faults = append(faults, linkFault{
			kind:  ErrProducerUnknown,
			coord: locate(doc, "resources", i, "producer"),
			detail: fmt.Sprintf("вид ключей %q вне закрытого набора; принимаются: %s",
				r.Producer, strings.Join(resourceProducers, ", ")),
		})
	}
	return faults
}

// validateResourceVerbs — имя и класс каждого действия; класс короткой формы
// восстанавливается ТУТ ЖЕ, единственным вызовом правила.
func validateResourceVerbs(r *Resource, doc *yaml.Node, i int) []error {
	var faults []error
	for j := range r.Verbs {
		v := &r.Verbs[j]
		if v.Name == "" {
			faults = append(faults, linkFault{
				kind:   ErrVerbNameRequired,
				coord:  locate(doc, "resources", i, "verbs", j),
				detail: "действие не назвало себя: имя действия — сегмент права, по которому его выдают",
			})
			continue
		}
		if v.Class == "" {
			class, ok := ClassOfCanonicalVerb(v.Name)
			if !ok {
				faults = append(faults, linkFault{
					kind:  ErrVerbClassNotDerivable,
					coord: locate(doc, "resources", i, "verbs", j),
					detail: fmt.Sprintf("%s: класс действия %q не выводится — из имени класс берётся "+
						"ТОЛЬКО при точном совпадении с одним из %s; назовите класс явно",
						fmt.Sprintf("resources[%d].verbs[%d].class", i, j), v.Name,
						strings.Join(canonicalVerbClasses, " · ")),
				})
				continue
			}
			v.Class = class
		}
		if !contains(canonicalVerbClasses, v.Class) {
			faults = append(faults, linkFault{
				kind:  ErrVerbClassUnknown,
				coord: locate(doc, "resources", i, "verbs", j),
				detail: fmt.Sprintf("%s: класс %q вне закрытого набора; принимаются: %s",
					fmt.Sprintf("resources[%d].verbs[%d].class", i, j), v.Class,
					strings.Join(canonicalVerbClasses, ", ")),
			})
		}
	}
	return faults
}

// validateResourceRelations — объявленное отношение не вправе занять имя,
// которое порождает глагол того же ресурса.
func validateResourceRelations(r *Resource, doc *yaml.Node, i int) []error {
	var faults []error
	generated := map[string]string{}
	for _, v := range r.Verbs {
		if v.Name != "" {
			generated[VerbRelationName(v.Name)] = v.Name
		}
	}
	for k, rel := range r.Relations {
		if rel.Name == "" {
			faults = append(faults, linkFault{
				kind:   ErrRelationNameRequired,
				coord:  locate(doc, "resources", i, "relations", k),
				detail: "отношение не назвало себя: безымянное отношение нечем адресовать в модели",
			})
			continue
		}
		verb, shadows := generated[rel.Name]
		if !shadows {
			continue
		}
		faults = append(faults, linkFault{
			kind:  ErrRelationShadowsVerb,
			coord: locate(doc, "resources", i, "relations", k),
			detail: fmt.Sprintf("%s: имя %q уже порождается глаголом %q того же ресурса — "+
				"два объявления одного отношения, из которых верно одно",
				fmt.Sprintf("resources[%d].relations[%d].name", i, k), rel.Name, verb),
		})
	}
	return faults
}

// VerbRelationName — имя отношения модели, порождаемое действием.
//
// Экспортирована, потому что тот же вывод делает рендер блоков модели (#1089):
// вторая копия правила разошлась бы с первой молча, и разошлась бы там, где
// расхождение не видно — обе стороны отвечают одинаково на входе, где правило
// совпадает.
//
// # Приведение к нижнему регистру — НЕ косметика, и цена его отсутствия измерена
//
// Авторский глагол пишется верблюжьим (`addTargets`), отношение модели — строчным:
// канон несёт `define v_addtargets`. Тот же вывод уже сделан эмиттером —
// `authzmap.targetGroupVerbRelations` объявляет набор `nlb_target_group` именами
// `v_addtargets`/`v_removetargets` и говорит об этом дословно: «имя, написанное
// иначе, чем его собирает эмиттер, адресовало бы отношение, по которому никто не
// постучится».
//
// Без приведения эта функция расходилась с эмиттером на КАЖДОМ неканоническом
// глаголе, и расхождение было тихим: сравнение сторон не совпало бы ни разу и
// отняло бы живое право, выглядя рабочим. Тот же класс каталог держит
// ограничением таблицы — `CHECK (verb = lower(btrim(verb)))`.
//
// Держит правило проба против ДЕРЕВА (verb_relation_name_test.go), а не против
// литерала рядом: литерал согласился бы с любой редакцией правила.
func VerbRelationName(verb string) string { return "v_" + strings.ToLower(verb) }
