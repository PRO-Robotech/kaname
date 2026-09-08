// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
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
//	порождается    name · objectType · parents[] · verbs[]
//	объявляется    notes[] · relations[] · subjects[] · tiers[] · cascade[]
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
	// ЗДЕСЬ БЫЛ `ErrObjectTypeUnknown` — «тип объекта вне закрытой таблицы
	// authzmap». Он снят ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ (задача #2015): таблица типов
	// разомкнута, членство в ней больше не спрашивается, и производителя у этого
	// отказа не осталось ни одного. Оставь я сентинел «на всякий случай» — он
	// объявлял бы отказ, которого продукт не производит, и следующий читатель
	// написал бы на него проверку, зелёную при любом входе.
	//
	// ErrObjectTypeMalformed — имя типа объекта не той формы.
	//
	// Пришло на место снятого и отличается от него предметом: тот судил ЧЛЕНСТВО
	// в таблице, недоступной автору манифеста, этот судит ФОРМУ, которую автор
	// читает в тексте отказа и может исправить.
	ErrObjectTypeMalformed = errors.New("manifest: resource objectType name is malformed")
	// ErrObjectTypeRedefinesImage — доставка присваивает своей строке тип,
	// который образ уже объявил ДРУГОЙ строкой.
	//
	// Отдельный отказ, а не частный случай формы: чинится он переносом типа к
	// владельцу, а не правкой имени.
	ErrObjectTypeRedefinesImage = errors.New("manifest: resource objectType redefines a type the image already declares")
	// ErrObjectTypeCollision — один тип объекта объявлен больше чем одной
	// строкой: двумя ресурсами документа либо двумя манифестами обхода.
	//
	// У типа один владелец. Прими мы второго — права, выданные на одну строку,
	// материализовались бы на объектах другой, а чья строка доедет до
	// применителя, решал бы порядок обхода.
	ErrObjectTypeCollision = errors.New("manifest: object type is declared by more than one resource")
	// ErrParentRequired — указатель на объект-владелец не назван.
	ErrParentRequired = errors.New("manifest: resource parents are required")
	// ErrParentUnknown — тип объекта указателя вне закрытого набора.
	ErrParentUnknown = errors.New("manifest: resource parent type is outside the closed set")
	// ErrParentNameRequired — указатель не назвал себя.
	ErrParentNameRequired = errors.New("manifest: resource parent name is required")
	// ErrParentNameDuplicated — два указателя под одним именем. Второй объявил бы
	// то же отношение модели во второй раз, и верно из двух было бы одно.
	ErrParentNameDuplicated = errors.New("manifest: two resource parents share one name")
	// ErrParentFormRedundant — длинная форма указателя при совпадающих имени и
	// типе: одно значение, записываемое двумя способами.
	ErrParentFormRedundant = errors.New("manifest: parent written in the long form while its name equals its type")
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
	// ErrNoteAnchorRequired — примечание не назвало якоря.
	ErrNoteAnchorRequired = errors.New("manifest: note anchor is required")
	// ErrNoteAnchorUnknown — якорь примечания не объявлен блоком: примечание не
	// напечаталось бы вовсе, а вызывающий получил бы успех.
	ErrNoteAnchorUnknown = errors.New("manifest: note is anchored to a relation the block does not declare")
	// ErrNoteAnchorDuplicated — два примечания на одном якоре: порядок между ними
	// ничем не задан.
	ErrNoteAnchorDuplicated = errors.New("manifest: two notes share one anchor")
	// ErrNoteTextRequired — примечание без текста печатать нечего.
	ErrNoteTextRequired = errors.New("manifest: note text is required")
	// ErrNoteLineNotAComment — строка текста примечания не начинается со знака
	// комментария: в блоке модели она перестала бы быть прозой.
	ErrNoteLineNotAComment = errors.New("manifest: note text line does not start with a comment sign")
	// ErrRelationPositionUnknown — место отношения вне закрытого набора.
	ErrRelationPositionUnknown = errors.New("manifest: relation position is outside the closed set")
	// ErrResourceVerbsRequired — ресурс не назвал ни одного действия.
	ErrResourceVerbsRequired = errors.New("manifest: resource declares no verbs")
	// ErrRelationDefinitionRequired — объявленное дословно отношение не сказало,
	// ЧЕМ оно является.
	ErrRelationDefinitionRequired = errors.New("manifest: relation has no definition")
	// ErrBaseRolesWithoutTenantVerb — ресурс объявил базовые ярусные роли, а
	// арендатору у него доступно ноль действий.
	ErrBaseRolesWithoutTenantVerb = errors.New("manifest: base roles are declared on a resource with no tenant-facing verb")
	// ErrRelationNameRequired — отношение не назвало себя.
	ErrRelationNameRequired = errors.New("manifest: relation name is required")
	// ErrCascadeTermIncomplete — терм каскада назван наполовину: без отношения
	// либо без указателя, от которого он выводится.
	ErrCascadeTermIncomplete = errors.New("manifest: cascade term is incomplete")
	// ErrCascadeFromUnknown — терм каскада выводится от указателя, которого у
	// ресурса нет: отношение адресовало бы объект, которого блок не объявляет.
	ErrCascadeFromUnknown = errors.New("manifest: cascade term derives from an undeclared parent")
	// ErrTierNameRequired — ярус не назвал себя.
	ErrTierNameRequired = errors.New("manifest: tier name is required")
	// ErrVerbSourceUnknown — действие выводится от отношения, которого блок не несёт.
	ErrVerbSourceUnknown = errors.New("manifest: verb derives from a relation the block does not declare")
	// ErrTierSourceUnknown — ярус выводится от отношения, которого блок не несёт.
	ErrTierSourceUnknown = errors.New("manifest: tier derives from a relation the block does not declare")
	// ErrTierFormRedundant — длинная форма яруса без собственных источников:
	// одно значение, записанное двумя способами.
	ErrTierFormRedundant = errors.New("manifest: tier written in the long form while deriving from the chain")
	// ErrSourceListEmpty — перечень источников объявлен пустым. Пустой перечень
	// неотличим от опущенного ключа, а формы «без источников вовсе» канон не несёт.
	ErrSourceListEmpty = errors.New("manifest: an empty source list is not a form of the model")
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

// verbClassesOf — классы действия, ПРИНИМАЕМЫЕ у этого ресурса: канонические
// пять ПЛЮС отношения, порождаемые его собственными действиями.
//
// # Набор классов перестал быть пятёркой, и это замер
//
// Тип `nlb_target_group` объявляет ШЕСТЬ отношений действия — четыре операции над
// объектом плюс `v_addtargets`/`v_removetargets`, — и запись каталога спрашивает
// `v_addtargets`. Пока набор классов был пятёркой, это действие не выражалось НИ
// ОДНИМ входом: длинная форма давала «класс вне закрытого набора», короткая —
// «класс не выводится», а любой другой класс писал бы не то отношение, которого
// требует гейт. Возможность была объявлена и неисполнима.
//
// # Набор ВЫВОДИТСЯ из самого ресурса, а НЕ спрашивается у закрытой таблицы
//
// Два довода, и каждый самостоятельно достаточен.
//
// Первый — направление истины. Таблицы типов ПОРОЖДАЮТСЯ из манифеста (#1092);
// загрузчик, спрашивающий у них набор классов, замкнул бы круг: манифест
// принимался бы ровно тем, что из него же и выводится.
//
// Второй — запрет читать каталожный факт у литерала (kacho#1816, гейт
// `internal/check` `TestIAMCT2_LiteralIsNotAReadSource`). «Какие глаголы
// объявлены» есть каталожный факт: он меняется снятием строки в РАБОТАЮЩЕМ
// процессе, и спрашивать его полагается у снимка каталога, а не у литерала.
// Снимка у загрузчика нет и быть не должно — он судит ФОРМУ документа.
//
// # Что здесь НЕ судится, и кто это судит
//
// Несёт ли тип это отношение на самом деле — вопрос СУЩЕСТВА, и его задаёт
// применитель ролей (`manifest/roleexport`, `judgeVerb`) со снимком каталога в
// руках: класс, не удовлетворяющий гейт действия, там находка MOD-RL-22 с
// перечнем годных классов. Здесь остаётся форма: класс либо канонический, либо
// это отношение, которое порождает действие ЭТОГО ЖЕ ресурса.
//
// Порядок детерминирован: сперва канонические в объявленном порядке, затем
// собственные действия в порядке документа. Отказ печатает этот перечень, и
// порядок, зависящий от обхода карты, читался бы по-разному от прогона к прогону.
func verbClassesOf(r *Resource) []string {
	out := CanonicalVerbs()
	for _, v := range r.Verbs {
		if v.Name == "" {
			continue
		}
		if lowered := strings.ToLower(v.Name); !contains(out, lowered) {
			out = append(out, lowered)
		}
	}
	return out
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

// scopeAnchors — закрытый набор ЯКОРЕЙ ОБЛАСТИ платформы. Тот же словарь, что у
// областей выдачи (`iam.project | iam.account | iam.cluster`) без точечного
// префикса, и он ОСТАЁТСЯ закрытым: расширяется тип указателя, а не право.
var scopeAnchors = []string{"project", "account", "cluster"}

// parentTypeIsKnown — тип объекта, на который указатель вправе указывать.
//
// Принимается ТРИ словаря, и они разные:
//
//	якорь области            закрытый набор выше; `cluster` живёт только в нём —
//	                         записи в таблице типов у него нет вовсе;
//	тип ОБРАЗА               порождённая сборкой таблица `authzmap`;
//	тип ЭТОГО ЖЕ документа   ресурс, объявленный тем же манифестом (#2015).
//
// Слить первые два одним ключом значило бы объявить, что ресурс-владелец и
// область выдачи суть одно, — а замер по канону говорит обратное:
// `registry_repository` указывает на `registry_registry`, который областью
// выдачи не является ни при каком написании.
//
// Третий словарь и есть размыкание: оператор чужого облака вправе подвесить свой
// тип под свой же, и без него ЛЮБАЯ иерархия его модуля была бы невыразима — тип
// родителя он объявляет тем же манифестом, и таблица образа о нём не знает by
// construction (objecttype.go).
//
// Обход СЮДА не приходит намеренно: указатель резолвится по типам ТОГО ЖЕ
// документа, а не всей доставки. Замер по дереву — указателей на тип (а не на
// якорь области) ОДИН на шесть манифестов, и он внутридокументный; открыв обход,
// я заведомо разрешил бы иерархию через границу модуля, которой сегодня нет и
// решения о которой никто не принимал.
func parentTypeIsKnown(typ string, ownTypes map[string]struct{}) bool {
	if contains(scopeAnchors, typ) {
		return true
	}
	if _, own := ownTypes[typ]; own {
		return true
	}
	_, ok := authzmap.DottedType(typ)
	return ok
}

// superAdminRelation — имя отношения супер-доступа в блоке модели. Объявлено
// ОДИН раз: имя порождается рендером, а на него ссылаются источники ярусов и
// якорь примечания, и второе объявление разошлось бы с первым молча.
const superAdminRelation = "super_admin"

// SuperAdminRelation возвращает имя отношения супер-доступа.
//
// Экспортировано ради рендера блоков модели: он порождает это отношение, а
// загрузчик проверяет ссылки на него, и вторая копия имени разошлась бы с первой.
func SuperAdminRelation() string { return superAdminRelation }

// defaultTierChain — ярусы по умолчанию, в порядке убывания прав. Порядок
// НЕСУЩИЙ: каждый следующий ярус выводится от предыдущего, а первый — от
// супер-доступа.
var defaultTierChain = []string{"admin", "editor", "viewer"}

// defaultSubjectSet — состав субъектов, который канон несёт у ярусов и у
// отношений действий по умолчанию.
var defaultSubjectSet = []string{"user", "service_account", "group#member"}

// DefaultTiers возвращает КОПИЮ умолчательной цепочки ярусов.
//
// Импортёров двое — рендер (порождает строки) и загрузчик (проверяет ссылки на
// ярусы у ресурса, который свой набор не объявил). Вторая копия цепочки
// разошлась бы с первой молча: обе стороны отвечают одинаково ровно там, где
// совпадают.
func DefaultTiers() []string {
	out := make([]string, len(defaultTierChain))
	copy(out, defaultTierChain)
	return out
}

// DefaultSubjects возвращает КОПИЮ умолчательного состава субъектов.
func DefaultSubjects() []string {
	out := make([]string, len(defaultSubjectSet))
	copy(out, defaultSubjectSet)
	return out
}

// relationPositions — закрытый набор МЕСТ авторского отношения в блоке, в
// порядке следования строк. Умолчание — `beforeVerbs`: так стояли все авторские
// отношения, пока место задавала постоянная рендера.
var relationPositions = []string{"beforeTiers", "beforeVerbs", "afterVerbs"}

// RelationPositions возвращает КОПИЮ закрытого набора мест.
//
// Экспортирован ради рендера: он раскладывает отношения по этим местам, а
// загрузчик проверяет значение ключа, и второй перечень разошёлся бы с первым
// молча — на том самом месте, о котором не знает.
func RelationPositions() []string {
	out := make([]string, len(relationPositions))
	copy(out, relationPositions)
	return out
}

// DefaultRelationPosition — место, которое отношение занимает, не назвав его.
func DefaultRelationPosition() string { return relationPositions[1] }

// resourceProducers — закрытый набор видов ключей записи.
var resourceProducers = []string{"derived", "authored"}

// resourceTiers — ярусы, на которые ресурс порождает базовую роль, когда он об
// этом сказал. Порядок — от слабого к сильному, как читает его модель прав.
//
// Здесь объявлен НАБОР, а не каскад: `roleexport` объявляет тот же перечень
// именами каскада, и предметы у них разные — там порядок значим (обладатель
// сильного яруса удовлетворяет гейт слабого), здесь значим только состав.
// Свести их в одно объявление нельзя по направлению импортов: `roleexport`
// зависит от разбора, разбор от него — НИКОГДА.
var resourceTiers = []string{"viewer", "editor", "admin"}

// Resource — один ресурс модуля.
//
// Порождённые и авторские ключи лежат В ОДНОЙ структуре намеренно: они
// описывают один предмет, и разнесение их по двум сообщениям заставило бы
// вызывающего склеивать записи по имени — ровно та работа, которую ключ
// `producer` снимает одним словом.
type Resource struct {
	// Name — имя ресурса ДОСЛОВНО тем словом, которым его называет закрытая
	// таблица типов: `securityGroup` у vpc, `targetGroups` у балансировщика.
	//
	// Числа у этого написания НЕТ, и обещать его нельзя: восемь ключей таблицы
	// из 27 множественные (loadbalancer · registry · storage), остальные
	// единственные. Прежняя редакция обещала «единственное число» — то есть
	// требование схемы противоречило самой таблице ровно у тех модулей, где
	// автору манифеста и нужна подсказка (#1884).
	//
	// Написание ОБЩЕЕ с правилом роли и с привязкой записей каталога, и это не
	// совпадение: правило, назвавшее ресурс иначе, отвергает validateRuleCatalog
	// на пути запроса, а привязка приводит выведенное из имени службы к тому же
	// слову (authzmap.CatalogSpelling). Словарь один, объявлен один раз.
	Name string `yaml:"name"`
	// ObjectType — тип объекта модели прав. ОБЯЗАТЕЛЕН: правило вывода из имени
	// снято целиком (см. шапку файла).
	ObjectType string `yaml:"objectType"`
	// Parents — указатели на объекты, под которыми живёт ресурс, в порядке
	// блока модели. Первый — якорь области; остальные структурные.
	Parents []Parent `yaml:"parents"`
	// Producer — чем являются ОСТАЛЬНЫЕ ключи записи: `derived` (порождены из
	// аннотаций) либо `authored` (написаны человеком, аннотаций у ресурса нет).
	Producer string `yaml:"producer"`
	// Notes — АВТОРСКИЕ примечания блока модели, каждое со своим ЯКОРЕМ.
	// Перегенерация обязана их сохранить: производителя у них нет.
	Notes []Note `yaml:"notes"`
	// Subjects — АВТОРСКИЙ состав субъектов, когда он уже общего. Умолчание
	// здесь расширило бы доступ молча.
	Subjects []string `yaml:"subjects"`
	// Tiers — АВТОРСКИЙ набор ярусов, когда он отличается от общего: составом
	// либо источниками вывода.
	Tiers []ResourceTier `yaml:"tiers"`
	// Cascade — правая часть отношения супер-доступа, когда она отличается от
	// умолчания `super_admin from <первый указатель>`.
	Cascade []CascadeTerm `yaml:"cascade"`
	// Relations — АВТОРСКИЕ отношения модели, не выводимые ни из одного
	// действия: RPC под них нет.
	Relations []Relation `yaml:"relations"`
	// Verbs — действия ресурса. Обе формы записи принимаются (см. Verb).
	Verbs []Verb `yaml:"verbs"`
	// BaseRoles — ресурс порождает БАЗОВЫЕ ЯРУСНЫЕ РОЛИ.
	//
	// Признак ЯВНЫЙ, и это решение, а не умолчание: наивный вывод трёх ярусов
	// из классов даёт тридцать ролей при живых восемнадцати, то есть двенадцать
	// системных ролей завелись бы молча — необратимая правка каталога прав
	// арендатора. Дискриминатора, отделяющего ресурсы с ярусами от ресурсов без
	// них, среди прочих полей НЕ СУЩЕСТВУЕТ: ни якорь, ни состав субъектов, ни
	// набор ярусов, ни доля внутренних действий шесть от четырёх не отделяют.
	// Это перепись приёмки, а не «не нашли».
	//
	// Отсутствие признака означает «ярусов нет».
	BaseRoles bool `yaml:"baseRoles"`
}

// BaseRoleTiers — ярусы, которые ресурс ПОРОЖДАЕТ базовыми ролями.
//
// Пусто, когда признак не объявлен: отсутствие означает «ярусов нет», а не
// «ярусы по умолчанию». Умолчание здесь и есть та самая молчаливая правка
// каталога, ради запрета которой признак заведён.
//
// Авторский набор `tiers` СУЖАЕТ выводимое: он объявлен ровно там, где состав
// уже общего (у административного ресурса нет яруса редактора вовсе), и
// выводить роль на ярус, которого у типа нет, значило бы выдавать право,
// которого никто не спрашивает.
func (r Resource) BaseRoleTiers() []string {
	if !r.BaseRoles {
		return nil
	}
	if len(r.Tiers) > 0 {
		// Имя яруса, а не запись целиком: базовая роль адресуется именем, а
		// перечень отношений вывода — предмет блока модели, не роли.
		named := make([]string, 0, len(r.Tiers))
		for _, t := range r.Tiers {
			named = append(named, t.Name)
		}
		return named
	}
	return append([]string(nil), resourceTiers...)
}

// Note — АВТОРСКОЕ примечание блока модели: текст и ЯКОРЬ, то есть имя
// отношения, перед которым примечание стоит.
//
// # Якорь обязателен, и это замер, а не осторожность
//
// Примечаний в модульных блоках канона 15 на 634 строки, и якорями им служат
// девять разных отношений: указатель, супер-доступ, ярусы, действия и авторские
// отношения — в том числе последнее отношение блока. Пока примечание было ОДНИМ
// текстом без координаты, рендер обязан был выбрать одну позицию, и всякий блок
// с иным расположением прозы был недостижим by construction.
//
// Примечания несут самоистекающие маркеры и ссылки на задачи: потерять их
// перегенерацией значило бы снять условие, о котором никто не решал.
//
// # Знак комментария принадлежит ТЕКСТУ, а не рендеру
//
// Замер: отступ у всех 634 строк прозы модульных блоков — четыре пробела, формы
// `#текст` без пробела нет ни одной, голых решёток 76. Значит рендер строки есть
// чистое склеивание `"    " + строка`. Хранить текст без решётки и добавлять её
// рендером — отвергнуто с ценой: 76 голых решёток стали бы пустыми строками
// YAML, и правило «пустая строка означает решётку» жило бы в ДВУХ местах.
//
// Строка без решётки отвергается синхронно, с якорем и номером строки внутри
// текста: воспроизведённая дословно, она стала бы в блоке объявлением отношения.
type Note struct {
	// Before — имя отношения, ПЕРЕД которым стоит примечание. Отношение обязано
	// быть объявлено этим же блоком: примечание с якорем в пустоту не
	// напечаталось бы вовсе, а вызывающий получил бы успех.
	Before string `yaml:"before"`
	// Text — сам текст, строками, СО знаком комментария у каждой: рендер
	// воспроизводит его дословно и своего правила оформления не имеет.
	Text string `yaml:"text"`
}

// Parent — указатель на объект, под которым живёт ресурс: ИМЯ отношения в блоке
// и ТИП объекта, на который оно указывает.
//
// # Имя и тип — разные строки, и это замер, а не осторожность
//
// У 26 модульных блоков канона из 27 они совпадают (`define project: [project]`),
// у одного — нет: `registry_repository` несёт `define parent: [registry_registry]`.
// Пока имя выводилось из типа, эта пара не порождалась НИ ПРИ КАКОМ значении
// ключа, то есть блок был недостижим by construction.
//
// # Форм записи ДВЕ, и каждое значение выразимо ровно ОДНОЙ
//
//	project                                    короткая: имя равно типу
//	{name: parent, type: registry_registry}    длинная: они различаются
//
// Длинная форма при совпадающих имени и типе ОТВЕРГАЕТСЯ: одно значение, два
// способа записи — ровно тот класс, который манифест и ловит. Тот же приём, что
// у действия (`Verb`): короткая форма ровно там, где выводить есть из чего.
type Parent struct {
	// Name — имя отношения-указателя в блоке модели.
	Name string `yaml:"name"`
	// Type — тип объекта, на который указатель указывает.
	Type string `yaml:"type"`

	// long — запись пришла длинной формой. Неэкспортируемое и без yaml-тега: это
	// НЕ ключ документа, а форма его записи, и обход полей структур (MOD-MF-21)
	// его не видит.
	long bool
}

// UnmarshalYAML принимает обе формы и НЕ теряет строгость к неизвестному ключу.
//
// Библиотека не проносит `Decoder.KnownFields(true)` внутрь собственного
// UnmarshalYAML (то же измерено у `Verb`), поэтому ключи сверяются здесь, до
// разбора, и отказ называет ключ и номер строки ровно как это делает библиотека.
func (p *Parent) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag != "!!str" {
			return fmt.Errorf("line %d: a parent written as a scalar must be a string, got %s",
				node.Line, node.Tag)
		}
		p.Name, p.Type, p.long = node.Value, node.Value, false
		return nil
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Value != "name" && key.Value != "type" {
				return fmt.Errorf("line %d: field %s not found in type parent", key.Line, key.Value)
			}
		}
		var raw struct {
			Name string `yaml:"name"`
			Type string `yaml:"type"`
		}
		if err := node.Decode(&raw); err != nil {
			return err
		}
		p.Name, p.Type, p.long = raw.Name, raw.Type, true
		return nil
	default:
		return fmt.Errorf("line %d: a parent is a string or a mapping, got %s",
			node.Line, nodeKindName(node.Kind))
	}
}

// CascadeTerm — один терм правой части отношения супер-доступа: `<relation> from
// <from>`. Термы соединяются `or` в порядке объявления.
//
// # Написаний каскада в каноне ЧЕТЫРЕ, и это замер, а не осторожность
//
//	super_admin from <указатель>                                        19 блоков — умолчание
//	admin from account                                                   4 блока
//	any_admin from cluster                                               2 блока
//	admin from account or any_admin from cluster                         1 блок
//	super_admin from project or admin from account or any_admin ...      1 блок
//
// Восемь блоков несут написание, которого одно умолчание не даёт ни при каком
// входе. Форма структурная, а не текстовая: разбор строки `admin from account`
// завёл бы ВТОРОЙ разборщик грамматики модели прав, и он разошёлся бы с первым
// молча — на той самой форме, которой не знает.
type CascadeTerm struct {
	// Relation — отношение НА ОБЪЕКТЕ-ВЛАДЕЛЬЦЕ, от которого выводится каскад.
	// Загрузчик его существования не проверяет и проверить не может: отношение
	// принадлежит блоку владельца, а не этому. Проверяет сверка с каноном.
	Relation string `yaml:"relation"`
	// From — ИМЯ указателя этого ресурса, по которому идёт вывод. Указатель
	// обязан быть объявлен: иначе каскад адресует объект, которого блок не несёт.
	From string `yaml:"from"`
}

// ResourceTier — ярус прав ресурса.
//
// Имя типа несёт слово «ресурс», потому что в этом же пакете живёт ЯРУС РОЛИ
// (`Tier` в roles.go) — уровень, на котором роль определена. Предметы разные:
// здесь ступень прав внутри блока модели, там якорь определения роли, — и одно
// имя на двоих читалось бы как один предмет.
//
// # Форм записи ДВЕ, и каждое значение выразимо ровно ОДНОЙ
//
//	admin                                короткая: ярус выводится от ПРЕДЫДУЩЕГО
//	{name: admin, from: [owner, super_admin]}   длинная: источники названы
//
// Замер: `account` несёт `define admin: [...] or owner or super_admin`,
// `iam_user` — `define viewer: [...] or subject or editor`. Постоянная цепочка
// `admin → editor → viewer` этих двух написаний не даёт ни при каком входе.
//
// Длинная форма без собственных источников ОТВЕРГАЕТСЯ: она означала бы ровно то
// же, что короткая.
type ResourceTier struct {
	// Name — имя яруса в блоке модели.
	Name string `yaml:"name"`
	// From — отношения, от которых ярус выводится, в порядке правой части. Пусто
	// означает умолчание: предыдущий ярус, а для первого — супер-доступ.
	From []string `yaml:"from"`

	// long — запись пришла длинной формой (см. Parent.long).
	long bool
}

// UnmarshalYAML принимает обе формы яруса и НЕ теряет строгость к неизвестному
// ключу (см. Parent.UnmarshalYAML — то же измерено у действия).
func (tr *ResourceTier) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Tag != "!!str" {
			return fmt.Errorf("line %d: a tier written as a scalar must be a string, got %s",
				node.Line, node.Tag)
		}
		tr.Name, tr.From, tr.long = node.Value, nil, false
		return nil
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			key := node.Content[i]
			if key.Value != "name" && key.Value != "from" {
				return fmt.Errorf("line %d: field %s not found in type tier", key.Line, key.Value)
			}
		}
		var raw struct {
			Name string   `yaml:"name"`
			From []string `yaml:"from"`
		}
		if err := node.Decode(&raw); err != nil {
			return err
		}
		tr.Name, tr.From, tr.long = raw.Name, raw.From, true
		return nil
	default:
		return fmt.Errorf("line %d: a tier is a string or a mapping, got %s",
			node.Line, nodeKindName(node.Kind))
	}
}

// Relation — отношение модели прав, объявленное человеком.
//
// Текст определения здесь НЕ разбирается: его грамматика принадлежит модели
// прав, и второй её разборщик разошёлся бы с первым молча. Рендер блоков модели
// — предмет #1104 → #1089.
//
// # Место отношения в блоке приходит ИЗ МАНИФЕСТА, и раскладок в каноне ТРИ
//
//	beforeTiers   перед ярусами            5 блоков: owner у account и обоих
//	                                       registry_*, subject у iam_user,
//	                                       member у iam_group
//	beforeVerbs   после ярусов, до действий 1 блок: ssh и console у
//	                                       compute_instance — УМОЛЧАНИЕ
//	afterVerbs    после действий           4 блока: member_remover у account,
//	                                       шесть отношений распоряжения у
//	                                       iam_user, realization_writer у
//	                                       compute_instance, announce_writer у
//	                                       nlb_network_load_balancer
//
// Пока место задавала постоянная рендера, побайтовая сверка объявляла
// расхождением то, о чём никто не решал: канон несёт все три раскладки законно.
type Relation struct {
	Name       string `yaml:"name"`
	Definition string `yaml:"definition"`
	// Position — МЕСТО отношения в блоке относительно порождаемых строк.
	// Пусто означает умолчание `beforeVerbs`.
	Position string `yaml:"position"`
}

// Verb — действие ресурса. Записывается ДВУМЯ формами:
//
//   - get                                   короткая: класс выводится из имени
//   - {name: addCidrBlocks, class: update}   длинная: класс назван
//
// Обычной структурой Go это не разбирается («cannot unmarshal !!str `get` into
// verb»), поэтому у типа свой UnmarshalYAML.
//
// # Отношение действия бывает шире умолчания, и это замер
//
// Умолчание — `[user, service_account, group#member] or super_admin`, и его
// несут 24 модульных блока канона из 27. Остальные три несут иное:
// `registry_repository` — `[user:*, user, service_account, group#member] or owner
// or super_admin` (анонимное чтение публичного репозитория), `registry_registry`
// — вывод от `owner`, `nlb_target_group` — вывод от другого ДЕЙСТВИЯ (`v_update`).
// Ни одно из трёх не порождалось умолчательной формой, а объявить `v_*`
// авторским отношением загрузчик не позволяет (имя порождается глаголом того же
// ресурса) — то есть возможность была объявлена и неисполнима ни одним входом.
type Verb struct {
	Name  string `yaml:"name"`
	Class string `yaml:"class"`
	// Subjects — состав субъектов ЭТОГО действия, когда он отличается от общего.
	// Ключ `subjects` РЕСУРСА сюда не относится: он сужает ярусы и действий не
	// трогает — замер по `vpc_address_pool`, где ярусы несут [user,
	// service_account], а его же `v_get` — полный набор с `group#member`.
	Subjects []string `yaml:"subjects"`
	// From — отношения, от которых действие выводится, в порядке правой части.
	// Пусто означает умолчание: супер-доступ.
	From []string `yaml:"from"`
	// Internal — действие живёт на ВНУТРЕННЕМ слушателе: арендатору оно
	// недоступно by construction (ban #6). Признак порождается из аннотаций
	// контрактов вместе с остальным разделом, а не пишется рукой, и сверяется с
	// каталогом прав: там та же плоскость видна приставкой `Internal` у имени
	// службы. Два объявления одной плоскости разошлись бы молча, поэтому сверка
	// обязательна, а не факультативна.
	Internal bool `yaml:"internal"`
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
			if key.Value != "name" && key.Value != "class" && key.Value != "internal" &&
				key.Value != "subjects" && key.Value != "from" {
				return fmt.Errorf("line %d: field %s not found in type verb", key.Line, key.Value)
			}
		}
		var raw struct {
			Name     string   `yaml:"name"`
			Class    string   `yaml:"class"`
			Internal bool     `yaml:"internal"`
			Subjects []string `yaml:"subjects"`
			From     []string `yaml:"from"`
		}
		if err := node.Decode(&raw); err != nil {
			return err
		}
		v.Name, v.Class, v.Internal = raw.Name, raw.Class, raw.Internal
		v.Subjects, v.From = raw.Subjects, raw.From
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
func validateResources(m *Manifest, doc *yaml.Node, referent TypeReferent) []error {
	var faults []error
	seen := map[string][]int{}

	// Типы, объявленные ЭТИМ документом, известны ДО суждения о его ресурсах:
	// иначе указатель на тип, объявленный НИЖЕ по документу, отвергался бы
	// порядком записей, а не по существу (тот же довод, что у двух ступеней
	// обхода в check.go).
	ownTypes, typeCollisions := declaredTypesOf(m)
	for _, c := range typeCollisions {
		faults = append(faults, linkFault{
			kind:  ErrObjectTypeCollision,
			coord: locate(doc, "resources", c.Second, "objectType"),
			detail: fmt.Sprintf("тип %q объявлен ресурсами resources[%d] и resources[%d] — "+
				"у типа объекта один владелец; отношение `v_<глагол>` адресуется именем типа, "+
				"поэтому права, выданные на одну строку, материализовались бы на объектах "+
				"другой, а какая из двух строк каталога переживёт применение, решал бы "+
				"порядок записей", c.Type, c.First, c.Second),
		})
	}

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

		faults = append(faults, validateResourceAnchors(m, r, doc, i, referent, ownTypes)...)
		faults = append(faults, validateResourceCascade(r, doc, i)...)
		faults = append(faults, validateResourceTiers(r, doc, i)...)
		faults = append(faults, validateResourceBaseRoles(r, doc, i)...)
		faults = append(faults, validateResourceVerbs(r, doc, i)...)
		faults = append(faults, validateResourceRelations(r, doc, i)...)
		faults = append(faults, validateResourceNotes(r, doc, i)...)
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
//
// # Что здесь судится о типе — ФОРМА и ВЛАДЕНИЕ, а НЕ членство (задача #2015)
//
// Членство в порождённой сборкой таблице снято как предикат: тип, объявленный
// доставленным манифестом, ЗАВОДИТСЯ этим объявлением, и спрашивать таблицу
// значило бы спрашивать у собственного ответа. Разбор — objecttype.go.
//
// Осталось два предиката, и они разные:
//
//	ФОРМА     судится при ЛЮБОМ референте: имя негодной формы отвергнет колонка
//	          каталога ключом, а строка `type` — допуск собранной модели, и
//	          отказ пришёл бы чужой полосой;
//	ВЛАДЕНИЕ  судится там, где таблица УЖЕ ПРОИЗВЕДЕНА ([ReferentShippedTable]):
//	          тип, который несёт образ, доставка не вправе присвоить другой
//	          строке. В проходе, который таблицу ПОРОЖДАЕТ ([ReferentCanon]),
//	          образа ещё нет — там тот же вопрос был бы вопросом к собственному
//	          ответу, и законный перенос типа с одной строки дерева на другую
//	          отвергался бы своей же будущей таблицей.
func validateResourceAnchors(m *Manifest, r *Resource, doc *yaml.Node, i int,
	referent TypeReferent, ownTypes map[string]struct{}) []error {
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
		if err, bad := objectTypeFault(m.Module, r.Name, r.ObjectType,
			referent.guardsImageOwnership()); bad {
			faults = append(faults, linkFault{
				kind:   errors.Unwrap(err),
				coord:  locate(doc, "resources", i, "objectType"),
				detail: strings.TrimPrefix(err.Error(), errors.Unwrap(err).Error()+": "),
			})
		}
	}

	faults = append(faults, validateResourceParents(r, doc, i, ownTypes)...)

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

// validateResourceParents — указатели ресурса: имя, тип и единственность формы.
//
// Находки собираются ВСЕ и по каждому указателю: названная первая заставила бы
// автора чинить их по одной, по прогону на каждую.
func validateResourceParents(r *Resource, doc *yaml.Node, i int, ownTypes map[string]struct{}) []error {
	var faults []error
	if len(r.Parents) == 0 {
		return []error{linkFault{
			kind:  ErrParentRequired,
			coord: locate(doc, "resources", i, "parents"),
			detail: fmt.Sprintf("указатель на объект-владелец не назван ни один; первый из них "+
				"есть якорь области, и принимаются якоря %s либо тип закрытой таблицы iam. "+
				"Без указателя блок модели не с чем связать, и каскад супер-доступа "+
				"выводить не от чего", strings.Join(scopeAnchors, ", ")),
		}}
	}

	seen := map[string]int{}
	for k := range r.Parents {
		p := &r.Parents[k]
		switch p.Name {
		case "":
			faults = append(faults, linkFault{
				kind:  ErrParentNameRequired,
				coord: locate(doc, "resources", i, "parents", k),
				detail: fmt.Sprintf("resources[%d].parents[%d].name: указатель не назвал себя — "+
					"безымянное отношение нечем адресовать в модели", i, k),
			})
		default:
			if first, dup := seen[p.Name]; dup {
				faults = append(faults, linkFault{
					kind:  ErrParentNameDuplicated,
					coord: locate(doc, "resources", i, "parents", k),
					detail: fmt.Sprintf("resources[%d].parents[%d].name: имя %q уже объявлено "+
						"указателем resources[%d].parents[%d] — одно отношение модели, "+
						"объявленное дважды, и верно из двух одно", i, k, p.Name, i, first),
				})
			} else {
				seen[p.Name] = k
			}
		}

		switch {
		case p.Type == "":
			faults = append(faults, linkFault{
				kind:  ErrParentUnknown,
				coord: locate(doc, "resources", i, "parents", k),
				detail: fmt.Sprintf("resources[%d].parents[%d].type: тип объекта не назван; "+
					"принимаются якорь области (%s) либо тип закрытой таблицы iam",
					i, k, strings.Join(scopeAnchors, ", ")),
			})
		case !parentTypeIsKnown(p.Type, ownTypes):
			faults = append(faults, linkFault{
				kind:  ErrParentUnknown,
				coord: locate(doc, "resources", i, "parents", k),
				detail: fmt.Sprintf("resources[%d].parents[%d].type: тип %q вне закрытого набора; "+
					"принимаются якорь области (%s) либо тип закрытой таблицы iam. Указатель на "+
					"тип, которого не существует, объявил бы отношение, по которому никто не "+
					"постучится", i, k, p.Type, strings.Join(scopeAnchors, ", ")),
			})
		}

		if p.long && p.Name != "" && p.Name == p.Type {
			faults = append(faults, linkFault{
				kind:  ErrParentFormRedundant,
				coord: locate(doc, "resources", i, "parents", k),
				detail: fmt.Sprintf("resources[%d].parents[%d]: имя равно типу (%q), а запись "+
					"длинная — одно значение, записанное двумя способами. Напишите строкой: "+
					"`parents: [%s]`", i, k, p.Name, p.Name),
			})
		}
	}
	return faults
}

// declaredRelationNames — имена ВСЕХ отношений, которые блок этого ресурса
// объявляет: указатели, супер-доступ, авторские отношения, ярусы и отношения
// действий.
//
// Один перечень на двоих: им проверяются источники яруса (ссылка на отношение,
// которого блок не несёт, — висячая) и якорь примечания. Второй такой перечень
// разошёлся бы с первым молча — на том самом виде отношения, о котором не знает.
func declaredRelationNames(r *Resource) map[string]struct{} {
	out := make(map[string]struct{}, len(r.Parents)+len(r.Tiers)+len(r.Relations)+len(r.Verbs)+1)
	for _, p := range r.Parents {
		if p.Name != "" {
			out[p.Name] = struct{}{}
		}
	}
	out[superAdminRelation] = struct{}{}
	for _, rel := range r.Relations {
		if rel.Name != "" {
			out[rel.Name] = struct{}{}
		}
	}
	tiers := r.Tiers
	if len(tiers) == 0 {
		for _, name := range DefaultTiers() {
			out[name] = struct{}{}
		}
	}
	for _, t := range tiers {
		if t.Name != "" {
			out[t.Name] = struct{}{}
		}
	}
	for _, v := range r.Verbs {
		// Внутреннее действие отношения не порождает (VerbProducesRelation),
		// поэтому и ссылаться на него в `from` нечем: источник, которого блок
		// не объявляет, даёт вердикт «нет» всегда, оставаясь на вид
		// полноценным.
		if v.Name != "" && VerbProducesRelation(v) {
			out[VerbRelationName(v.Name)] = struct{}{}
		}
	}
	return out
}

// sortedNames — имена перечня в детерминированном порядке: отказ, зависящий от
// обхода карты, читался бы по-разному от прогона к прогону.
func sortedNames(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// validateResourceCascade — термы каскада супер-доступа.
func validateResourceCascade(r *Resource, doc *yaml.Node, i int) []error {
	var faults []error
	if r.Cascade == nil {
		return nil
	}
	if len(r.Cascade) == 0 {
		return []error{linkFault{
			kind:  ErrSourceListEmpty,
			coord: locate(doc, "resources", i, "cascade"),
			detail: fmt.Sprintf("resources[%d].cascade: перечень термов объявлен пустым. Пустой "+
				"перечень неотличим от опущенного ключа, а блока без каскада канон не несёт: "+
				"опустите ключ, и каскад возьмёт умолчание `super_admin from <первый указатель>`", i),
		}}
	}
	declaredParents := make(map[string]struct{}, len(r.Parents))
	for _, p := range r.Parents {
		if p.Name != "" {
			declaredParents[p.Name] = struct{}{}
		}
	}
	for k, term := range r.Cascade {
		if term.Relation == "" || term.From == "" {
			faults = append(faults, linkFault{
				kind:  ErrCascadeTermIncomplete,
				coord: locate(doc, "resources", i, "cascade", k),
				detail: fmt.Sprintf("resources[%d].cascade[%d]: терм каскада есть пара "+
					"`<relation> from <from>`, и названы обе половины либо ни одной; "+
					"получено relation=%q, from=%q", i, k, term.Relation, term.From),
			})
			continue
		}
		if _, ok := declaredParents[term.From]; !ok {
			faults = append(faults, linkFault{
				kind:  ErrCascadeFromUnknown,
				coord: locate(doc, "resources", i, "cascade", k),
				detail: fmt.Sprintf("resources[%d].cascade[%d].from: указателя %q у ресурса нет; "+
					"объявлены: %s. Каскад по необъявленному указателю адресовал бы объект, "+
					"которого блок не несёт, — и вердикт по нему был бы «нет» всегда",
					i, k, term.From, strings.Join(sortedNames(declaredParents), ", ")),
			})
		}
	}
	return faults
}

// validateResourceTiers — имена ярусов и отношения, от которых они выводятся.
func validateResourceTiers(r *Resource, doc *yaml.Node, i int) []error {
	var faults []error
	known := declaredRelationNames(r)
	for k := range r.Tiers {
		t := &r.Tiers[k]
		if t.Name == "" {
			faults = append(faults, linkFault{
				kind:  ErrTierNameRequired,
				coord: locate(doc, "resources", i, "tiers", k),
				detail: fmt.Sprintf("resources[%d].tiers[%d].name: ярус не назвал себя — "+
					"безымянное отношение нечем адресовать в модели", i, k),
			})
			continue
		}
		if t.long && t.From == nil {
			faults = append(faults, linkFault{
				kind:  ErrTierFormRedundant,
				coord: locate(doc, "resources", i, "tiers", k),
				detail: fmt.Sprintf("resources[%d].tiers[%d]: длинная форма без ключа from "+
					"означает ровно то же, что короткая, — одно значение, записанное двумя "+
					"способами. Напишите именем: `- %s`", i, k, t.Name),
			})
		}
		if t.From != nil && len(t.From) == 0 {
			faults = append(faults, linkFault{
				kind:  ErrSourceListEmpty,
				coord: locate(doc, "resources", i, "tiers", k),
				detail: fmt.Sprintf("resources[%d].tiers[%d].from: перечень источников объявлен "+
					"пустым. Яруса без источника канон не несёт: опустите ключ, и ярус "+
					"выведется от предыдущего", i, k),
			})
		}
		for j, src := range t.From {
			if _, ok := known[src]; ok {
				continue
			}
			faults = append(faults, linkFault{
				kind:  ErrTierSourceUnknown,
				coord: locate(doc, "resources", i, "tiers", k),
				detail: fmt.Sprintf("resources[%d].tiers[%d].from[%d]: отношения %q блок не "+
					"объявляет; объявлены: %s. Вывод от несуществующего отношения даёт "+
					"вердикт «нет» всегда, оставаясь на вид полноценным ярусом",
					i, k, j, src, strings.Join(sortedNames(known), ", ")),
			})
		}
	}
	return faults
}

// validateResourceBaseRoles — базовые ярусные роли объявлены там, где их есть
// кому выдать.
//
// Базовая роль выдаётся АРЕНДАТОРУ, а внутренняя плоскость арендатору
// недоступна by construction (ban #6). Ресурс, у которого внутренние ВСЕ
// действия, порождал бы роль, дающую ноль прав и выглядящую действующей: и
// привязка создаётся, и роль перечисляется, и доступа нет. Отличить такую
// выдачу от неисполненной вызывающему нечем.
//
// Судится ОБЪЯВЛЕННОЕ, а не всякий ресурс с внутренними действиями: без
// признака ярусов нет вовсе, и запрещать тогда нечего.
func validateResourceBaseRoles(r *Resource, doc *yaml.Node, i int) []error {
	if !r.BaseRoles || len(r.Verbs) == 0 {
		return nil
	}
	for _, v := range r.Verbs {
		if !v.Internal {
			return nil
		}
	}
	return []error{linkFault{
		kind:  ErrBaseRolesWithoutTenantVerb,
		coord: locate(doc, "resources", i, "baseRoles"),
		detail: fmt.Sprintf("resources[%d].baseRoles: ресурс %q объявил базовые ярусные роли (%s), "+
			"а арендатору у него доступно НОЛЬ действий из %d — все они живут на внутреннем "+
			"слушателе. Такая роль выдаётся, перечисляется и не даёт ни одного права: снимите "+
			"признак либо назовите действие, доступное арендатору",
			i, r.Name, strings.Join(r.BaseRoleTiers(), ", "), len(r.Verbs)),
	}}
}

// validateResourceVerbs — имя и класс каждого действия; класс короткой формы
// восстанавливается ТУТ ЖЕ, единственным вызовом правила.
func validateResourceVerbs(r *Resource, doc *yaml.Node, i int) []error {
	var faults []error
	if len(r.Verbs) == 0 {
		faults = append(faults, linkFault{
			kind:  ErrResourceVerbsRequired,
			coord: locate(doc, "resources", i),
			detail: fmt.Sprintf("resources[%d].verbs: ресурс не назвал ни одного действия — "+
				"он не порождает НИ ОДНОГО отношения модели, и роль, назвавшая его в правиле, "+
				"выдаёт пустоту при действующей на вид привязке", i),
		})
	}
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
						"ТОЛЬКО при точном совпадении с одним из %s; назовите класс явно. Класс вне "+
						"пятёрки объявляется длинной формой: {name: %s, class: %s}",
						fmt.Sprintf("resources[%d].verbs[%d].class", i, j), v.Name,
						strings.Join(canonicalVerbClasses, " · "), v.Name, strings.ToLower(v.Name)),
				})
				continue
			}
			v.Class = class
		}
		faults = append(faults, validateVerbSources(r, v, doc, i, j)...)
		if accepted := verbClassesOf(r); !contains(accepted, v.Class) {
			faults = append(faults, linkFault{
				kind:  ErrVerbClassUnknown,
				coord: locate(doc, "resources", i, "verbs", j),
				detail: fmt.Sprintf("%s: класс %q вне набора, принимаемого ресурсом %q; принимаются: "+
					"%s. Набор перестал быть пятёркой: к каноническим классам добавлены отношения, "+
					"которые порождают собственные действия ресурса. Несёт ли тип это отношение на "+
					"самом деле — вопрос СУЩЕСТВА, и его задаёт применитель ролей со снимком "+
					"каталога в руках",
					fmt.Sprintf("resources[%d].verbs[%d].class", i, j), v.Class, r.Name,
					strings.Join(accepted, ", ")),
			})
		}
	}
	return faults
}

// validateVerbSources — состав субъектов и источники вывода одного действия.
//
// Источник обязан быть объявлен ЭТИМ ЖЕ блоком: вывод от несуществующего
// отношения даёт вердикт «нет» всегда, оставаясь на вид полноценным действием.
func validateVerbSources(r *Resource, v *Verb, doc *yaml.Node, i, j int) []error {
	var faults []error
	if v.Subjects != nil && len(v.Subjects) == 0 {
		faults = append(faults, linkFault{
			kind:  ErrSourceListEmpty,
			coord: locate(doc, "resources", i, "verbs", j),
			detail: fmt.Sprintf("resources[%d].verbs[%d].subjects: перечень субъектов объявлен "+
				"пустым. Пустой перечень неотличим от опущенного ключа, а отношения без "+
				"субъектов канон не несёт: опустите ключ, и состав возьмёт умолчание (%s)",
				i, j, strings.Join(defaultSubjectSet, ", ")),
		})
	}
	if v.From != nil && len(v.From) == 0 {
		faults = append(faults, linkFault{
			kind:  ErrSourceListEmpty,
			coord: locate(doc, "resources", i, "verbs", j),
			detail: fmt.Sprintf("resources[%d].verbs[%d].from: перечень источников объявлен "+
				"пустым. Опустите ключ, и действие выведется от супер-доступа", i, j),
		})
	}
	if len(v.From) == 0 {
		return faults
	}
	known := declaredRelationNames(r)
	for k, src := range v.From {
		if _, ok := known[src]; ok {
			continue
		}
		faults = append(faults, linkFault{
			kind:  ErrVerbSourceUnknown,
			coord: locate(doc, "resources", i, "verbs", j),
			detail: fmt.Sprintf("resources[%d].verbs[%d].from[%d]: отношения %q блок не "+
				"объявляет; объявлены: %s. Вывод от несуществующего отношения даёт вердикт "+
				"«нет» всегда, оставаясь на вид полноценным действием",
				i, j, k, src, strings.Join(sortedNames(known), ", ")),
		})
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
		// Определение судится ОТДЕЛЬНО от имени и до выхода по безымянному:
		// у отношения, лишённого обоих, автор обязан увидеть обе находки, а не
		// чинить их по одной, по прогону на каждую.
		if strings.TrimSpace(rel.Definition) == "" {
			faults = append(faults, linkFault{
				kind:  ErrRelationDefinitionRequired,
				coord: locate(doc, "resources", i, "relations", k),
				detail: fmt.Sprintf("resources[%d].relations[%d].definition: отношение объявлено "+
					"дословно и не сказало, чем оно является; отношение объявляют дословно ровно "+
					"затем, чтобы перегенерация модели его СОХРАНИЛА, а сохранять нечего", i, k),
			})
		}
		if rel.Name == "" {
			faults = append(faults, linkFault{
				kind:   ErrRelationNameRequired,
				coord:  locate(doc, "resources", i, "relations", k),
				detail: "отношение не назвало себя: безымянное отношение нечем адресовать в модели",
			})
			continue
		}
		if rel.Position != "" && !contains(relationPositions, rel.Position) {
			faults = append(faults, linkFault{
				kind:  ErrRelationPositionUnknown,
				coord: locate(doc, "resources", i, "relations", k),
				detail: fmt.Sprintf("resources[%d].relations[%d].position: место %q вне закрытого "+
					"набора; принимаются: %s. Место, которого рендер не знает, оставило бы "+
					"отношение там, где его никто не решал ставить",
					i, k, rel.Position, strings.Join(relationPositions, ", ")),
			})
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

// validateResourceNotes — якорь и текст каждого примечания.
func validateResourceNotes(r *Resource, doc *yaml.Node, i int) []error {
	var faults []error
	known := declaredRelationNames(r)
	seen := map[string]int{}
	for k := range r.Notes {
		n := &r.Notes[k]
		switch n.Before {
		case "":
			faults = append(faults, linkFault{
				kind:  ErrNoteAnchorRequired,
				coord: locate(doc, "resources", i, "notes", k),
				detail: fmt.Sprintf("resources[%d].notes[%d].before: примечание не назвало якоря — "+
					"печатать его было бы негде, и текст пропал бы молча; объявлены: %s",
					i, k, strings.Join(sortedNames(known), ", ")),
			})
		default:
			if _, ok := known[n.Before]; !ok {
				faults = append(faults, linkFault{
					kind:  ErrNoteAnchorUnknown,
					coord: locate(doc, "resources", i, "notes", k),
					detail: fmt.Sprintf("resources[%d].notes[%d].before: отношения %q блок не "+
						"объявляет; объявлены: %s. Примечание с якорем в пустоту не "+
						"напечаталось бы вовсе, а вызывающий получил бы успех",
						i, k, n.Before, strings.Join(sortedNames(known), ", ")),
				})
			}
			if first, dup := seen[n.Before]; dup {
				faults = append(faults, linkFault{
					kind:  ErrNoteAnchorDuplicated,
					coord: locate(doc, "resources", i, "notes", k),
					detail: fmt.Sprintf("resources[%d].notes[%d].before: якорь %q уже занят "+
						"примечанием resources[%d].notes[%d] — порядок между двумя текстами "+
						"на одном якоре ничем не задан; сведите их в одно примечание",
						i, k, n.Before, i, first),
				})
			} else {
				seen[n.Before] = k
			}
		}
		if strings.TrimSpace(n.Text) == "" {
			faults = append(faults, linkFault{
				kind:  ErrNoteTextRequired,
				coord: locate(doc, "resources", i, "notes", k),
				detail: fmt.Sprintf("resources[%d].notes[%d].text: примечание без текста печатать "+
					"нечего, а якорь его при этом объявлен занятым", i, k),
			})
			continue
		}
		faults = append(faults, validateNoteText(n, doc, i, k)...)
	}
	return faults
}

// validateNoteText — КАЖДАЯ строка текста начинается со знака комментария.
//
// Знак принадлежит тексту, а не рендеру (замер: отступ у всех 634 строк прозы
// модульных блоков — четыре пробела, формы `#текст` без пробела нет ни одной), и
// рендер строки есть чистое склеивание. Строка без знака перестала бы в блоке
// быть прозой: модель прочла бы её как объявление отношения — то есть примечание
// внесло бы в модель ПРАВО, о котором никто не решал.
func validateNoteText(n *Note, doc *yaml.Node, i, k int) []error {
	var faults []error
	for lineNo, line := range strings.Split(strings.TrimRight(n.Text, "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		faults = append(faults, linkFault{
			kind:  ErrNoteLineNotAComment,
			coord: locate(doc, "resources", i, "notes", k),
			detail: fmt.Sprintf("resources[%d].notes[%d].text, строка %d (якорь %q): %q не "+
				"начинается со знака комментария. Рендер воспроизводит текст ДОСЛОВНО, "+
				"поэтому такая строка стала бы в блоке объявлением отношения — примечание "+
				"внесло бы в модель право, о котором никто не решал",
				i, k, lineNo+1, n.Before, line),
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

// VerbProducesRelation — порождает ли действие отношение модели.
//
// Действие ВНУТРЕННЕЙ плоскости не порождает: арендатору оно недоступно by
// construction (ban #6), а отношение существует ровно затем, чтобы правом на
// него кого-то наделить.
//
// # Это ЗАМЕР, а не осторожность
//
// Перепись каталога прав (101 внутреннее действие шести модулей) даёт четыре
// вида гейта у внутреннего действия, и ни один не спрашивает отношения, которое
// породило бы ТОЛЬКО оно:
//
//   - ярус ОБЛАСТИ (`system_admin` / `system_viewer` на `cluster`) — 58; кортеж
//     на область пишет ярусная роль платформы, к разделу модуля отношения нет;
//   - отношение, которое УЖЕ порождает объявленное ТЕНАНТСКОЕ действие того же
//     ресурса (`v_update` / `v_get` на `vpc_address`) — 8; второго объявления
//     ему не нужно;
//   - собственное отношение ресурса (`editor`, `realization_writer`,
//     `announce_writer`, `session_reader`, `admin`, `viewer`);
//   - гейта нет вовсе — 18 освобождённых; правом такое действие не выдаётся ни
//     при каком разделе.
//
// # Чем это плохо, если порождать всё-таки
//
// Порождённое `v_internal…` — отношение, которого не спрашивает НИ ОДИН гейт.
// Право на него выдаётся, перечисляется в роли и не даёт доступа ни к чему;
// отличить такую выдачу от неисполненной вызывающему нечем. Тот же довод уже
// записан у базовых ярусов (`validateResourceBaseRoles`): ресурс, все действия
// которого внутренние, ярусов не получает именно поэтому.
//
// Вторым следствием побайтовая сверка канона (`make -C services/iam
// model-canon-check`) отвергала бы строку, которой в модели нет, — то есть
// объявить внутреннее действие было НЕЛЬЗЯ НИ ОДНИМ ВХОДОМ, пока правило не
// объявлено здесь.
//
// # Почему объявлено ОДИН раз
//
// Читателей ПЯТЬ, и они в разных пакетах. Здесь стояло «три» — перечень был
// неполон в день записи, и цена неполноты измерена на сведённом дереве: два
// ненайденных читателя вывели из манифестов каталог, которого модель не несёт.
//
//   - рендер блоков модели (`modelrender.Render`) — что попадает в `define v_*`;
//   - сверка соединения (`roleexport`) — набор отношений, на которых «едет»
//     незаявленная запись каталога;
//   - загрузчик (`declaredRelationNames`) — что вправе стоять в `from`;
//   - порождение таблиц типов (`authzmapgen.verbRelationsOf`) — набор `v_*`
//     ТИПА. Ключ здесь КЛАСС, а не имя, поэтому внутреннее действие втаскивало
//     в набор класс, которого у тенантских действий ресурса нет вовсе:
//     `vpc_address` и `storage_image` получали `v_create`, `iam_user` —
//     `v_update`, при том что модель ни одного не объявляет;
//   - деривация строк каталога (`modulecatalog.RowsOf`) — за какое действие
//     выдаётся право. Строка существует затем, чтобы правило роли резолвилось в
//     `v_<токен>`; у внутреннего действия его нет, и строка обещала бы выдачу,
//     которой не будет.
//
// Вторая копия правила расходится с первой МОЛЧА: обе стороны отвечают
// одинаково на тенантском действии, то есть на подавляющем большинстве входов.
// Именно так это и вышло — расхождение проявилось не на правке правила, а на
// сведении линии, когда манифесты впервые объявили внутреннее действие.
func VerbProducesRelation(v Verb) bool { return !v.Internal }
