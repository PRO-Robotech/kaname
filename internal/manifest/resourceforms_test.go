// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package manifest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// resourceforms_test.go — ФОРМЫ раздела `resources`, заведённые ради блоков,
// которые канон несёт сегодня и которые прежняя форма не выражала ни при каком
// входе (#1845, #1846, #1853, #1858, #1860).
//
// Каждая проба здесь — ПАРА: отрицание (загрузчик отвергает и называет поле и
// правило) плюс положительный контроль (законный близнец проходит). Отрицание без
// пары зеленеет на форме, отвергающей всё, и потому утверждением не является.

// resourceDoc — манифест с ОДНИМ ресурсом vpc, куда подставляется проверяемый кусок.
func resourceDoc(body string) string {
	return "apiVersion: iam/v1\nmodule: vpc\nresources:\n  - name: network\n" +
		"    objectType: vpc_network\n    producer: derived\n" + body +
		"    verbs: [get]\n"
}

// mustRefuse требует отказа с названной причиной и с каждым из названных слов в
// тексте: отказ, не называющий поля и правила, посылает автора искать опечатку.
func mustRefuse(t *testing.T, doc string, kind error, mentions ...string) {
	t.Helper()
	_, err := manifest.Load([]byte(doc))
	if err == nil {
		t.Fatalf("вход принят, хотя должен быть отвергнут:\n%s", doc)
	}
	if !errors.Is(err, kind) {
		t.Fatalf("отказ не отнесён к своей причине (%v): %v", kind, err)
	}
	for _, m := range mentions {
		if !strings.Contains(err.Error(), m) {
			t.Errorf("отказ не называет %q: %v", m, err)
		}
	}
}

// mustAccept — законный близнец: без него отрицание выше ничего не утверждает.
func mustAccept(t *testing.T, doc string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("парный положительный отвергнут: %v\n%s", err, doc)
	}
	return m
}

// ── Указатели: имя и тип раздельно (#1860), их бывает несколько (#1858) ──────

// TestMODMR28ParentTypeMayBeAClosedTableType — тип указателя расширен ТИПАМИ, а
// не якорями области.
//
// Замер: `registry_repository` указывает на `registry_registry`, который областью
// выдачи не является ни при каком написании. Якорь области остаётся закрытым
// набором и здесь не расширяется — расширяется словарь ТИПОВ.
func TestMODMR28ParentTypeMayBeAClosedTableType(t *testing.T) {
	m := mustAccept(t, "apiVersion: iam/v1\nmodule: registry\nresources:\n  - name: repository\n"+
		"    objectType: registry_repository\n    producer: authored\n"+
		"    parents:\n      - {name: parent, type: registry_registry}\n    verbs: [get]\n")
	p := m.Resources[0].Parents
	if len(p) != 1 || p[0].Name != "parent" || p[0].Type != "registry_registry" {
		t.Fatalf("имя и тип указателя не разделены: %+v", p)
	}

	// Отрицание: тип вне обоих словарей.
	mustRefuse(t, "apiVersion: iam/v1\nmodule: registry\nresources:\n  - name: repository\n"+
		"    objectType: registry_repository\n    producer: authored\n"+
		"    parents:\n      - {name: parent, type: registry_repositoryz}\n    verbs: [get]\n",
		manifest.ErrParentUnknown,
		"resources[0].parents[0].type", "registry_repositoryz", "project", "account", "cluster")
}

// TestMODMR28TheLongParentFormIsRefusedWhenNameEqualsType — одно значение
// выразимо ровно ОДНИМ способом.
//
// `{name: project, type: project}` и `project` дают побайтово одну и ту же строку
// блока. Приняв обе, раздел завёл бы два написания одного значения — тот самый
// класс, который манифест ловит у остальных ключей.
func TestMODMR28TheLongParentFormIsRefusedWhenNameEqualsType(t *testing.T) {
	mustRefuse(t, resourceDoc("    parents:\n      - {name: project, type: project}\n"),
		manifest.ErrParentFormRedundant,
		"resources[0].parents[0]", "parents: [project]")

	// Законный близнец: та же пара, записанная короткой формой.
	mustAccept(t, resourceDoc("    parents: [project]\n"))
	// И длинная форма там, где имя и тип РАЗЛИЧАЮТСЯ, остаётся законной.
	mustAccept(t, "apiVersion: iam/v1\nmodule: registry\nresources:\n  - name: repository\n"+
		"    objectType: registry_repository\n    producer: authored\n"+
		"    parents:\n      - {name: parent, type: registry_registry}\n    verbs: [get]\n")
}

// TestMODMR29DuplicateParentNameNamesBothIndices — два указателя под одним именем
// объявили бы одно отношение модели дважды.
func TestMODMR29DuplicateParentNameNamesBothIndices(t *testing.T) {
	mustRefuse(t, resourceDoc("    parents:\n      - project\n      - {name: project, type: account}\n"),
		manifest.ErrParentNameDuplicated,
		"resources[0].parents[1].name", "resources[0].parents[0]")

	// Законный близнец: два РАЗНЫХ имени — так написан `iam_access_binding`.
	mustAccept(t, resourceDoc("    parents: [project, account, cluster]\n"))
}

// TestMODMR29ParentsAreRequired — ресурс без указателя не с чем связать, и каскад
// супер-доступа выводить не от чего.
func TestMODMR29ParentsAreRequired(t *testing.T) {
	mustRefuse(t, resourceDoc(""), manifest.ErrParentRequired, "resources[0].parents")
	mustRefuse(t, resourceDoc("    parents: []\n"), manifest.ErrParentRequired, "resources[0].parents")
	mustAccept(t, resourceDoc("    parents: [project]\n"))
}

// TestMODMR29AnUnknownKeyInsideAParentIsRefusedWithItsLine — строгость к
// неизвестному ключу не теряется внутри собственного разбора формы.
//
// Библиотека не проносит `Decoder.KnownFields(true)` внутрь UnmarshalYAML — то же
// измерено у действия, — поэтому ключ сверяется до разбора, а отказ называет ключ
// и номер строки ровно как это делает библиотека.
func TestMODMR29AnUnknownKeyInsideAParentIsRefusedWithItsLine(t *testing.T) {
	_, err := manifest.Load([]byte(resourceDoc("    parents:\n      - {name: project, typ: project}\n")))
	if err == nil {
		t.Fatalf("неизвестный ключ указателя принят")
	}
	for _, want := range []string{"field typ not found in type parent", "line 8"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}
	// Законный близнец: тот же отображённый указатель с ВЕРНЫМ ключом.
	mustAccept(t, "apiVersion: iam/v1\nmodule: registry\nresources:\n  - name: repository\n"+
		"    objectType: registry_repository\n    producer: authored\n"+
		"    parents:\n      - {name: parent, type: registry_registry}\n    verbs: [get]\n")
}

// ── Каскад и ярусы: ссылка обязана иметь предмет (#1858) ─────────────────────

// TestMODMR30ACascadeTermDerivesFromADeclaredParent — вывод по указателю,
// которого блок не объявляет, дал бы вердикт «нет» всегда.
func TestMODMR30ACascadeTermDerivesFromADeclaredParent(t *testing.T) {
	mustRefuse(t, resourceDoc("    parents: [project]\n"+
		"    cascade:\n      - {relation: any_admin, from: cluster}\n"),
		manifest.ErrCascadeFromUnknown,
		"resources[0].cascade[0].from", "cluster", "project")

	// Законный близнец: тот же терм при объявленном указателе.
	mustAccept(t, resourceDoc("    parents: [project, cluster]\n"+
		"    cascade:\n      - {relation: any_admin, from: cluster}\n"))
}

// TestMODMR30AHalfNamedCascadeTermIsRefused — терм есть ПАРА, и названы обе
// половины либо ни одной.
func TestMODMR30AHalfNamedCascadeTermIsRefused(t *testing.T) {
	mustRefuse(t, resourceDoc("    parents: [project]\n"+
		"    cascade:\n      - {relation: admin}\n"),
		manifest.ErrCascadeTermIncomplete, "resources[0].cascade[0]", "relation")
	mustRefuse(t, resourceDoc("    parents: [project]\n"+
		"    cascade:\n      - {from: project}\n"),
		manifest.ErrCascadeTermIncomplete, "resources[0].cascade[0]", "from")
	mustAccept(t, resourceDoc("    parents: [project]\n"+
		"    cascade:\n      - {relation: admin, from: project}\n"))
}

// TestMODMR30AnEmptyCascadeIsRefused — пустой перечень неотличим от опущенного
// ключа, а блока без каскада канон не несёт.
func TestMODMR30AnEmptyCascadeIsRefused(t *testing.T) {
	mustRefuse(t, resourceDoc("    parents: [project]\n    cascade: []\n"),
		manifest.ErrSourceListEmpty, "resources[0].cascade", "опустите ключ")
	// Законный близнец: ключ опущен — каскад берёт умолчание.
	mustAccept(t, resourceDoc("    parents: [project]\n"))
}

// TestMODMR31ATierSourceMustBeDeclaredByTheBlock — ярус, выведенный от
// несуществующего отношения, остаётся на вид полноценным и не даёт ничего.
func TestMODMR31ATierSourceMustBeDeclaredByTheBlock(t *testing.T) {
	mustRefuse(t, resourceDoc("    parents: [project]\n"+
		"    tiers:\n      - {name: admin, from: [owner, super_admin]}\n      - editor\n      - viewer\n"),
		manifest.ErrTierSourceUnknown,
		"resources[0].tiers[0].from[0]", "owner", "super_admin")

	// Законный близнец: то же отношение, объявленное авторским.
	mustAccept(t, resourceDoc("    parents: [project]\n"+
		"    relations:\n      - {name: owner, definition: \"[user]\"}\n"+
		"    tiers:\n      - {name: admin, from: [owner, super_admin]}\n      - editor\n      - viewer\n"))
}

// TestMODMR31TheLongTierFormIsRefusedWithoutOwnSources — длинная форма без
// ключа from означает ровно то же, что короткая.
func TestMODMR31TheLongTierFormIsRefusedWithoutOwnSources(t *testing.T) {
	mustRefuse(t, resourceDoc("    parents: [project]\n"+
		"    tiers:\n      - {name: admin}\n      - viewer\n"),
		manifest.ErrTierFormRedundant, "resources[0].tiers[0]", "- admin")
	mustRefuse(t, resourceDoc("    parents: [project]\n"+
		"    tiers:\n      - {name: admin, from: []}\n      - viewer\n"),
		manifest.ErrSourceListEmpty, "resources[0].tiers[0].from")
	mustAccept(t, resourceDoc("    parents: [project]\n    tiers: [admin, viewer]\n"))
}

// ── Класс действия берётся из набора ТИПА, а не из пятёрки (#1853) ───────────

// targetGroupDoc — манифест балансировщика с ресурсом, чей ТИП объявляет набор
// шире канонического CRUD: `nlb_target_group` несёт `v_addtargets` и
// `v_removetargets` сверх четырёх.
//
// Токен модуля — `loadbalancer`, а каталог сервиса зовётся `nlb`: два разных
// словаря, и манифест, названный по каталогу, набором модулей отвергается.
func targetGroupDoc(verbs string) string {
	return "apiVersion: iam/v1\nmodule: loadbalancer\nresources:\n  - name: targetGroups\n" +
		"    objectType: nlb_target_group\n    parents: [project]\n    producer: derived\n" +
		"    verbs: " + verbs + "\n"
}

// TestMODMR32AVerbClassOutsideTheFiveIsExpressible — класс действия вне пятёрки
// выразим длинной формой.
//
// Замер, из которого проба выведена: закрытый набор классов загрузчика был
// пятёркой, тип `nlb_target_group` объявляет ШЕСТЬ отношений действия, а запись
// каталога спрашивает `v_addtargets`. Действие `addTargets` не выражалось ни
// одним входом: длинная форма давала «класс вне закрытого набора», короткая —
// «класс не выводится», а любой другой класс писал бы не то отношение, которого
// требует гейт.
func TestMODMR32AVerbClassOutsideTheFiveIsExpressible(t *testing.T) {
	m := mustAccept(t, targetGroupDoc(
		"[get, list, update, delete, {name: addTargets, class: addtargets}]"))
	verbs := m.Resources[0].Verbs
	last := verbs[len(verbs)-1]
	if last.Name != "addTargets" || last.Class != "addtargets" {
		t.Fatalf("класс действия вне пятёрки прочитан неверно: %+v", last)
	}
}

// TestMODMR32TheShortFormStillDerivesOnlyTheFive — контроль в обратную сторону
// по КОРОТКОЙ форме.
//
// Правило «класс из имени» осталось одним и прежним: оно берёт класс ТОЛЬКО при
// точном совпадении с каноническим. Расширив его на собственные действия
// ресурса, загрузчик вывел бы у `listOperations` класс `listoperations`, тогда
// как гейт этого действия спрашивает `v_list`, — то есть правило стало бы
// производить неверный класс молча.
func TestMODMR32TheShortFormStillDerivesOnlyTheFive(t *testing.T) {
	mustRefuse(t, targetGroupDoc("[get, list, update, delete, addTargets]"),
		manifest.ErrVerbClassNotDerivable,
		"resources[0].verbs[4].class", "addTargets", "{name: addTargets, class: addtargets}")

	// Законный близнец: та же пятёрка короткой формой проходит.
	mustAccept(t, targetGroupDoc("[get, list, update, delete]"))
}

// TestMODMR32AClassNoActionOfThisResourceProducesIsRefused — контроль в обратную
// сторону по ДЛИННОЙ форме.
//
// Набор принимаемых классов есть канонические пять ПЛЮС отношения, которые
// порождают собственные действия ЭТОГО ресурса. Класс, которого не порождает ни
// одно из них, отвергается с перечнем годных.
//
// Несёт ли тип это отношение на самом деле — вопрос СУЩЕСТВА, и его задаёт
// применитель ролей (`roleexport.judgeVerb`) со снимком каталога в руках:
// загрузчик снимка не имеет и каталожный факт у литерала не спрашивает
// (kacho#1816, гейт `internal/check` `TestIAMCT2_LiteralIsNotAReadSource`).
func TestMODMR32AClassNoActionOfThisResourceProducesIsRefused(t *testing.T) {
	mustRefuse(t, targetGroupDoc("[get, {name: addTargets, class: frobnicate}]"),
		manifest.ErrVerbClassUnknown,
		"resources[0].verbs[1].class", "frobnicate", "addtargets", "targetGroups")

	// Класс соседнего действия, которого этот ресурс НЕ объявляет, — тоже отказ.
	mustRefuse(t, targetGroupDoc("[get, {name: addTargets, class: removetargets}]"),
		manifest.ErrVerbClassUnknown,
		"resources[0].verbs[1].class", "removetargets")

	// Законный близнец: объявите оба действия — и класс каждого принимается.
	mustAccept(t, targetGroupDoc("[get, {name: addTargets, class: addtargets}, "+
		"{name: removeTargets, class: removetargets}]"))
	// И канонический класс принимается у всякого ресурса.
	mustAccept(t, resourceDoc("    parents: [project]\n"))
}

// ── Источники и субъекты действия (#1846) ────────────────────────────────────

// TestMODMR33AVerbSourceMustBeDeclaredByTheBlock — действие, выведенное от
// несуществующего отношения, остаётся на вид полноценным и не даёт ничего.
func TestMODMR33AVerbSourceMustBeDeclaredByTheBlock(t *testing.T) {
	mustRefuse(t, resourceDoc("    parents: [project]\n")[:len(resourceDoc("    parents: [project]\n"))-
		len("    verbs: [get]\n")]+"    verbs:\n      - {name: get, from: [owner]}\n",
		manifest.ErrVerbSourceUnknown,
		"resources[0].verbs[0].from[0]", "owner", "super_admin")

	// Законный близнец: то же отношение, объявленное авторским.
	mustAccept(t, resourceDoc("    parents: [project]\n")[:len(resourceDoc("    parents: [project]\n"))-
		len("    verbs: [get]\n")]+"    relations:\n      - {name: owner, definition: \"[user]\"}\n"+
		"    verbs:\n      - {name: get, from: [owner, super_admin]}\n")
}

// TestMODMR33AnEmptySourceOrSubjectListIsRefused — пустой перечень неотличим от
// опущенного ключа, а отношения без субъектов и без источников канон не несёт.
func TestMODMR33AnEmptySourceOrSubjectListIsRefused(t *testing.T) {
	head := resourceDoc("    parents: [project]\n")
	head = head[:len(head)-len("    verbs: [get]\n")]

	mustRefuse(t, head+"    verbs:\n      - {name: get, from: []}\n",
		manifest.ErrSourceListEmpty, "resources[0].verbs[0].from", "пустым")
	mustRefuse(t, head+"    verbs:\n      - {name: get, subjects: []}\n",
		manifest.ErrSourceListEmpty, "resources[0].verbs[0].subjects", "опустите ключ")

	// Законный близнец: ключи опущены — состав и источник берут умолчание.
	mustAccept(t, head+"    verbs: [get]\n")
	mustAccept(t, head+"    verbs:\n      - {name: get, subjects: [\"user:*\", user]}\n")
}

// ── Место авторского отношения (#1862) ───────────────────────────────────────

// TestMODMR34ARelationPlaceOutsideTheClosedSetIsRefused — место, которого рендер
// не знает, оставило бы отношение там, где его никто не решал ставить.
func TestMODMR34ARelationPlaceOutsideTheClosedSetIsRefused(t *testing.T) {
	head := resourceDoc("    parents: [project]\n")
	head = head[:len(head)-len("    verbs: [get]\n")]

	mustRefuse(t, head+"    relations:\n      - {name: owner, definition: \"[user]\", position: last}\n"+
		"    verbs: [get]\n",
		manifest.ErrRelationPositionUnknown,
		"resources[0].relations[0].position", "last", "beforeTiers", "beforeVerbs", "afterVerbs")

	// Законные близнецы: все три места и опущенный ключ.
	for _, place := range append(manifest.RelationPositions(), "") {
		body := ", position: " + place
		if place == "" {
			body = ""
		}
		mustAccept(t, head+"    relations:\n      - {name: owner, definition: \"[user]\""+body+"}\n"+
			"    verbs: [get]\n")
	}
}

// ── Примечание с якорем (#1845) ──────────────────────────────────────────────

// TestMODMR35ANoteAnchorMustBeDeclaredByTheBlock — примечание с якорем в пустоту
// не напечаталось бы вовсе, а вызывающий получил бы успех.
func TestMODMR35ANoteAnchorMustBeDeclaredByTheBlock(t *testing.T) {
	head := resourceDoc("    parents: [project]\n")
	head = head[:len(head)-len("    verbs: [get]\n")]

	mustRefuse(t, head+"    notes:\n      - {before: owner, text: '# разбор'}\n    verbs: [get]\n",
		manifest.ErrNoteAnchorUnknown,
		"resources[0].notes[0].before", "owner", "super_admin", "v_get")

	// Законные близнецы: якорями служат указатель, супер-доступ, ярус, действие
	// и авторское отношение — все пять видов, которыми канон пользуется.
	for _, anchor := range []string{"project", "super_admin", "viewer", "v_get", "owner"} {
		mustAccept(t, head+"    relations:\n      - {name: owner, definition: \"[user]\"}\n"+
			"    notes:\n      - {before: "+anchor+", text: '# разбор'}\n    verbs: [get]\n")
	}
}

// TestMODMR35TwoNotesOnOneAnchorAreRefused — порядок между двумя текстами на
// одном якоре ничем не задан.
func TestMODMR35TwoNotesOnOneAnchorAreRefused(t *testing.T) {
	head := resourceDoc("    parents: [project]\n")
	head = head[:len(head)-len("    verbs: [get]\n")]

	mustRefuse(t, head+"    notes:\n      - {before: project, text: '# первый'}\n"+
		"      - {before: project, text: '# второй'}\n    verbs: [get]\n",
		manifest.ErrNoteAnchorDuplicated,
		"resources[0].notes[1].before", "resources[0].notes[0]")

	// Законный близнец: два примечания на РАЗНЫХ якорях.
	mustAccept(t, head+"    notes:\n      - {before: project, text: '# первый'}\n"+
		"      - {before: v_get, text: '# второй'}\n    verbs: [get]\n")
}

// TestMODMR35ANoteWithoutTextIsRefused — печатать нечего, а якорь при этом
// объявлен занятым.
func TestMODMR35ANoteWithoutTextIsRefused(t *testing.T) {
	head := resourceDoc("    parents: [project]\n")
	head = head[:len(head)-len("    verbs: [get]\n")]

	mustRefuse(t, head+"    notes:\n      - {before: project, text: \"   \"}\n    verbs: [get]\n",
		manifest.ErrNoteTextRequired, "resources[0].notes[0].text")
	mustAccept(t, head+"    notes:\n      - {before: project, text: '# разбор'}\n    verbs: [get]\n")
}

// TestC08ANoteLineWithoutACommentSignIsRefused — инъекция C-08: строка текста
// примечания без решётки отвергается синхронно, с якорем и номером строки.
//
// Рендер воспроизводит текст ДОСЛОВНО, поэтому такая строка стала бы в блоке
// объявлением отношения — примечание внесло бы в модель право, о котором никто
// не решал.
//
// Законный близнец обязателен ВДВОЙНЕ: все 634 строки прозы модульных блоков
// канона начинаются с решётки, и без него норма закрывалась бы проверкой,
// отвергающей ВСЯКИЙ текст, — то есть отрицание зеленело бы на пустом множестве.
func TestC08ANoteLineWithoutACommentSignIsRefused(t *testing.T) {
	head := resourceDoc("    parents: [project]\n")
	head = head[:len(head)-len("    verbs: [get]\n")]

	mustRefuse(t, head+"    notes:\n      - before: project\n        text: |\n"+
		"          # первая строка\n          define admin: [user:*]\n    verbs: [get]\n",
		manifest.ErrNoteLineNotAComment,
		"resources[0].notes[0].text", "строка 2", "project", "define admin: [user:*]")

	// Законный близнец: та же строка С решёткой — принимается.
	mustAccept(t, head+"    notes:\n      - before: project\n        text: |\n"+
		"          # первая строка\n          # define admin: [user:*]\n    verbs: [get]\n")
	// И одинокая решётка (76 таких строк в каноне) — тоже.
	mustAccept(t, head+"    notes:\n      - before: project\n        text: |\n"+
		"          # первая\n          #\n          # третья\n    verbs: [get]\n")
}
