// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_flush_parity_test.go — ГЕЙТ КЛАССА: полоса производителей
// очереди смены субъекта не пополняется МОЛЧА (задача #17, порт-ПОЛОВИНА
// семейства `subjectchangeflushparity`).
//
// Предмет, что именно разрез сделал с этим гейтом и чего половина НЕ держит —
// в шапке `subject_change_flush_parity.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// subject_change_flush_parity_injection_test.go.
package check_test

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// subjectChangeProducerRoster — ПЕРЕЧЕНЬ производителей очереди смены субъекта:
// координата → сколько обращений к производителю несёт файл.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ ПЕРЕЧЕНЬ, ЕСЛИ РАЗБОР И ТАК ИХ НАХОДИТ
//
// Разбор отвечает «сколько их сейчас». Перечень отвечает на другой вопрос —
// «решал ли кто-нибудь, что их стало больше», и ровно он и есть предмет
// семейства. Без перечня шестой производитель не оставляет в этом репозитории
// следа ВООБЩЕ: прогон остаётся зелёным, дифф — чистым, а вторая полоса
// (самосброс у края, `SelfFlushSetHome`) о пополнении не узнаёт.
//
// С перечнем добавление производителя краснит гейт и заставляет правку
// перечня — то есть кладёт в дифф строку, на которой обзор спрашивает: «краю
// сказали?». Больше этого один репозиторий здесь не может, и это сказано прямо.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЗДЕСЬ НЕТ НАМЕРЕННО: СООТВЕТСТВИЯ «ПРОИЗВОДИТЕЛЬ ↔ ИМЯ МЕТОДА»
//
// Производитель — обращение к методу порта в use-case; полное имя метода
// контракта ему не принадлежит и механически из него не выводится. Ведомость
// такого соответствия стала бы ТРЕТЬИМ местом об одном предмете, расходящимся
// молча. Предок отказался от неё по той же причине, и отказ здесь повторён, а
// не пересмотрен.
var subjectChangeProducerRoster = map[string]int{
	"internal/apps/kaname/api/access_binding/create.go": 1,
	"internal/apps/kaname/api/access_binding/delete.go": 1,
	"internal/apps/kaname/api/access_binding/revoke.go": 1,
	"internal/apps/kaname/api/group/add_member.go":      1,
	"internal/apps/kaname/api/group/remove_member.go":   1,
}

// TestSelfFlushCoversEveryProducerOfTheSubjectChangeQueue — имя сохранено
// ДОСЛОВНО с монорепо, хотя гейт судит половину предмета предка.
//
// Имя оставлено осознанно: семейство одно, и переименование сделало бы ссылки
// на него ложными молча. Чем именно эта половина отличается от предка, сказано
// в шапке извлечения и печатается переписью КАЖДОГО прогона — читатель узнаёт
// границу из вывода, а не из исходника.
func TestSelfFlushCoversEveryProducerOfTheSubjectChangeQueue(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	tree, err := treecorpus.NewTree(root)
	if err != nil {
		t.Fatalf("состав дерева не установлен: %v — «ноль находок» здесь означало бы "+
			"«ноль прочитанного»", err)
	}

	var (
		filesRead int
		producers []check.SubjectChangeProducer
	)
	for _, rel := range tree.SortedFiles() {
		if !check.IsSubjectChangeProducerFile(rel) {
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if readErr != nil {
			t.Fatalf("чтение %s: %v", rel, readErr)
		}
		filesRead++
		if !strings.Contains(string(b), check.EmitSubjectChangeSelector) {
			continue
		}
		p, perr := check.SubjectChangeProducersIn(rel, string(b))
		if perr != nil {
			t.Fatalf("%v — файл не разобран, и его молчание ничего не значит", perr)
		}
		producers = append(producers, p...)
	}

	// ── премисы: «ноль находок» отличимо от «ноль прочитанного» ─────────────
	if filesRead == 0 {
		t.Fatalf("под %s не прочитано НИ ОДНОГО непроверочного файла — слой переехал, "+
			"и обход пуст: вердикт беспредметен", check.SubjectChangeProducerRootRel)
	}
	if len(producers) == 0 {
		t.Fatalf("обращений к %s не найдено НИ ОДНОГО при %d прочитанных файлах — либо очередь "+
			"перестала писаться вовсе, либо распознаватель ослеп; и то и другое означает, "+
			"что «полосы сошлись» получено даром",
			check.EmitSubjectChangeSelector, filesRead)
	}

	// ── вторая полоса: измеренное ОТСУТСТВИЕ, а не молчание ────────────────
	//
	// Спрашивается у СОСТАВА этого дерева, а не у диска: вердикт обязан быть
	// свойством коммита. Непустой ответ означал бы, что край переехал сюда, —
	// и тогда половина обязана стать целым, а не остаться половиной.
	selfFlushHere := 0
	for _, rel := range tree.SortedFiles() {
		if !strings.HasSuffix(rel, ".go") {
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if readErr != nil {
			t.Fatalf("чтение %s: %v", rel, readErr)
		}
		declares, derr := check.DeclaresSelfFlushSet(rel, string(b))
		if derr != nil {
			t.Fatalf("%v — файл не разобран, и его молчание ничего не значит", derr)
		}
		if declares {
			selfFlushHere++
		}
	}

	coords := make([]string, 0, len(producers))
	for _, p := range producers {
		coords = append(coords, p.String())
	}
	sort.Strings(coords)

	// Перепись печатает ОБЕ величины полос. Одна скрывает ровно тот случай,
	// ради которого семейство заведено.
	t.Logf("перепись: файлов слоя %s прочитано %d · производителей очереди найдено %d (%s) · "+
		"перечень объявляет %d в %d файлах · набор самосброса %q в этом дереве: файлов %d "+
		"(его дом — %s, и оттуда он не читается: вердикт обязан быть свойством коммита, "+
		"а не того, что лежит в кеше машины)",
		check.SubjectChangeProducerRootRel, filesRead, len(producers), strings.Join(coords, ", "),
		check.SubjectChangeRosterTotal(subjectChangeProducerRoster), len(subjectChangeProducerRoster),
		check.SelfFlushSetName, selfFlushHere, check.SelfFlushSetHome)

	if selfFlushHere > 0 {
		t.Errorf("набор самосброса %q встречается в ЭТОМ дереве (%d файлов) — вторая полоса "+
			"приехала сюда, и гейт обязан перестать быть половиной: сверяйте полосы МЕЖДУ "+
			"СОБОЙ, как это делал предок, а не перечень с разбором",
			check.SelfFlushSetName, selfFlushHere)
	}

	diff := check.CompareSubjectChangeRoster(producers, subjectChangeProducerRoster)
	for _, u := range diff.Undeclared {
		t.Errorf("полоса производителей пополнилась, и перечень об этом не знает: %s\n"+
			"  Реплика, обслужившая мутацию, отвечает по закешированному вердикту до следующего "+
			"чтения очереди — то есть по ОТОЗВАННОМУ праву, и дольше всего там, где пользователь "+
			"только что нажал «отозвать». Вторая полоса — набор %q в %s — живёт в ДРУГОМ "+
			"репозитории и о пополнении не узнаёт ни от сборки, ни от обзора диффа.\n"+
			"  Впишите производителя в перечень ЭТИМ ЖЕ изменением и пополните набор самосброса "+
			"у края своим.",
			u, check.SelfFlushSetName, check.SelfFlushSetHome)
	}
	for _, s := range diff.Stale {
		t.Errorf("записи перечня нечего называть: %s\n"+
			"  Перечень обязан истекать сам: запись, пережившая своего производителя, "+
			"остаётся на вид рабочей и молча расширяет то, что гейт считает объявленным.", s)
	}
}
