// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"os"
	"path"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestTheEnvelopeIsBuiltOnlyByTheCompositionRootOnTheWallClockMeter — страж
// корня композиции (приёмка Ф3, Р17 «Мера прогона», Ф3-53): в не-тестовом
// дереве службы огибающую строит ОДНО место — композиционный корень, — и мера
// в нём — мера настенных часов. Иная мера в не-тестовом файле — у места
// построения, записью поля меры после построения либо подставным типом на месте
// порта — и второе построение — красное с координатой; мера назначенной
// стоимости в файле пробы — молчание. Вывод печатает перепись; пустой обход и
// несостоявшаяся посылка — отказ, а не «находок ноль». Способность упасть
// доказана инъекцией: envelope_composition_root_injection_test.go.
func TestTheEnvelopeIsBuiltOnlyByTheCompositionRootOnTheWallClockMeter(t *testing.T) {
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
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева: %v", err)
	}
	spec := check.EnvelopeCompositionRootSpec()
	verdict, err := check.JudgeEnvelopeCompositionRoot(tree, spec)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Logf("перепись: %s", verdict.Summary())

	for _, f := range verdict.Findings {
		t.Errorf("страж корня композиции: %s", f)
	}
	// Положительный контроль того же прогона: законное место найдено. Без него
	// «находок 0» не отличалось бы от распознавателя, не узнавшего ничего.
	if len(verdict.Sites) != 1 {
		t.Fatalf("ожидалось ровно одно построение огибающей — вызов конструктора в %s на мере настенных часов; найдено %d",
			spec.RootDir, len(verdict.Sites))
	}
	site := verdict.Sites[0]
	if path.Dir(site.Rel) != spec.RootDir || site.Form != check.EnvelopeSiteCall || !site.WallClock {
		t.Errorf("единственное построение — не вызов конструктора в %s на мере настенных часов: %s", spec.RootDir, site)
	}
	// Те же положительные контроли для распознавателей записи поля меры и
	// подставного типа: законная запись поля в конструкторе и методы порта у
	// огибающей дома узнаны. Без них «записей 0» и «реализаций 0» не отличались
	// бы от распознавателя, не читающего ни поля, ни методов.
	if len(verdict.Census.LawfulMeterWrites) == 0 {
		t.Errorf("законная запись поля меры `%s` в конструкторе не узнана — распознаватель записей поля слеп", verdict.Census.MeterField)
	}
	if verdict.Census.PortMethods == 0 || verdict.Census.PortMethodsAtHome != verdict.Census.PortMethods {
		t.Errorf("методов порта %s %d, из них узнано у огибающей дома %d — распознаватель подставного типа слеп",
			verdict.Census.Port, verdict.Census.PortMethods, verdict.Census.PortMethodsAtHome)
	}
}
