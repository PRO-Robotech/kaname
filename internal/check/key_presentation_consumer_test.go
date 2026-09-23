// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_presentation_consumer_test.go — ПРОБА ПОСЫЛКИ исключения оси «заведено»
// (`internal/apps/kaname/api/humansession/completed_login.go`, §«Ключи доступа в
// ось «заведено» НЕ ВХОДЯТ»; приёмка Ф12 Р7 ред. 11; задача
// PRO-Robotech/kaname#287).
//
// Ось «заведено» ключей доступа не видит. Это безопасно, пока ни одна полоса не
// поднимает уровень сессии утверждением ключа: тогда ключ не бывает фактором,
// до уровня которого вход обязан дойти. Событие, снимающее посылку, — появление
// в прод-коде ПОТРЕБИТЕЛЯ предъявления ключа; эта проба краснеет на нём.
//
// Способность упасть и смолчать — key_presentation_consumer_injection_test.go.
package check_test

import (
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// keyPresentationLawfulUses — места вне словаря, где предъявление ключа
// берётся законно. Ключ — путь от корня модуля.
//
// Перечень закрыт и самоистекает: запись, которой нечего исключать, — находка.
var keyPresentationLawfulUses = map[string]check.KeyPresentationLawfulUse{
	// ПРОИЗВОДИТЕЛЬ: проверка утверждения строит предъявление для своего
	// ответа (Ф7-06). Уровня сессии она не пишет, а край получает от неё флаги,
	// а не уровень; поле ответа сегодня не читает никто.
	"internal/apps/kaname/api/access_keys/finish_assertion.go": {
		Func: "Execute",
		Why:  "производитель: проверка утверждения строит предъявление для своего ответа",
	},
	// ДЕКОДЕР слов, УЖЕ записанных в сессию, в предъявления правила уровня.
	// Ключа он ни от кого не принимает: слово `webauthn` доедет до него, только
	// если его запишет потребитель, — а потребитель судится этой пробой.
	"internal/apps/kaname/api/humansession/change_password.go": {
		Func: "presentationsOf",
		Why:  "декодер слов записи сессии в предъявления правила уровня",
	},
}

func TestAccessKeyPresentationHasNoSessionLevelConsumer(t *testing.T) {
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
	corpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}

	findings, census, err := check.JudgeKeyPresentationConsumers(corpus, keyPresentationLawfulUses)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	switch {
	case census.HomeDeclarations != len(check.KeyPresentationNames):
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: в словаре %s объявлено %d из %d имён предъявления ключа (%s) — "+
			"имена сменились, и молчание пробы сказано ни о чём (прочитано файлов %d)",
			check.AssuranceHomeRel, census.HomeDeclarations, len(check.KeyPresentationNames),
			strings.Join(check.KeyPresentationNames, ", "), census.Files)
	case census.FilesImportingHome == 0:
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: ни один файл прод-кода не импортирует словарь %s — разбор импорта слеп "+
			"(прочитано файлов %d)", check.AssuranceHomeImport, census.Files)
	}
	t.Logf("перепись: файлов прод-кода прочитано %d, импортирующих словарь %d; обращений к предъявлению ключа вне "+
		"словаря %d — законных %d (записей ведомости %d)",
		census.Files, census.FilesImportingHome, census.Uses, census.LawfulUses, len(keyPresentationLawfulUses))

	if len(findings) != 0 {
		t.Fatalf("у предъявления ключа появился потребитель вне словаря, производителя и декодера — %d находок:\n  %s\n\n"+
			"Ось «заведено» (%s) ключей не видит; полоса, поднимающая уровень сессии утверждением ключа, "+
			"обязана тем же изменением ввести ключи в ось.",
			len(findings), strings.Join(findings, "\n  "), check.FailureResetHomeRel)
	}
}
