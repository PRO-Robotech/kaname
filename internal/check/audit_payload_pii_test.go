// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// audit_payload_pii_test.go — ГЕЙТ: в не-тестовом дереве службы нет нагрузки
// журнала аудита, несущей личные данные (`kacho#2483`).
//
// Норма, состав форм, состав перечня личных ключей и то, чего в перечне нет
// намеренно, — в шапке `audit_payload_pii.go`; здесь они не пересказываются,
// чтобы два места об одном предмете не разошлись.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// audit_payload_pii_injection_test.go.
package check_test

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestAuditPayloadCarriesNoPersonalData — нагрузка события аудита не несёт
// личных данных.
//
// Что делать, если гейт сработал, — три исхода, четвёртого нет:
//
//  1. поле нужно для корреляции → его там уже нет нужды класть: неизменяемый
//     идентификатор субъекта в нагрузке есть, и он остаётся правдой через год,
//     тогда как почта и имя изменяемы;
//  2. поле нужно получателю потока по существу → предмет требует РЕШЕНИЯ, а не
//     правки: объявленное исключение с названным сроком хранения личных данных
//     в потоке. Решение записывается приёмкой, а не комментарием;
//  3. поле попало по инерции копирования соседнего события → снять.
//
// Приписать ключ в перечень прощённых — НЕ исход: перечня прощённых у разбора
// нет, и заводить его нельзя. Каждая такая запись есть место, куда личное поле
// вносят незамеченным.
func TestAuditPayloadCarriesNoPersonalData(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	// Обход — по корню МОДУЛЯ службы: дерево платформы этому модулю не
	// принадлежит, и судить его отсюда значило бы краснеть на чужом.
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	findings, census, err := check.ScanAuditPayloads(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход дерева не состоялся: %v", err)
	}

	t.Logf("%s; находок %d", census, len(findings))

	// Пустой обход: «личных ключей нет» здесь означало бы «ничего не читал».
	if census.Read == 0 {
		t.Fatal("не прочитано ни одного файла Go — вердикт беспредметен")
	}
	if census.Parsed == 0 {
		t.Fatal("не разобрано ни одного файла Go — признак «ключ нагрузки» не производится, " +
			"поэтому ноль находок сказано ни о чём")
	}
	// Предмет разбора: мест построения нагрузки должно быть НЕ НОЛЬ. Ноль
	// означает либо снятый журнал аудита (тогда снимается и гейт), либо разбор,
	// переставший видеть предмет, — и второе выглядит точно так же, как чистое
	// дерево.
	if census.Sites == 0 {
		t.Fatalf("мест построения нагрузки осмотрено НОЛЬ при %d разобранных файлах — "+
			"журнал аудита снят либо разбор перестал видеть предмет", census.Parsed)
	}
	if census.Keys == 0 {
		t.Fatalf("мест построения нагрузки %d, а ключей осмотрено НОЛЬ — разбор находит "+
			"места и не читает их содержимого", census.Sites)
	}
	// Непрозрачное место литеральным разбором не судится. Ноль — вердикт
	// обхода; не ноль — названная вслух граница вердикта, а не находка.
	if n := census.SitesByForm[check.FormOpaque]; n > 0 {
		t.Logf("ГРАНИЦА ВЕРДИКТА: мест с непрозрачной нагрузкой %d — их ключи литеральным "+
			"разбором не читаются, и «личных ключей нет» о них НЕ сказано", n)
	}

	for _, f := range findings {
		t.Errorf("личные данные в нагрузке журнала аудита: %s\n"+
			"Приёмник кладёт ВСЕ поля нагрузки как есть — шага сокрытия нет ни одного, — "+
			"поэтому ключ уезжает в поток, а срок хранения потока становится сроком "+
			"хранения личных данных. Корреляция личного поля не требует: неизменяемый "+
			"идентификатор субъекта в нагрузке уже есть.", f)
	}
}

// TestEveryAuditPayloadFormIsSeenByTheParser — КАЖДАЯ объявленная форма
// доходит до решения.
//
// Форма, объявленная и не ловимая, не даёт ни красного, ни зелёного: она
// МОЛЧИТ, и записанное в ней оказывается вне наблюдения, оставаясь на вид
// покрытым (`testing.md` §«Гейт на класс», п. 7). Поэтому каждая форма
// предъявляется ТОМУ ЖЕ разбору, что ходит по дереву, а не проверяется чтением.
func TestEveryAuditPayloadFormIsSeenByTheParser(t *testing.T) {
	t.Parallel()
	forms := check.AuditPayloadForms()
	if len(forms) == 0 {
		t.Fatal("осмотрено: форм 0 — «все формы ловятся» здесь означало бы «форм нет»")
	}
	for _, form := range forms {
		t.Run(form.Name, func(t *testing.T) {
			sites, err := check.ParseAuditPayloadSites("synthetic.go", []byte(form.Example))
			if err != nil {
				t.Fatalf("разбор примера формы %q: %v", form.Name, err)
			}
			var keys []string
			seen := map[string]bool{}
			for _, s := range sites {
				seen[s.Form] = true
				for _, k := range s.Keys {
					keys = append(keys, k.Name)
				}
			}
			if !seen[form.Name] {
				t.Fatalf("форма %q (%s) разбором НЕ опознана; опознаны: %v.\n"+
					"Форма, объявленная и не ловимая, есть слепая зона, выглядящая покрытой",
					form.Name, form.Why, sortedFormNames(seen))
			}
			// Опознать место мало: ключ обязан из него ДОЕХАТЬ до сверки.
			// Форма, опознанная без ключей, молчит ровно так же.
			if !containsString(keys, "email") {
				t.Fatalf("форма %q опознана, но ключ примера до сверки НЕ доехал (собрано: %v) — "+
					"место видно, содержимое нет", form.Name, keys)
			}
		})
	}
}

// TestEveryDeclaredPersonalKeyIsCaught — КАЖДЫЙ объявленный ключ ловится.
//
// Ключ, объявленный и не ловимый, есть обещание защиты, которой нет: перечень
// читается как список запрещённого, а запрещает он подмножество.
func TestEveryDeclaredPersonalKeyIsCaught(t *testing.T) {
	t.Parallel()
	keys := check.AuditPersonalKeys()
	if len(keys) == 0 {
		t.Fatal("объявлено личных ключей 0 — гейт запрещает пустое множество")
	}
	for _, k := range keys {
		t.Run(k.Key, func(t *testing.T) {
			if strings.TrimSpace(k.Why) == "" {
				t.Fatalf("у ключа %q не названа причина — находка без причины снимается "+
					"следующим как непонятная", k.Key)
			}
			root := synthAuditTree(t, map[string]string{
				"internal/thing/thing.go": fmt.Sprintf(
					"package thing\n\nfunc f(v string) {\n\t_ = Event{Payload: map[string]any{%q: v}}\n}\n", k.Key),
			})
			findings, census, err := check.ScanAuditPayloads(root)
			if err != nil {
				t.Fatalf("обход синтетического дерева: %v", err)
			}
			if census.Read == 0 {
				t.Fatal("синтетическое дерево не прочитано")
			}
			if len(findings) != 1 || findings[0].Key != k.Key {
				t.Fatalf("ключ %q объявлен личным, а разбор его НЕ находит: находок %d (%v)",
					k.Key, len(findings), findings)
			}
		})
	}
}

func sortedFormNames(seen map[string]bool) []string {
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	return out
}

func containsString(hay []string, needle string) bool {
	for _, s := range hay {
		if s == needle {
			return true
		}
	}
	return false
}
