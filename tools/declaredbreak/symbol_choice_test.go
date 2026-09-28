// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// symbol_choice_test.go — ФОРМА СИМВОЛА находки на настоящем выводе buf.
//
// ПРЕДМЕТ. Какой символ ложится в координату разрыва, решает код, а запись перечня
// пишет человек по шапке `proto/declared-breaks.yaml`. Разойдись они — и
// сопоставление рассыплется молча: обе стороны останутся синтаксически верными.
//
// История формы. До задачи kaname#127 комментарий обещал «последнее кавычечное
// вхождение», а код брал первое вхождение вида имени, — и символом было имя
// снятого (`id`, `Get`), а не его контейнер. Задача kaname#474 показала, что этого
// мало: у значения перечисления buf имени не печатает (только номер), и символом
// становилось перечисление; у поля — имя без сообщения. Запись о снятии одного
// значения прощала снятие любого соседнего.
//
// Нынешняя форма: где сообщение называет объемлющий символ (`on message`,
// `on enum`, `on service`), символ — `<контейнер>.<предмет>`, а предмет — ПЕРВОЕ
// кавычечное вхождение до контейнера: номер у поля и значения перечисления, имя у
// RPC, oneof, зарезервированного имени, запись диапазона у зарезервированного
// диапазона. У обязательного поля buf пишет контейнер ПЕРВЫМ (`Message "M" had
// required field "N"`), и символ — тот же `M.N`. Где контейнера нет — первое
// кавычечное вхождение вида имени, как прежде; у снятия файла — путь.
//
// ВХОД НАСТОЯЩИЙ: обходятся ВСЕ фикстуры `testdata/*.jsonl` и
// `testdata/*/*.jsonl`, и каждая находка обязана стоять в таблице ожиданий ниже.
// Находка вне таблицы — провал (фикстура принесла форму, о которой проба не
// знает), запись таблицы без находки — тоже провал (ожидание пережило свою
// фикстуру).
package declaredbreak_test

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/PRO-Robotech/kaname/tools/declaredbreak"
)

// expectedSymbol — сообщение buf → символ находки. Ключ — сообщение ДОСЛОВНО:
// так ожидание не зависит от разбора, который оно проверяет.
var expectedSymbol = map[string]string{
	// testdata/buf-breaking-real.jsonl
	`Previously present file "kaname/cloud/iam/v1/user_token_service.proto" was deleted.`: "kaname/cloud/iam/v1/user_token_service.proto",
	`Previously present field "1" with name "id" on message "Role" was deleted.`:          "Role.1",
	`Previously present RPC "Get" on service "RoleService" was deleted.`:                  "RoleService.Get",
	// testdata/sibling — значения перечисления: имени значения buf не печатает.
	`Previously present enum value "3" on enum "CredentialKind" was deleted.`:                                              "CredentialKind.3",
	`Previously present enum value "4" on enum "CredentialKind" was deleted.`:                                              "CredentialKind.4",
	`Enum value "3" on enum "CredentialKind" changed name from "CREDENTIAL_KIND_FEDERATED" to "CREDENTIAL_KIND_EXTERNAL".`: "CredentialKind.3",
	`Enum value "4" on enum "CredentialKind" changed name from "CREDENTIAL_KIND_LEGACY" to "CREDENTIAL_KIND_RETIRED".`:     "CredentialKind.4",
	// поля: номер, а не имя, — у переименования buf имени в описании поля не печатает.
	`Previously present field "1" with name "page_size" on message "ListRolesRequest" was deleted.`:                                "ListRolesRequest.1",
	`Previously present field "2" with name "page_size" on message "ListRoleOperationsRequest" was deleted.`:                       "ListRoleOperationsRequest.2",
	`Field "1" on message "ListRolesRequest" changed name from "page_size" to "page_limit".`:                                       "ListRolesRequest.1",
	`Field "2" on message "ListRolesRequest" changed name from "page_token" to "page_cursor".`:                                     "ListRolesRequest.2",
	`Field "1" with name "page_limit" on message "ListRolesRequest" changed option "json_name" from "pageSize" to "pageLimit".`:    "ListRolesRequest.1",
	`Field "2" with name "page_cursor" on message "ListRolesRequest" changed option "json_name" from "pageToken" to "pageCursor".`: "ListRolesRequest.2",
	// зарезервированное имя и диапазон: у диапазона предмет не имеет вида имени.
	`Previously present reserved name "organization_id" on message "Account" was deleted.`:              "Account.organization_id",
	`Previously present reserved range "[7]" on message "Account" is missing values: [7] were removed.`: "Account.[7]",
	// обязательное поле: контейнер buf пишет ПЕРВЫМ.
	`Previously present field "1" with name "a" on message "RequiredProbe" was deleted.`:                                                                                                  "RequiredProbe.1",
	`Previously present field "2" with name "b" on message "RequiredProbe" was deleted.`:                                                                                                  "RequiredProbe.2",
	`Message "RequiredProbe" had required field "1" deleted. Required fields must always be sent, so if one side does not know about the required field, this will result in a breakage.`: "RequiredProbe.1",
	`Message "RequiredProbe" had required field "2" deleted. Required fields must always be sent, so if one side does not know about the required field, this will result in a breakage.`: "RequiredProbe.2",
	// контейнера buf не печатает вовсе: различает такие разрывы только расходование записи.
	`Message option "no_standard_descriptor_accessor" changed from "false" to "true".`: "no_standard_descriptor_accessor",
}

func TestSymbolNamesTheSubjectInsideItsContainer(t *testing.T) {
	var files []string
	for _, pat := range []string{"testdata/*.jsonl", "testdata/*/*.jsonl"} {
		m, err := filepath.Glob(pat)
		if err != nil {
			t.Fatalf("обход фикстур: %v", err)
		}
		files = append(files, m...)
	}
	sort.Strings(files)

	seen := map[string]int{}
	var findings int
	for _, p := range files {
		f, err := os.Open(p) // #nosec G304 -- путь из обхода testdata
		if err != nil {
			t.Fatalf("фикстура %s не открыта: %v", p, err)
		}
		got, err := declaredbreak.ParseFindings(f)
		_ = f.Close()
		if err != nil {
			t.Fatalf("фикстура %s не разобрана: %v", p, err)
		}
		for _, fd := range got {
			findings++
			want, ok := expectedSymbol[fd.Message]
			if !ok {
				t.Errorf("%s: форма сообщения вне таблицы ожиданий — проба о ней не знает: %s %q",
					p, fd.Type, fd.Message)
				continue
			}
			seen[fd.Message]++
			if fd.Symbol() != want {
				t.Errorf("%s: %s — символ %q, ожидался %q.\n  сообщение: %s",
					p, fd.Type, fd.Symbol(), want, fd.Message)
			}
		}
	}
	t.Logf("перепись: фикстур %d, находок %d, форм сообщения в таблице %d, из них встречено %d",
		len(files), findings, len(expectedSymbol), len(seen))
	if len(files) == 0 || findings == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: не прочитано ни одной фикстуры настоящего вывода buf")
	}
	for msg := range expectedSymbol {
		if seen[msg] == 0 {
			t.Errorf("ожидание пережило свою фикстуру — ни одна находка его не несёт: %q", msg)
		}
	}
}
