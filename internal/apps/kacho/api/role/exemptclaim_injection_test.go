// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// exemptclaim_injection_test.go — доказательство того, что сверка полосы
// СПОСОБНА упасть и способна смолчать (задача продукта #2047).
//
// Вход синтетический: настоящее дерево не трогается, поэтому доказательство не
// истекает вместе с починкой комментариев (`testing.md` §«Гейт на класс», п. 5).
//
// Каждый случай меняет РОВНО ОДИН факт против положительного близнеца: либо
// объявление контракта, либо место, где стоит слово. Дельта в два факта сразу не
// доказывала бы ничего — покраснеть мог сосед.
package role_test

import (
	"strings"
	"testing"
)

const (
	// contractNoExempt — обе читающие полосы объявлены фильтруемыми.
	contractNoExempt = `service RoleService {
  rpc Get (GetRoleRequest) returns (Role) {
    option (kacho.iam.authz.v1.permission)     = "iam.roles.get";
    option (kacho.iam.authz.v1.scope_filtered) = true;
  }
}`
	// contractWithExempt — тот же контракт, где полоса ДЕЙСТВИТЕЛЬНО освобождена.
	// Ровно один факт отличия от близнеца выше.
	contractWithExempt = `service RoleService {
  rpc Get (GetRoleRequest) returns (Role) {
    option (kacho.iam.authz.v1.permission)     = "<exempt>";
  }
}`
)

func TestExemptClaim_CanFailAndStaysSilent(t *testing.T) {
	const (
		srcClaims = "// Get stays <exempt> in proto so a system-role read passes.\npackage role\n" +
			"func f() {}\n"
		srcClean = "// Get is scope_filtered; полоса объявлена контрактом.\npackage role\n" +
			"func f() {}\n"
		// Слово стоит в СТРОКЕ, а не в комментарии: предикат по подстроке
		// покраснел бы здесь, разбор — нет.
		srcLiteral = "package role\n\nfunc f() string { return \"<exempt>\" }\n"
	)

	cases := []struct {
		name         string
		contract     string
		sources      map[string]string
		wantFindings int
		wantNamed    string
		wantExempts  int
		wantClaims   int
	}{
		{
			name:         "контракт не освобождал, комментарий называет полосу — предмет #2047",
			contract:     contractNoExempt,
			sources:      map[string]string{"get.go": srcClaims},
			wantFindings: 1, wantNamed: "get.go:1", wantExempts: 0, wantClaims: 1,
		},
		{
			name:         "законный близнец: контракт ДЕЙСТВИТЕЛЬНО освободил полосу",
			contract:     contractWithExempt,
			sources:      map[string]string{"get.go": srcClaims},
			wantFindings: 0, wantExempts: 1, wantClaims: 1,
		},
		{
			name:         "законный близнец: комментарий полосы не называет",
			contract:     contractNoExempt,
			sources:      map[string]string{"get.go": srcClean},
			wantFindings: 0, wantExempts: 0, wantClaims: 0,
		},
		{
			name:         "законный близнец: слово в СТРОКОВОМ ЛИТЕРАЛЕ, а не в комментарии",
			contract:     contractNoExempt,
			sources:      map[string]string{"get.go": srcLiteral},
			wantFindings: 0, wantExempts: 0, wantClaims: 0,
		},
		{
			name:         "два файла: находка называет ОБА места",
			contract:     contractNoExempt,
			sources:      map[string]string{"get.go": srcClaims, "list.go": srcClaims},
			wantFindings: 2, wantNamed: "list.go:1", wantExempts: 0, wantClaims: 2,
		},
		{
			name:         "исходников не дали вовсе — премиса гейта дерева обязана упасть",
			contract:     contractNoExempt,
			sources:      map[string]string{},
			wantFindings: 0, wantExempts: 0, wantClaims: 0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			findings, census, err := auditExemptClaims(tc.contract, tc.sources)
			if err != nil {
				t.Fatalf("сверка не отработала: %v", err)
			}
			t.Logf("находок %d · %s", len(findings), census)

			if census.ContractExempts != tc.wantExempts {
				t.Fatalf("объявлений в контракте %d, ожидалось %d",
					census.ContractExempts, tc.wantExempts)
			}
			if census.Claims != tc.wantClaims {
				t.Fatalf("блоков, называющих полосу, %d, ожидалось %d",
					census.Claims, tc.wantClaims)
			}
			if len(findings) != tc.wantFindings {
				t.Fatalf("находок %d, ожидалось %d: %v", len(findings), tc.wantFindings, findings)
			}
			if tc.wantNamed != "" && !strings.Contains(strings.Join(findings, "\n"), tc.wantNamed) {
				t.Fatalf("находка не назвала место %q: %v", tc.wantNamed, findings)
			}
			if len(tc.sources) == 0 && census.FilesRead != 0 {
				t.Fatalf("файлов прочитано %d при пустом входе", census.FilesRead)
			}
		})
	}
}

// TestExemptClaim_EmptyContractIsNotAVerdict — непрочитанный контракт есть
// «не выполнилось»: премиса гейта не установлена, и молчать он не вправе.
func TestExemptClaim_EmptyContractIsNotAVerdict(t *testing.T) {
	_, _, err := auditExemptClaims("   \n", map[string]string{"get.go": "package role\n"})
	if err == nil {
		t.Fatal("пустой контракт принят за годную премису — вердикт был бы получен даром")
	}
	t.Logf("отказ сверки, как и должно: %v", err)
}

// TestExemptClaim_UnparsableSourceIsNotAVerdict — неразобранный исходник есть
// «не выполнилось»: ноль блоков комментария у него неотличим от честного нуля.
func TestExemptClaim_UnparsableSourceIsNotAVerdict(t *testing.T) {
	_, _, err := auditExemptClaims(contractNoExempt, map[string]string{"get.go": "package role\nfunc f( {"})
	if err == nil {
		t.Fatal("неразобранный исходник принят за годный: ноль комментариев был бы засчитан")
	}
	t.Logf("отказ разбора, как и должно: %v", err)
}
