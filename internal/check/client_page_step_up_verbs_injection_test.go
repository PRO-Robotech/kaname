// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Доказательство способности гейта раздела Step-up упасть — инъекцией в ОБЕ
// стороны, с законными близнецами; каждая меняет ровно один факт.

// lawfulStepUpContract — синтетический контракт: два глагола с порогом «2»,
// один без порога, и слово опции в КОММЕНТАРИИ у безпорогового.
const lawfulStepUpContract = `syntax = "proto3";

service DemoService {
  rpc Get (GetRequest) returns (Demo) {
    // required_acr_min здесь НЕ объявлен намеренно: чтение — уровень «1».
    option (corelib.authz.v1.required_acr_min) = "1";
  }
  rpc Delete (DeleteRequest) returns (corelib.operation.Operation) {
    option (google.api.http) = { delete: "/demo/v1/demos/{id}" };
    option (corelib.authz.v1.required_acr_min) = "2";
  }
}

service KeyService {
  rpc Issue (IssueRequest) returns (corelib.operation.Operation) {
    option (corelib.authz.v1.required_acr_min) = "2";
  }
}
`

// lawfulStepUpPage — страница, сходящаяся с близнецом: раздел Step-up с обоими
// глаголами, глагол без порога упомянут ВНЕ раздела.
const lawfulStepUpPage = "" +
	"# Модель\n\n" +
	"## Verb-bearing\n\n<code>DemoService.Get</code> требует `v_get`.\n\n" +
	"## Step-up (ACR floor) {#step-up}\n\n" +
	"<table><tbody>\n" +
	"<tr><td>удаление</td><td><code>DemoService.Delete</code></td></tr>\n" +
	"<tr><td>удостоверения</td><td><code>KeyService.Issue</code></td></tr>\n" +
	"</tbody></table>\n\n" +
	"## Условия\n\nПроза о <code>DemoService.Get</code> вне раздела.\n"

func lawfulStepUpFiles() map[string]string {
	return map[string]string{"demo_service.proto": lawfulStepUpContract}
}

func TestStepUpPageGateIsSilentOnTheLawfulPair(t *testing.T) {
	findings, c := auditStepUpPage(lawfulStepUpFiles(), lawfulStepUpPage)
	require.Empty(t, findings, "законная пара обязана молчать")
	require.Equal(t, 3, c.rpcsRead)
	require.Equal(t, 2, c.flooredInProto)
	require.Equal(t, 2, c.verbsOnPage)
}

// Прямая сторона: контракт получил порог, страницу не дописали.
func TestStepUpPageGateRedsWhenTheContractOutgrowsThePage(t *testing.T) {
	src := strings.Replace(lawfulStepUpContract,
		"    option (corelib.authz.v1.required_acr_min) = \"1\";",
		"    option (corelib.authz.v1.required_acr_min) = \"2\";", 1)
	require.NotEqual(t, lawfulStepUpContract, src, "инъекция не внеслась")
	findings, c := auditStepUpPage(map[string]string{"demo_service.proto": src}, lawfulStepUpPage)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "DemoService.Get", "находка обязана НАЗЫВАТЬ глагол")
	require.Equal(t, 1, c.missingOnPage)
}

// Обратная сторона: страница называет глагол, у которого порога нет.
func TestStepUpPageGateRedsWhenThePageNamesAnUnflooredVerb(t *testing.T) {
	page := strings.Replace(lawfulStepUpPage,
		"<tr><td>удостоверения</td><td><code>KeyService.Issue</code></td></tr>\n",
		"<tr><td>удостоверения</td><td><code>KeyService.Issue</code>, <code>DemoService.Get</code></td></tr>\n", 1)
	require.NotEqual(t, lawfulStepUpPage, page, "инъекция не внеслась")
	findings, c := auditStepUpPage(lawfulStepUpFiles(), page)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "DemoService.Get")
	require.Contains(t, findings[0], "пережило свой предмет")
	require.Equal(t, 1, c.extraOnPage)
}

// Законный близнец прямой стороны: слово опции в КОММЕНТАРИИ контракта
// порогом не является — гейт читает строку опции, а не слово.
func TestStepUpPageGateIsSilentOnTheOptionNamedInAComment(t *testing.T) {
	src := strings.Replace(lawfulStepUpContract,
		"    // required_acr_min здесь НЕ объявлен намеренно: чтение — уровень «1».",
		"    // прежде здесь стояло option (corelib.authz.v1.required_acr_min) = \"2\"; и было снято.", 1)
	require.NotEqual(t, lawfulStepUpContract, src, "инъекция не внеслась")
	findings, c := auditStepUpPage(map[string]string{"demo_service.proto": src}, lawfulStepUpPage)
	require.Empty(t, findings, "комментарий контракта порогом не является")
	require.Equal(t, 2, c.flooredInProto)
}

// Законный близнец обратной стороны: глагол без порога назван ВНЕ раздела
// Step-up (в лживой паре выше он стоит в разделе) — гейт судит раздел.
func TestStepUpPageGateIsSilentOnAVerbNamedOutsideTheSection(t *testing.T) {
	findings, _ := auditStepUpPage(lawfulStepUpFiles(), lawfulStepUpPage)
	require.Empty(t, findings, "`DemoService.Get` вне раздела — не утверждение о пороге")
}

// Пустой раздел: глаголов ноль ⇒ несущая проба падает на переписи.
func TestStepUpPageGateReportsAnEmptyWalkInsteadOfPassing(t *testing.T) {
	findings, c := auditStepUpPage(lawfulStepUpFiles(), "# Модель\n\n## Условия\n")
	require.Zero(t, c.verbsOnPage)
	require.NotEmpty(t, findings)
}
