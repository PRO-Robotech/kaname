// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Доказательство способности гейта страницы полосы входа упасть — инъекцией в
// ОБЕ стороны, с законными близнецами. Каждая инъекция меняет РОВНО ОДИН факт
// против близнеца.

// lawfulLaneContract — синтетический слушатель: три пути, один маршрут края,
// два текста, два печенья.
var lawfulLaneContract = authLaneContract{
	Paths:      []string{"/iam/v1/auth/login", "/iam/v1/auth/logout", "/iam/v1/auth/second-factor/enroll"},
	EdgeRoutes: []string{"/iam/v1/auth/me"},
	Texts:      []string{"authentication failed", "FORM_TOKEN_REJECTED"},
	Cookies:    []string{"kaname_session", "kaname_form"},
}

// lawfulLanePage — страница, сходящаяся с близнецом: пути в обеих формах
// код-форматирования, маршрут края назван как чужой, приставка семейства в прозе.
const lawfulLanePage = "" +
	"# Полоса\n\n" +
	"| `POST /iam/v1/auth/login` | вход |\n" +
	"| <code>POST /iam/v1/auth/logout</code> | выход |\n" +
	"| `POST /iam/v1/auth/second-factor/enroll` | заведение |\n\n" +
	"«Кто я» (`GET /iam/v1/auth/me`) — маршрут края; `/iam/v1/auth/…` — не приставка.\n\n" +
	"Отказ: `authentication failed`, причина `FORM_TOKEN_REJECTED`.\n" +
	"Печенья `kaname_session` и `kaname_form`.\n"

func TestAuthLanePageGateIsSilentOnTheLawfulPair(t *testing.T) {
	findings, c := auditAuthLanePage(lawfulLanePage, lawfulLaneContract)
	require.Empty(t, findings, "законная пара обязана молчать")
	require.Equal(t, 3, c.pathsDeclared)
	require.Equal(t, 3, c.pathsNamed)
	require.Equal(t, 0, c.pathsForeign)
	require.Equal(t, 2, c.textsNamed)
	require.Equal(t, 2, c.cookiesNamed)
}

// Прямая сторона: слушатель получил путь, страницу не дописали.
func TestAuthLanePageGateRedsWhenTheListenerOutgrowsThePage(t *testing.T) {
	c := lawfulLaneContract
	c.Paths = append(append([]string(nil), c.Paths...), "/iam/v1/auth/step-up")
	findings, census := auditAuthLanePage(lawfulLanePage, c)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "/iam/v1/auth/step-up", "находка обязана НАЗЫВАТЬ путь")
	require.Equal(t, 3, census.pathsNamed)
}

// Обратная сторона: страница называет путь, которого слушатель не обслуживает.
func TestAuthLanePageGateRedsWhenThePageNamesAnAbsentPath(t *testing.T) {
	page := lawfulLanePage + "| `POST /iam/v1/auth/session` | список сессий |\n"
	findings, census := auditAuthLanePage(page, lawfulLaneContract)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "/iam/v1/auth/session")
	require.Contains(t, findings[0], "пережило свой предмет")
	require.Equal(t, 1, census.pathsForeign)
}

// Законный близнец обратной стороны: путь семейства в ПРОЗЕ, без
// код-форматирования, гейт не судит — иначе краснел бы на объяснении.
func TestAuthLanePageGateIsSilentOnAPathNamedOnlyInProse(t *testing.T) {
	page := lawfulLanePage + "Прежде здесь стоял путь /iam/v1/auth/session, и его сняли.\n"
	findings, _ := auditAuthLanePage(page, lawfulLaneContract)
	require.Empty(t, findings, "путь вне код-форматирования — проза, а не утверждение о полосе")
}

// Текст отказа снят со страницы — находка называет текст.
func TestAuthLanePageGateRedsWhenARefusalTextIsMissing(t *testing.T) {
	page := strings.Replace(lawfulLanePage, "`authentication failed`", "`authentication refused`", 1)
	require.NotEqual(t, lawfulLanePage, page, "инъекция не внеслась")
	findings, census := auditAuthLanePage(page, lawfulLaneContract)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], `"authentication failed"`)
	require.Equal(t, 1, census.textsNamed)
}

// Печенье снято со страницы — находка называет печенье.
func TestAuthLanePageGateRedsWhenACookieIsMissing(t *testing.T) {
	page := strings.Replace(lawfulLanePage, "`kaname_form`", "`kaname_csrf`", 1)
	require.NotEqual(t, lawfulLanePage, page, "инъекция не внеслась")
	findings, census := auditAuthLanePage(page, lawfulLaneContract)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "kaname_form")
	require.Equal(t, 1, census.cookiesNamed)
}

// Пустая страница: код-спанов ноль ⇒ несущая проба обязана упасть на переписи,
// а не на находках.
func TestAuthLanePageGateReportsAnEmptyWalkInsteadOfPassing(t *testing.T) {
	findings, census := auditAuthLanePage("# Пусто\n\nНи одного код-спана.\n", lawfulLaneContract)
	require.Zero(t, census.spansRead)
	require.NotEmpty(t, findings)
}
