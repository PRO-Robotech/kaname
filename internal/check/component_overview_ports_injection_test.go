// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Доказательство способности гейта таблицы портов упасть — инъекцией в ОБЕ стороны
// и с законными близнецами.
//
// Инъекция меняет РОВНО ОДИН факт против своего положительного близнеца: иначе
// неизвестно, какой из двух дал красное, и вердикт недействителен, оставаясь на
// вид зелёным.

// lawfulRegisterSrc — положительный близнец: две функции-регистратора, по службе в
// каждой, плюс `AuthorizeService` на ОБОИХ слушателях — так и стоит в дереве, и
// это законно (запрет #6 запрещает обратное: `Internal.*` наружу).
const lawfulRegisterSrc = `package main

func registerPublicServices() {
	iamv1.RegisterAccountServiceServer(srv, h)
	iamv1.RegisterAuthorizeServiceServer(srv, h)
}

func registerInternalServices() {
	iamv1.RegisterInternalIAMServiceServer(srv, h)
	iamv1.RegisterAuthorizeServiceServer(srv, h)
}
`

// lawfulDoc — таблица, сходящаяся с близнецом выше.
const lawfulDoc = "" +
	"| Listener | Сервис | Назначение |\n" +
	"|---|---|---|\n" +
	"| `:9090`   | `AccountService`   | CRUD Account |\n" +
	"| `:9090`   | `AuthorizeService` | Check |\n" +
	"| `:9091`   | `InternalIAMService` | fgaproxy |\n" +
	"| `:9091`   | `AuthorizeService` | тот же обработчик по mTLS-ребру |\n"

// TestPortTableGateIsSilentOnTheLawfulPair — контроль. Без него любое красное ниже
// могло бы приходить от соседа, а не от внесённого дефекта.
func TestPortTableGateIsSilentOnTheLawfulPair(t *testing.T) {
	findings, c, err := auditPortTable(lawfulRegisterSrc, lawfulDoc)
	require.NoError(t, err)
	require.Empty(t, findings, "законная пара обязана молчать")
	require.Equal(t, 2, c.registrarsRead)
	require.Equal(t, 4, c.registered)
	require.Equal(t, 4, c.tableRows)
}

// TestPortTableGateRedsWhenRegistrationOutgrowsTheDoc — прямая сторона: служба села
// на слушатель, строку в таблицу не дописали. Это ровно #1359.
func TestPortTableGateRedsWhenRegistrationOutgrowsTheDoc(t *testing.T) {
	src := strings.Replace(lawfulRegisterSrc,
		"	iamv1.RegisterInternalIAMServiceServer(srv, h)",
		"	iamv1.RegisterInternalIAMServiceServer(srv, h)\n	iamv1.RegisterInternalLimitServiceServer(srv, h)",
		1)
	require.NotEqual(t, lawfulRegisterSrc, src, "инъекция не внеслась")

	findings, c, err := auditPortTable(src, lawfulDoc)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "InternalLimitService", "находка обязана НАЗЫВАТЬ службу")
	require.Contains(t, findings[0], ":9091", "находка обязана называть слушатель")
	require.Equal(t, 1, c.missingInDoc)
	require.Equal(t, 0, c.extraInDoc)
}

// TestPortTableGateRedsWhenTheDocNamesAnAbsentService — обратная сторона: строка
// пережила свой предмет. Без этой половины гейт молчал бы на снятой службе.
func TestPortTableGateRedsWhenTheDocNamesAnAbsentService(t *testing.T) {
	doc := lawfulDoc + "| `:9090`   | `RetiredDiskService` | снятая служба |\n"

	findings, c, err := auditPortTable(lawfulRegisterSrc, doc)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "RetiredDiskService")
	require.Contains(t, findings[0], "пережило свой предмет")
	require.Equal(t, 0, c.missingInDoc)
	require.Equal(t, 1, c.extraInDoc)
}

// TestPortTableGateIsSilentOnARegistrationNamedOnlyInProse — законный близнец
// первой инъекции. Тот же токен, что и в ней, но КОММЕНТАРИЕМ: гейт судит узел
// вызова, а не вхождение имени, — иначе краснел бы на объяснении самого себя.
func TestPortTableGateIsSilentOnARegistrationNamedOnlyInProse(t *testing.T) {
	src := strings.Replace(lawfulRegisterSrc,
		"	iamv1.RegisterInternalIAMServiceServer(srv, h)",
		"	// прежде здесь стоял iamv1.RegisterInternalLimitServiceServer(srv, h)\n	iamv1.RegisterInternalIAMServiceServer(srv, h)",
		1)
	require.NotEqual(t, lawfulRegisterSrc, src, "инъекция не внеслась")

	findings, c, err := auditPortTable(src, lawfulDoc)
	require.NoError(t, err)
	require.Empty(t, findings, "имя в комментарии регистрацией не является")
	require.Equal(t, 4, c.registered, "комментарий не обязан менять перепись регистраций")
}

// TestPortTableGateIsSilentWhenOneServiceSitsOnBothListeners — второй законный
// близнец: пересечение слушателей законно и не должно читаться как расхождение.
func TestPortTableGateIsSilentWhenOneServiceSitsOnBothListeners(t *testing.T) {
	findings, _, err := auditPortTable(lawfulRegisterSrc, lawfulDoc)
	require.NoError(t, err)
	require.Empty(t, findings)

	// та же служба, снятая с ОДНОГО слушателя в таблице, — уже находка,
	// и находка называет именно тот слушатель, с которого её сняли.
	doc := strings.Replace(lawfulDoc, "| `:9091`   | `AuthorizeService` | тот же обработчик по mTLS-ребру |\n", "", 1)
	findings, _, err = auditPortTable(lawfulRegisterSrc, doc)
	require.NoError(t, err)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], ":9091")
	require.Contains(t, findings[0], "AuthorizeService")
}

// TestPortTableGateReportsAnEmptyWalkInsteadOfPassing — пустой обход обязан быть
// отличим от «ноль находок»: регистраторов ноль ⇒ вердикт беспредметен.
func TestPortTableGateReportsAnEmptyWalkInsteadOfPassing(t *testing.T) {
	findings, c, err := auditPortTable("package main\n\nfunc unrelated() {}\n", lawfulDoc)
	require.NoError(t, err)
	require.Zero(t, c.registrarsRead, "регистраторов не найдено — несущая проба обязана упасть на этом")
	require.Zero(t, c.registered)
	// Находки при этом ЕСТЬ — таблица называет то, чего не регистрируется;
	// но решает беспредметность именно перепись, а не их число.
	require.NotEmpty(t, findings)
}
