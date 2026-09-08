// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// service_account_project_retired_test.go — поле, которое никто не заполняет,
// снято с контракта.
//
// `ServiceAccount.project_id` был объявлен в ответе, лежал колонкой с внешним
// ключом и читался при чеканке токена, но записать его было нечем: ни один
// запрос его не принимал, ни один INSERT/UPDATE не передавал, а выборка
// агрегата его даже не выбирала. Ветка «если проект задан — положить его в
// claim» недостижима by construction, а сам claim не читает никто.
//
// Три законных исхода для такого поля: реализовать, отвергать явно, снять с
// контракта. Реализовать значило бы завести подсистему проектных служебных
// учёток (область прав, извлечение области на краю, приёмка) — это не
// «допилить поле в чужом сообщении». Отвергать нечего: поле не принимается ни
// одним запросом. Поэтому — снять, зарезервировав номер и имя, чтобы никто не
// занял их заново с другим смыслом.

import (
	"testing"

	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

func TestServiceAccount_ProjectIDRetiredFromContract(t *testing.T) {
	desc := (&iamv1.ServiceAccount{}).ProtoReflect().Descriptor()

	require.Nil(t, desc.Fields().ByName("project_id"),
		"поле снято с контракта: у него не было ни одного писателя")

	var reservedName bool
	for i := 0; i < desc.ReservedNames().Len(); i++ {
		if desc.ReservedNames().Get(i) == "project_id" {
			reservedName = true
		}
	}
	require.True(t, reservedName,
		"имя обязано быть зарезервировано — иначе его займут заново с другим смыслом")

	var reservedNumber bool
	for i := 0; i < desc.ReservedRanges().Len(); i++ {
		r := desc.ReservedRanges().Get(i)
		if r[0] <= 6 && 6 < r[1] {
			reservedNumber = true
		}
	}
	require.True(t, reservedNumber,
		"номер 6 обязан быть зарезервирован — иначе старый клиент прочтёт новое поле как проект")
}
