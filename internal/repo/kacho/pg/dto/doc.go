// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package dto — pg ↔ domain mapping для kacho-iam.
//
// Структура (per resource):
//
//	account.go    AccountRow {ID, Name, Description, Labels []byte, OwnerUserID, CreatedAt}
//	              (RowDTO).ToDomain() → domain.Account, error
//	              (domain.Account).FromDomain() → AccountRow
//
//	project.go    ProjectRow {ID, AccountID, Name, Description, Labels []byte, CreatedAt}
//	              ... аналогично
//
//	user.go, service_account.go, group.go, group_member.go, role.go, access_binding.go.
//
// JSONB Labels десериализуется `json.Unmarshal([]byte, &map[string]string)`
// + cast в domain.Labels — по образцу kacho-vpc/internal/repo/kacho/pg/dto/.
package dto
