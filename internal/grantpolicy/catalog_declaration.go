// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantpolicy

import "github.com/PRO-Robotech/kaname/internal/domain"

// CatalogEffect описывает влияние каталожной операции на доступ.
type CatalogEffect uint8

const (
	UnknownEffect CatalogEffect = iota
	UnchangedAccess
	ChangesHolders
	ChangesTier
	ChangesHoldersAndTier
	// AuthorityInput участвует в расчёте полномочий и собственного RPC не имеет.
	AuthorityInput
)

// CatalogDirection независимо уточняет направление эффекта. Сужение доступа
// сохраняет изменение держателей или яруса; само направление права не подтверждает.
type CatalogDirection uint8

const (
	UnspecifiedDirection CatalogDirection = iota
	// WithdrawsAccess означает только снятие уже выданного доступа.
	WithdrawsAccess
	// ExpandsOrMixesAccess включает выдачу нового доступа, в том числе вместе с отзывом.
	ExpandsOrMixesAccess
)

// WithdrawalAuthority называет проверенный контракт чистого отзыва. Проверка
// каталога связывает его с точным RPC и его действующим способом авторизации.
// Эта декларация не участвует в принятии запросов и сама доступа не разрешает.
type WithdrawalAuthority uint8

const (
	NoWithdrawalAuthority WithdrawalAuthority = iota
	// TargetGroupMembershipWithdrawal — ESC-24: право менять именно группу запроса.
	TargetGroupMembershipWithdrawal
	// ActiveDelegationBindingWithdrawal — GD-31/Р2: только выдача действующего
	// делегирования вызывающего; обычный путь сохраняет v_delete на привязке
	// и проверку права выдавать на её области.
	ActiveDelegationBindingWithdrawal
	// TargetRoleDeletionWithdrawal — ESC §2 п.4: право удалить именно роль запроса.
	TargetRoleDeletionWithdrawal
	// TargetGroupDeletionWithdrawal — ESC §2 п.4: право удалить именно группу запроса.
	TargetGroupDeletionWithdrawal
	// TargetServiceAccountDisableWithdrawal — SAC-12/16: право отключить
	// именно служебную учётку запроса. Для включения действует отдельная проверка каталога.
	TargetServiceAccountDisableWithdrawal
	// TargetUserCredentialWithdrawal — CVR-01–04 и Ф7-25/27. Снимается
	// существующее удостоверение указанного человека по его двери token_issuer.
	TargetUserCredentialWithdrawal
	// TargetServiceAccountKeyWithdrawal — CVR-05–08 и SAC-12. Снимается
	// существующий ключ указанной служебной учётки по её двери v_update.
	TargetServiceAccountKeyWithdrawal
	// TargetUserIdentityWithdrawal — удаление конкретной личности по
	// identity_remover на ней, с ограничениями удаления её связей.
	TargetUserIdentityWithdrawal
	// TargetUserAccessKeysWithdrawal — LMR-01: identity_suspender
	// снимает ключи и испытания только у указанного пользователя.
	TargetUserAccessKeysWithdrawal
	// TargetAccountDeletionWithdrawal — право v_delete на аккаунте
	// снимает его членства и выдачи в пределах контракта KN664.
	TargetAccountDeletionWithdrawal
	// TargetProjectDeletionWithdrawal — IAM-PNE-1: право v_delete
	// на проекте снимает его выдачи при соблюдении проверки непустоты.
	TargetProjectDeletionWithdrawal
	// TargetUserBlockWithdrawal — identity_suspender блокирует указанную
	// личность и сдвигает её отсечку. Разблокировка требует отдельной декларации.
	TargetUserBlockWithdrawal
	// TargetAccountMembershipWithdrawal — member_remover названного
	// аккаунта исключает указанного участника только из этого аккаунта.
	TargetAccountMembershipWithdrawal
	// TargetServiceAccountDeletionWithdrawal — v_delete на указанной
	// служебной учётке. Сохраняются ограничения удаления активных связей.
	TargetServiceAccountDeletionWithdrawal
)

// CatalogDeclaration формирует владелец операции по тем же проверкам,
// которые вызывает исполняемый путь.
type CatalogDeclaration struct {
	FullMethod          string
	Capability          domain.GrantCapabilityKind
	Effect              CatalogEffect
	Direction           CatalogDirection
	RequiresCheck       bool
	WithdrawalAuthority WithdrawalAuthority
}

// CatalogCapabilityDeclarations описывает управляющие координаты без своего
// RPC. Проверка выдачи использует bind для роли и apply для определения метки.
func CatalogCapabilityDeclarations() []CatalogDeclaration {
	return []CatalogDeclaration{
		{Capability: domain.GrantCapabilityBindRole, Effect: AuthorityInput},
		{Capability: domain.GrantCapabilityApplyAccessLabel, Effect: AuthorityInput},
	}
}
