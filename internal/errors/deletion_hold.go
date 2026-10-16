// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors

// deletion_hold.go — отказ снятия ПО СОДЕРЖИМОМУ у `UserService.Delete` и
// `AccountService.Delete` (kaname#725, приёмка
// `deletion-refusals-name-the-remainder-and-the-step.md`).
//
// # Две половины одного отказа
//
// Вид держащего (`HoldKind`) знает тот, кто отказал: охрана оператора снятия
// либо рубеж схемы (ключ, триггер), разобранный `pgmaperr`. Первого держащего
// и их число знает только ЧТЕНИЕ после отказа — у рубежа схемы оператор уже
// мёртв, и спросить у него нечего. Поэтому признаков два: [HeldBy] — «отказано
// держащими этого вида», с ним репозиторий дочитывает остаток, и [NamedHold] —
// отказ, уже назвавший первого держащего, с ним `shared.MapRepoErr` кладёт
// `metadata` в `ErrorInfo`.
//
// Обе формы ВЛОЖЕНЫ в [ErrReferenceInUse]: клиент и прочие потребители,
// различающие только полосу «ещё ссылаются», продолжают работать, а
// [StripSentinel] снимает служебное имя полосы так же, как у любого отказа по
// ссылке.

import stderrors "errors"

// HoldKind — вид ресурса, держащего снятие. Перечень закрыт и повторяет
// таблицу Р1 приёмки; порядок видов при охране — у репозитория.
type HoldKind string

const (
	// HoldAccountsOwned — человек владеет аккаунтами (`accounts.owner_user_id`).
	HoldAccountsOwned HoldKind = "accounts_owned"
	// HoldActiveBindings — на человеке есть действующие выдачи.
	HoldActiveBindings HoldKind = "active_bindings"
	// HoldGroupMembership — человек состоит в группах.
	HoldGroupMembership HoldKind = "group_membership"
	// HoldProjects — в аккаунте есть проекты.
	HoldProjects HoldKind = "projects"
	// HoldServiceAccounts — в аккаунте есть сервисные аккаунты.
	HoldServiceAccounts HoldKind = "service_accounts"
	// HoldGroups — в аккаунте есть группы.
	HoldGroups HoldKind = "groups"
	// HoldCustomRoles — в аккаунте есть свои роли.
	HoldCustomRoles HoldKind = "custom_roles"
)

// holdLane — полоса «ещё ссылаются» с видом держащего. Текст — текст
// [ErrReferenceInUse] ДОСЛОВНО: по нему [StripSentinel] узнаёт префикс полосы,
// и обёртка `Wrapf(HeldBy(k), …)` даёт клиенту тот же текст, что
// `Wrapf(ErrReferenceInUse, …)`.
type holdLane struct{ kind HoldKind }

func (h holdLane) Error() string { return ErrReferenceInUse.Error() }
func (h holdLane) Unwrap() error { return ErrReferenceInUse }

// HeldBy — полоса отказа снятия, держимого ресурсами вида kind. Ставится там,
// где отказ рождается: `Wrapf(HeldBy(kind), "<текст>")`.
func HeldBy(kind HoldKind) error { return holdLane{kind: kind} }

// HoldKindOf — вид держащего, если err — отказ полосы [HeldBy].
func HoldKindOf(err error) (HoldKind, bool) {
	var h holdLane
	if stderrors.As(err, &h) {
		return h.kind, true
	}
	return "", false
}

// Holder — первый держащий и число держащих того же вида в момент чтения;
// то, что уезжает в `ErrorInfo.metadata` (Р3).
type Holder struct {
	// ResourceType — вид первого держащего в написании metadata
	// (`account`, `access_binding`, `group`, `project`, `service_account`, `role`).
	ResourceType string
	// ResourceID — `id` первого держащего.
	ResourceID string
	// Remaining — число держащих этого вида, не меньше одного.
	Remaining int
}

// namedHold — отказ, назвавший остаток. holder == nil — держащих к моменту
// чтения уже нет (Р2): отсутствие держащего представлено отсутствием, а не
// пустыми полями.
type namedHold struct {
	text   string
	holder *Holder
}

func (n *namedHold) Error() string { return ErrReferenceInUse.Error() + ": " + n.text }
func (n *namedHold) Unwrap() error { return ErrReferenceInUse }

// NamedHold — окончательный отказ снятия: text — то, что увидит клиент,
// holder — первый держащий либо nil.
func NamedHold(text string, holder *Holder) error {
	if holder != nil {
		h := *holder
		holder = &h
	}
	return &namedHold{text: text, holder: holder}
}

// HolderOf — первый держащий отказа [NamedHold]; ok=false — держащего не
// названо (его нет либо отказ другой полосы).
func HolderOf(err error) (Holder, bool) {
	var n *namedHold
	if stderrors.As(err, &n) && n.holder != nil {
		return *n.holder, true
	}
	return Holder{}, false
}
