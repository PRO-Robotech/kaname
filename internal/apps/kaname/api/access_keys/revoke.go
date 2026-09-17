// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// revoke.go — СНЯТИЕ КЛЮЧА по его `id` (Ф7-25…27, Ф7-36, Ф7-47).
//
// # Порядок — несущий
//
// форма идентификатора (синхронно, первым стейтментом — Ф7-47: пустой —
// «обязательно», без известного префикса — `invalid access key id`; чужой
// известный префикс форму проходит и уходит в полосу отсутствия) → свежесть
// (Ф7-36) → человек → операция. Внутри операции ОДНОЙ транзакцией: строки
// ключей человека под замком (сериализация «сосчитать способы — снять», ban
// #10), последний способ входа не снимается (Ф7-26), снятие суженное
// владельцем — чужой и несуществующий неразличимы (Ф7-27), событие аудита.
// Слот потолка возвращает удаление строки — триггером, в той же транзакции.

import (
	"context"
	"errors"
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	corevalidate "github.com/PRO-Robotech/corelib/validate"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// RevokeInput — чей ключ и какой; идентификатор — СЫРОЙ, форму судит глагол.
type RevokeInput struct {
	UserID      domain.UserID
	Actor       domain.UserID
	AccessKeyID string
}

// RevokeUseCase — снятие ключа.
type RevokeUseCase struct {
	deps Deps
	ops  operations.Repo
}

// NewRevokeUseCase — построение с проверкой зависимостей.
func NewRevokeUseCase(d Deps, ops operations.Repo) (*RevokeUseCase, error) {
	d, err := d.validate("access key revoke")
	if err != nil {
		return nil, err
	}
	if ops == nil {
		return nil, errors.New("access key revoke: operations repo required")
	}
	return &RevokeUseCase{deps: d, ops: ops}, nil
}

// Execute — синхронные сверки, затем операция.
func (uc *RevokeUseCase) Execute(ctx context.Context, in RevokeInput) (*operations.Operation, error) {
	if in.UserID == "" {
		return nil, fieldRequired("user_id")
	}
	// Обязательность — свой required-check: платформенный маршрутизатор
	// пустую строку пропускает по контракту (Р10).
	if in.AccessKeyID == "" {
		return nil, fieldRequired("access_key_id")
	}
	// Форма — платформенным маршрутизатором, family-agnostic по контракту:
	// строка с известным префиксом любой формы проходит и уходит в полосу
	// отсутствия, где отказ побайтово равен отказу по чужому ключу (Ф7-47).
	if err := corevalidate.ResourceID("access key", ids.PrefixAccessKeyHyphen, in.AccessKeyID); err != nil {
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRevoke, RefusalForm)
		return nil, invalidAccessKeyID(in.AccessKeyID)
	}
	now := uc.deps.Now().UTC()
	if err := requireFresh(ctx, uc.deps, LaneRevoke, in.Actor, now); err != nil {
		return nil, err
	}
	user, err := uc.deps.Store.UserOf(ctx, in.UserID)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.Revoke.user", err)
	}
	// Полоса отсутствия судится ДО операции: клиент получает синхронный
	// NOT_FOUND, а не операцию с ошибкой; чужой ключ этой же полосой — строка
	// сужена владельцем и не видна (Ф7-27).
	keyID := domain.AccessKeyID(in.AccessKeyID)
	var owned bool
	for _, k := range uc.keysOf(ctx, in.UserID) {
		if k.ID == keyID {
			owned = true
			break
		}
	}
	if !owned {
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRevoke, RefusalNotFound)
		return nil, notFound(in.AccessKeyID)
	}
	op, err := operations.NewFromContext(ctx, domain.PrefixOperationIAM,
		fmt.Sprintf("Revoke access key %s", in.AccessKeyID),
		&iamv1.RevokeAccessKeyMetadata{UserId: string(in.UserID), AccessKeyId: in.AccessKeyID, AccountId: string(user.AccountID)})
	if err != nil {
		return nil, err
	}
	// Последний способ входа судится синхронно, чтобы отказ назвал следующий
	// шаг клиенту, и ещё раз под замком внутри транзакции — второе чтение
	// держит инвариант, первое только классифицирует.
	if err := uc.lastMethodRefusal(ctx, in.UserID, 0); err != nil {
		return nil, err
	}
	if err := uc.ops.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := string(in.Actor)
	operations.Run(ctx, uc.ops, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.commit(ctx, in.UserID, keyID, user.AccountID, actor)
	})
	return &op, nil
}

func (uc *RevokeUseCase) keysOf(ctx context.Context, userID domain.UserID) []domain.AccessKey {
	keys, _, err := uc.deps.Store.KeysOf(ctx, userID, "", 1000)
	if err != nil {
		uc.deps.Logger.Error("access keys: keys unreadable", "err", err.Error())
		return nil
	}
	return keys
}

// lastMethodRefusal — человек без пароля с одним ключом (сверх locked)
// остался бы без способа входа (Ф7-26).
func (uc *RevokeUseCase) lastMethodRefusal(ctx context.Context, userID domain.UserID, lockedCount int) error {
	has, err := uc.deps.Methods.HasPassword(ctx, userID)
	if err != nil {
		return mapStoreErr(uc.deps, "access_keys.Revoke.methods", err)
	}
	if has {
		return nil
	}
	n := lockedCount
	if n == 0 {
		n = len(uc.keysOf(ctx, userID))
	}
	if n <= 1 {
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRevoke, RefusalLastSignInMethod)
		return lastSignInMethod()
	}
	return nil
}

// commit — ОДНА транзакция под замком строк человека.
func (uc *RevokeUseCase) commit(ctx context.Context, userID domain.UserID, keyID domain.AccessKeyID, account domain.AccountID, actor string) (*anypb.Any, error) {
	w, err := uc.deps.Store.Writer(ctx)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.Revoke.writer", err)
	}
	defer func() { _ = w.Rollback(ctx) }()
	locked, err := w.LockKeysOf(ctx, userID)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.Revoke.lock", err)
	}
	if err := uc.lastMethodRefusal(ctx, userID, len(locked)); err != nil {
		return nil, err
	}
	removed, found, err := w.DeleteOwnedByID(ctx, userID, keyID)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.Revoke.delete", err)
	}
	if !found {
		uc.deps.Observer.AccessKeyRefusalObserved(LaneRevoke, RefusalNotFound)
		return nil, notFound(string(keyID))
	}
	if err := emitKeyAudit(ctx, w, AuditAccessKeyRevoked, removed, account, actor); err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.Revoke.audit", err)
	}
	if err := w.Commit(ctx); err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.Revoke.commit", err)
	}
	uc.deps.Observer.AccessKeyEventObserved(EventRevoked)
	return anypb.New(&iamv1.RevokeAccessKeyResponse{AccessKeyId: string(keyID)})
}
