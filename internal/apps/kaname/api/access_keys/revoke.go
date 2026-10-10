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
// (Ф7-36) → человек → операция. Внутри операции ОДНОЙ транзакцией: строка
// личности под замком первой (раньше строк ключей и сессий — порядок
// «личность → дети»), строки ключей человека под замком (сериализация
// «сосчитать способы — снять», ban #10), последний способ входа не снимается
// (Ф7-26), снятие суженное владельцем — чужой и несуществующий неразличимы
// (Ф7-27), записи сессии человека сняты и отсечка поставлена причиной
// `access-key-revoked` (Ф13 Р8), событие аудита. Слот потолка возвращает
// удаление строки — триггером, в той же транзакции.
//
// # Какие сессии гаснут
//
// Р8 гасит все ПРОЧИЕ сессии человека, а текущую оставляет. Номера записи
// сессии у глагола RPC нет (шапка `iface.go`), и текущая выводится из
// предъявленного удостоверения: его выпуск называет семейство, семейство —
// сессию, в которой шла церемония (`SessionOfCredential`). Так названа
// текущая у вызывающего, предъявившего токен нашей церемонии сам.
//
// Личность, переданная краем, выпуска не несёт: край передаёт личность, а не
// номер выпуска и не номер записи. Тогда отличить текущую нечем, и гаснут ВСЕ
// записи человека — сторона, закрывающая доступ: ключ снимают, лишившись
// устройства, и сессия держателя устройства неотличима от текущей. Номер
// записи вызывающего от края — kaname#677.

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
	// ActingCredential — идентификатор выпуска удостоверения, которым
	// вызывающий аутентифицирован (`jti`, проверенный целиком читателем
	// предъявленного); пусто — личность передана краем и выпуска не несёт.
	// По нему находится текущая сессия, которую снятие оставляет (Р8).
	ActingCredential string
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
	keys, err := uc.keysOf(ctx, in.UserID)
	if err != nil {
		return nil, err
	}
	var owned bool
	for _, k := range keys {
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
	if err := uc.lastMethodRefusal(ctx, in.UserID); err != nil {
		return nil, err
	}
	if err := uc.ops.Create(ctx, op); err != nil {
		return nil, err
	}
	actor := string(in.Actor)
	acting := in.ActingCredential
	operations.Run(ctx, uc.ops, op.ID, func(ctx context.Context) (*anypb.Any, error) {
		return uc.commit(ctx, in.UserID, keyID, user.AccountID, actor, acting)
	})
	return &op, nil
}

// keysOf — ключи человека. Ошибка чтения — внутренняя ошибка (текст
// хранилища только в журнал): пустой список вместо неё дал бы отказ о
// предмете — «ключа нет» либо «последний способ входа», — не установленный
// ничем (kaname#586).
func (uc *RevokeUseCase) keysOf(ctx context.Context, userID domain.UserID) ([]domain.AccessKey, error) {
	keys, _, err := uc.deps.Store.KeysOf(ctx, userID, "", 1000)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.Revoke.keys", err)
	}
	return keys, nil
}

// lastMethodRefusal — синхронная сверка ДО операции, портом пула (транзакции
// ещё нет): человек без пароля с одним ключом остался бы без способа входа
// (Ф7-26). Она только классифицирует — инвариант держит сверка под замком
// внутри транзакции (`lockedLastMethodRefusal`).
func (uc *RevokeUseCase) lastMethodRefusal(ctx context.Context, userID domain.UserID) error {
	has, err := uc.deps.Methods.HasPassword(ctx, userID)
	if err != nil {
		return mapStoreErr(uc.deps, "access_keys.Revoke.methods", err)
	}
	if has {
		return nil
	}
	keys, err := uc.keysOf(ctx, userID)
	if err != nil {
		return err
	}
	return uc.judgeLastMethod(false, len(keys))
}

// lockedLastMethodRefusal — та же сверка ВНУТРИ транзакции снятия: строки
// ключей уже под замком (locked), и пароль читается тем же соединением
// (`RevokeWriter.HasPassword`). Ни одного чтения портом пула здесь нет: второе
// соединение изнутри транзакции, держащей замки личности и ключей, — взаимная
// блокировка с входами ключом, которой база не видит (kaname#669).
func (uc *RevokeUseCase) lockedLastMethodRefusal(ctx context.Context, w RevokeWriter, userID domain.UserID, locked int) error {
	has, err := w.HasPassword(ctx, userID)
	if err != nil {
		return mapStoreErr(uc.deps, "access_keys.Revoke.methods", err)
	}
	return uc.judgeLastMethod(has, locked)
}

// judgeLastMethod — правило Ф7-26 одно на обе сверки: без пароля ключ, который
// снимают, обязан быть не последним.
func (uc *RevokeUseCase) judgeLastMethod(hasPassword bool, keys int) error {
	if hasPassword || keys > 1 {
		return nil
	}
	uc.deps.Observer.AccessKeyRefusalObserved(LaneRevoke, RefusalLastSignInMethod)
	return lastSignInMethod()
}

// commit — ОДНА транзакция под замком строк человека.
func (uc *RevokeUseCase) commit(ctx context.Context, userID domain.UserID, keyID domain.AccessKeyID, account domain.AccountID, actor, acting string) (*anypb.Any, error) {
	w, err := uc.deps.Store.RevokeWriter(ctx, userID)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.Revoke.writer", err)
	}
	defer func() { _ = w.Rollback(ctx) }()
	locked, err := w.LockKeysOf(ctx, userID)
	if err != nil {
		return nil, mapStoreErr(uc.deps, "access_keys.Revoke.lock", err)
	}
	if err := uc.lockedLastMethodRefusal(ctx, w, userID, len(locked)); err != nil {
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
	if err := uc.endSessionsOf(ctx, w, userID, actor, acting); err != nil {
		return nil, err
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

// endSessionsOf — снятие записей сессии человека, кроме текущей, и его
// отсечка (Ф13 Р8) в транзакции снятия ключа. Текущая — запись, в которой
// выпущено предъявленное удостоверение (шапка файла); не названа — снимаются
// все. Момент снятия — часы глагола; момент отсечки — тот же, что у смены
// пароля: на единицу разрешения раньше первой аутентификации личности нашей
// посадкой (`domain.CutoffBelowFirstAuthentication`), — им снимаются носители
// прежней посадки, а записи нашей снимает дверь снятия, и текущую отсечка не
// задевает. Памяти первой аутентификации нет — отсечка не ставится: её момент
// выводится только из сохранённого момента (часы процесса отсечку не датируют —
// перепись `revocationpolicy`), а память пишет каждая выдача, и без неё у
// личности нет ни одной выданной нами сессии; расхождение — находка о посеве,
// и оно пишется в журнал.
func (uc *RevokeUseCase) endSessionsOf(ctx context.Context, w RevokeWriter, userID domain.UserID, actor, acting string) error {
	now := uc.deps.Now().UTC()
	var keep domain.HumanSessionID
	if acting != "" {
		current, found, err := w.SessionOfCredential(ctx, userID, acting)
		if err != nil {
			return mapStoreErr(uc.deps, "access_keys.Revoke.current_session", err)
		}
		if found {
			keep = current
		}
	}
	if _, err := w.EndOtherSessions(ctx, userID, keep, now, domain.RevokeReasonAccessKeyRevoked); err != nil {
		return mapStoreErr(uc.deps, "access_keys.Revoke.sessions", err)
	}
	first, found, err := w.FirstAuthentication(ctx, userID)
	if err != nil {
		return mapStoreErr(uc.deps, "access_keys.Revoke.first_authentication", err)
	}
	if !found {
		uc.deps.Logger.WarnContext(ctx, "access key revoke: no first-authentication memory for the subject; cutoff not written",
			"user_id", string(userID))
		return nil
	}
	if err := w.UpsertCutoff(ctx, domain.UserTokenRevocation{
		UserID: userID, RevokeBefore: domain.CutoffBelowFirstAuthentication(first),
		Reason: domain.RevokeReasonAccessKeyRevoked, RevokedBy: domain.UserID(actor),
	}, domain.UserID(actor)); err != nil {
		return mapStoreErr(uc.deps, "access_keys.Revoke.cutoff", err)
	}
	return nil
}
