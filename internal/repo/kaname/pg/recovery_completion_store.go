// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// recovery_completion_store.go — ТРАНЗАКЦИЯ ИСХОДА ЗАВЕРШЕНИЯ ВОССТАНОВЛЕНИЯ
// (порт `humansession.RecoveryCompletionStore`; задача PRO-Robotech/kaname#458,
// приёмка `docs/engineering/acceptance/unverified-address-passes-to-the-mailbox-owner.md`,
// Р3, Р4).
//
// # Одна транзакция — обычное восстановление и переход записи
//
// Транзакция открывается дверью писателя нескольких сессий: строка человека
// взята замком `FOR NO KEY UPDATE` ПЕРВЫМ оператором (`holdPersonOf`), и
// писатель сессии, писатель зеркала и операторы перехода работают над ОДНОЙ
// `pgx.Tx`. Порядок «личность → всё прочее» общий с удалением личности, сменой
// пароля и сбросами администратора облака; захват выдачи входа (`FOR SHARE`)
// ждёт фиксации перехода и читает уже заменённый материал (Р5).
//
// # Чего здесь нет — и почему
//
// Активация приглашения — композиция варианта использования зеркала
// (`user.ActivateInviteOnVerificationTx`): адаптер базы пакет варианта
// использования не импортирует, и функция активации подаётся построением
// (`InviteActivatorTx`) — композиционным корнем и стендами проб одной и той
// же функцией.

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// InviteActivatorTx — активация приглашения над писателем зеркала ОТКРЫТОЙ
// транзакции исхода. Отказ «приглашение негодно» — humansession.ErrInviteNotValid.
type InviteActivatorTx func(ctx context.Context, w kaname.Writer, pending domain.User) (humansession.InviteActivation, error)

// RecoveryCompletionStore — хранилище транзакции исхода завершения
// восстановления на пуле.
type RecoveryCompletionStore struct {
	registration *RegistrationStore
	activate     InviteActivatorTx
}

// NewRecoveryCompletionStore — адаптер поверх пула; activate обязательна: без
// неё переход строки `PENDING` неисполним, и молча деградировать он не вправе.
func NewRecoveryCompletionStore(pool *pgxpool.Pool, activate InviteActivatorTx) (*RecoveryCompletionStore, error) {
	if pool == nil || activate == nil {
		return nil, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument recovery completion store: pool and invite activator required")
	}
	return &RecoveryCompletionStore{registration: NewRegistrationStore(pool), activate: activate}, nil
}

// RecoveryCompletionWriter — см. порт.
func (s *RecoveryCompletionStore) RecoveryCompletionWriter(ctx context.Context, userID domain.UserID) (humansession.RecoveryCompletionWriter, error) {
	w, err := beginHumanSessionWriter(ctx, s.registration.pool)
	if err != nil {
		return nil, mapErr(err, "RecoveryCompletion.Writer", "")
	}
	held, err := holdPersonOf(ctx, w, userID)
	if err != nil {
		return nil, err
	}
	return &recoveryCompletionTx{RegistrationWriter: held, activate: s.activate}, nil
}

// recoveryCompletionTx — писатель сессии, писатель зеркала и операторы
// перехода над одной транзакцией.
type recoveryCompletionTx struct {
	*RegistrationWriter
	activate InviteActivatorTx
}

// AddressVerified — см. порт: отметка, прочитанная соединением ЭТОЙ
// транзакции после захвата строки (уровень `read committed` писателя сессии:
// оператор видит подтверждение, зафиксированное за ожидание захвата).
func (w *recoveryCompletionTx) AddressVerified(ctx context.Context, userID domain.UserID) (bool, error) {
	if userID == "" {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument user_id: required")
	}
	var at *time.Time
	err := w.tx.QueryRow(ctx, emailVerifiedAtSQL, string(userID)).Scan(&at)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return false, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", userID)
	}
	if err != nil {
		return false, mapErr(err, "RecoveryCompletion.AddressVerified", string(userID))
	}
	return at != nil, nil
}

// UserTokenHeld — см. порт: наличие строки личного токена соединением ЭТОЙ
// транзакции после захвата строки личности.
func (w *recoveryCompletionTx) UserTokenHeld(ctx context.Context, userID domain.UserID) (bool, error) {
	return userTokenHeldTx(ctx, w.tx, userID)
}

// RetireStartedEnrolmentsOf — см. порт. Порядок операторов: начатое
// заведение генератора, затем испытания регистрации ключа.
func (w *recoveryCompletionTx) RetireStartedEnrolmentsOf(ctx context.Context, userID domain.UserID) (humansession.RetiredEnrolments, error) {
	var out humansession.RetiredEnrolments
	var err error
	if out.SecondFactorRows, err = retireStartedEnrolmentTx(ctx, w.tx, userID); err != nil {
		return humansession.RetiredEnrolments{}, err
	}
	if out.AccessKeyChallengeRows, err = retireRegistrationChallengesTx(ctx, w.tx, userID); err != nil {
		return humansession.RetiredEnrolments{}, err
	}
	return out, nil
}

// ActivateInviteOnVerification — см. порт: функция активации над писателем
// зеркала той же транзакции.
func (w *recoveryCompletionTx) ActivateInviteOnVerification(ctx context.Context, pending domain.User) (humansession.InviteActivation, error) {
	return w.activate(ctx, w.MirrorWriter(), pending)
}
