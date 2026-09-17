// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// recovery_request.go — ЗАПРОС КОДА ВОССТАНОВЛЕНИЯ (Ф5-01, Ф5-02, Ф5-09; Р1,
// Р2, Р3): для подтверждённого адреса чеканится код со сроком нашей настройки,
// и письмо ложится в НАШУ очередь своим видом события — той же транзакцией,
// что строка кода. Ответ вызывающему один при любом исходе и постановки не
// ждёт (Р2): исход различим только клеткой счётчика.
//
// # Порядок внутри запроса — несущий
//
//	форма → ЧТЕНИЕ адреса (одно, обе полосы) → ответ; работа полосы «адрес
//	есть» — вытеснить прежние коды, записать код и намерение — уходит
//	диспетчером ВНЕ пути ответа
//
// Заблокированная личность код получает (Ф1-59): отказ она встретит на
// предъявлении, тем же текстом, что на входе; ответ на запрос — как у всех.

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// recoveryCodeIDPrefix — приставка идентификатора потока восстановления в
// дефисном каноне. Наружу не адресуется; в платформенный каталог не входит.
const recoveryCodeIDPrefix = "rcv"

// RequestRecoveryInput — форма запроса.
type RequestRecoveryInput struct {
	Email string
	// Source — адрес источника, как его прислал допущенный вызывающий.
	Source string
}

// RequestRecoveryUseCase — запрос кода.
type RequestRecoveryUseCase struct {
	store    Store
	codeTTL  time.Duration
	dispatch Dispatcher
	observer Observer
	now      func() time.Time
	logger   *slog.Logger
}

// RequestRecoveryDeps — зависимости; срок кода — величина настройки без
// умолчания (Ф5-06): нулевой — отказ построения.
type RequestRecoveryDeps struct {
	Store      Store
	CodeTTL    time.Duration
	Dispatcher Dispatcher
	Observer   Observer
	Now        func() time.Time
	Logger     *slog.Logger
}

// NewRequestRecoveryUseCase — построение с проверкой зависимостей.
func NewRequestRecoveryUseCase(d RequestRecoveryDeps) (*RequestRecoveryUseCase, error) {
	switch {
	case d.Store == nil:
		return nil, fmt.Errorf("recovery request: session store required")
	case d.CodeTTL <= 0:
		return nil, fmt.Errorf("recovery request: recovery code ttl must be positive")
	case d.Dispatcher == nil:
		return nil, fmt.Errorf("recovery request: dispatcher required")
	}
	if d.Observer == nil {
		d.Observer = NopObserver{}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return &RequestRecoveryUseCase{
		store: d.Store, codeTTL: d.CodeTTL, dispatch: d.Dispatcher, observer: d.Observer, now: d.Now, logger: d.Logger,
	}, nil
}

// Execute — запрос кода. Ошибка возвращается ТОЛЬКО на отказ формы и на
// недоступность хранилища при чтении; исход самого запроса наружу не выходит.
func (uc *RequestRecoveryUseCase) Execute(ctx context.Context, in RequestRecoveryInput) error {
	addressKey := AddressKey(in.Email)
	if addressKey == "" {
		return FieldRequired("email")
	}
	target, found, err := uc.store.RecoveryTarget(ctx, domain.Email(addressKey))
	if err != nil {
		uc.observer.RecoveryRequestObserved(RecoveryRequestStoreFailed)
		return ErrStoreUnavailable
	}
	switch {
	case !found:
		uc.observer.RecoveryRequestObserved(RecoveryRequestNoRow)
		return nil
	case !target.EmailVerified:
		// Ф1-25: код — для подтверждённого адреса. Ответ тот же.
		uc.observer.RecoveryRequestObserved(RecoveryRequestUnverified)
		return nil
	}
	issuedAt := uc.now().UTC()
	// Постановка — ВНЕ пути ответа (Р2). Чеканка тоже там: код никому не нужен
	// раньше письма, а её стоимость — часть той же работы.
	uc.dispatch.Dispatch(ctx, func(ctx context.Context) {
		uc.mintAndEnqueue(ctx, target.User, issuedAt)
	})
	return nil
}

// mintAndEnqueue — чеканка, вытеснение прежних кодов, строка кода и намерение
// письма ОДНОЙ транзакцией (Ф5-09).
func (uc *RequestRecoveryUseCase) mintAndEnqueue(ctx context.Context, user domain.User, issuedAt time.Time) {
	value, err := domain.NewRecoveryCodeValue()
	if err != nil {
		uc.observer.RecoveryRequestObserved(RecoveryRequestStoreFailed)
		uc.logger.Error("recovery request: code not minted", "err", err.Error(), "user_id", string(user.ID))
		return
	}
	code := domain.RecoveryCode{
		ID: domain.RecoveryCodeID(ids.NewHyphenID(recoveryCodeIDPrefix)), UserID: user.ID, Digest: value.Digest(),
		IssuedAt: issuedAt, ExpiresAt: issuedAt.Add(uc.codeTTL),
	}
	if err := uc.write(ctx, user, code, value); err != nil {
		uc.observer.RecoveryRequestObserved(RecoveryRequestStoreFailed)
		uc.logger.Error("recovery request: code and letter not recorded", "err", err.Error(), "user_id", string(user.ID))
		return
	}
	uc.observer.RecoveryRequestObserved(RecoveryRequestQueued)
}

func (uc *RequestRecoveryUseCase) write(ctx context.Context, user domain.User, code domain.RecoveryCode, value domain.RecoveryCodeValue) error {
	w, err := uc.store.Writer(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = w.Rollback(ctx) }()
	if _, err := w.SupersedeRecoveryCodes(ctx, user.ID); err != nil {
		return err
	}
	if err := w.InsertRecoveryCode(ctx, code); err != nil {
		return err
	}
	if err := w.EmitRecoveryMail(ctx, RecoveryMailIntent{
		UserID: user.ID, AccountID: user.AccountID, To: string(user.Email), Code: value, ValidFor: uc.codeTTL,
	}); err != nil {
		return err
	}
	return w.Commit(ctx)
}
