// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks

// lifecycle_deadline.go — предел времени на обращение хуков заведения и
// восстановления человека к своему use-case (задача kaname#441).
//
// Хуки, чеканящие токен, идут под своим пределом на каждом обращении к базе
// ([WithCallDeadline], kaname#389). Хуки заведения по первому входу и
// завершения восстановления собираются на том же слушателе, их зовёт
// поставщик личности, и контекст запроса несёт ЕГО срок — либо никакого. Без
// своего предела неотвечающая база держала их обработчики столько, сколько ждал
// поставщик.
//
// Предмет предела — синхронная часть use-case: чтение строк личности и запись
// операции. Работу самой операции ведёт исполнитель операций, и срока
// вызывающего она не наследует (`operations.Run`): предел обращения её не
// обрывает.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
)

// ErrLifecyclePortNotWired — порт хука заведения или восстановления не подан
// сборке.
var ErrLifecyclePortNotWired = errors.New("iamhooks: lifecycle hook port is not wired")

// LifecyclePorts — всё, чем хуки заведения и восстановления человека
// обращаются к своему use-case.
//
// Перечень закрыт типом, как у [IssuancePorts]: сборка хуков получает use-case
// только через эти поля, и [WithLifecycleDeadline] оборачивает каждое. Порт,
// заведённый позже рядом, попадает под пробы обёртки и сборки обходом полей
// этого типа, а не по памяти.
type LifecyclePorts struct {
	// Provisioner — заведение человека по первому входу.
	Provisioner UserProvisioner
	// Recovery — завершение восстановления доступа.
	Recovery RecoveryCompleter
}

// WithLifecycleDeadline оборачивает КАЖДЫЙ порт хуков заведения и
// восстановления одним пределом на вызов.
//
// Неположительный предел — отказ построения тем же отказом, что у полос
// выдачи ([revocationpolicy.ErrLimitNotPositive]): контекст с таким сроком
// истекал бы в момент вызова, и хук отказывал бы каждому входу на первом
// запросе, а не на старте.
//
// Неподанный порт — тоже отказ построения ([ErrLifecyclePortNotWired]) с именем
// порта, а не пропуск: ветви «порт не провязан» у этих хуков нет, и хук без
// порта ломался бы на первом запросе поставщика, а не на старте.
func WithLifecycleDeadline(p LifecyclePorts, timeout time.Duration) (LifecyclePorts, error) {
	if timeout <= 0 {
		return LifecyclePorts{}, fmt.Errorf("iamhooks: lifecycle hooks: %w, got %s",
			revocationpolicy.ErrLimitNotPositive, timeout)
	}
	if p.Provisioner == nil {
		return LifecyclePorts{}, fmt.Errorf("%w: Provisioner", ErrLifecyclePortNotWired)
	}
	if p.Recovery == nil {
		return LifecyclePorts{}, fmt.Errorf("%w: Recovery", ErrLifecyclePortNotWired)
	}
	return LifecyclePorts{
		Provisioner: deadlineProvisioner{inner: p.Provisioner, timeout: timeout},
		Recovery:    deadlineRecovery{inner: p.Recovery, timeout: timeout},
	}, nil
}

// deadlineProvisioner — заведение человека со СВОИМ пределом на вызов.
type deadlineProvisioner struct {
	inner   UserProvisioner
	timeout time.Duration
}

func (d deadlineProvisioner) Provision(ctx context.Context, in ProvisionInput) error {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.Provision(ctx, in)
}

// deadlineRecovery — завершение восстановления со СВОИМ пределом на вызов.
type deadlineRecovery struct {
	inner   RecoveryCompleter
	timeout time.Duration
}

func (d deadlineRecovery) CompleteRecovery(ctx context.Context, in RecoveryInput) error {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	return d.inner.CompleteRecovery(ctx, in)
}
