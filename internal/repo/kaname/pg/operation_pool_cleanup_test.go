// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

// Срок уборки отделён от приёмочного условия: штатный исполнитель может
// работать 4 минуты, затем повторять terminalWrite 30 секунд с дополнительной
// попыткой записи до 5 секунд. Пять минут ограничивают уборку, сохраняя
// исходные сроки операции и проверок.
const operationPoolCleanupBudget = 5 * time.Minute

type operationPoolCleanupReporter interface {
	Errorf(string, ...any)
}

// Глобальное ожидание используют только непараллельные наблюдаемые фикстуры GD.
// Фикстуры, намеренно удерживающие другого исполнителя, его не устанавливают.
// Ошибка ожидания объявляется до закрытия пула при конечной уборке и не может
// считаться успешным завершением.
func closeOperationPoolAfterDrain(t operationPoolCleanupReporter, wait func(context.Context) error, closePool func()) {
	ctx, cancel := context.WithTimeout(context.Background(), operationPoolCleanupBudget)
	defer cancel()
	if err := wait(ctx); err != nil {
		t.Errorf("уборка пула операций: принятая работа не завершилась до закрытия пула: %v", err)
	}
	closePool()
}

// Настоящий Worker вызывает репозиторий после возврата своей функции.
// Барьер удерживает терминальную запись в БД; отмена контекста исполнителя
// не считается завершением записи.
type gatedOperationTerminalRepo struct {
	operations.Repo
	entered, release chan struct{}
	enteredOnce      sync.Once
	closed           atomic.Bool
	wroteAfterClose  atomic.Bool
}

func (r *gatedOperationTerminalRepo) MarkDone(ctx context.Context, _ string, _ *anypb.Any) error {
	r.enteredOnce.Do(func() { close(r.entered) })
	select {
	case <-r.release:
		r.wroteAfterClose.Store(r.closed.Load())
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type operationCleanupWitnessReporter struct {
	mu     sync.Mutex
	failed bool
	errors []string
}

func (r *operationCleanupWitnessReporter) Errorf(format string, args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.failed = true
	r.errors = append(r.errors, fmt.Sprintf(format, args...))
}

// Прежний pool.Close служит исполнимым отрицательным контролем. Новый путь
// обязан дождаться терминальной записи настоящего исполнителя даже после
// возврата функции и отмены родителя. Ранее объявленный отказ сохраняется.
func TestOperationPoolCleanupWaitsForTerminalWrite(t *testing.T) {
	for _, alreadyFailed := range []bool{false, true} {
		for _, drain := range []bool{false, true} {
			t.Run(fmt.Sprintf("failed_%t/drain_%t", alreadyFailed, drain), func(t *testing.T) {
				worker := operations.NewWorker()
				defer worker.Stop()
				repo := &gatedOperationTerminalRepo{entered: make(chan struct{}), release: make(chan struct{})}
				var release sync.Once
				unblock := func() { release.Do(func() { close(repo.release) }) }
				defer unblock()
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				functionReturned := make(chan struct{})
				operations.RunWithWorker(worker, parent, repo, "cleanup-witness", func(context.Context) (*anypb.Any, error) {
					close(functionReturned)
					return nil, nil
				})
				bound, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				select {
				case <-repo.entered:
				case <-bound.Done():
					t.Fatal("настоящий исполнитель не приступил к терминальной записи")
				}
				<-functionReturned
				if alreadyFailed {
					cancel()
					require.ErrorIs(t, parent.Err(), context.Canceled)
				}
				// Ранее объявленный отказ моделирует неуспешную проверку со сроком
				// 20 секунд. Настоящий провал testing.T здесь не скрывается.
				reporter := &operationCleanupWitnessReporter{failed: alreadyFailed}
				closed := make(chan struct{})
				closePool := func() { repo.closed.Store(true); close(closed) }
				if !drain {
					closePool()
					unblock()
				} else {
					waiting, finished := make(chan struct{}), make(chan struct{})
					go func() {
						defer close(finished)
						closeOperationPoolAfterDrain(reporter, func(ctx context.Context) error {
							deadline, ok := ctx.Deadline()
							if !ok || time.Until(deadline) < 4*time.Minute || ctx.Err() != nil {
								return fmt.Errorf("уборка унаследовала отмену или потеряла независимый срок")
							}
							close(waiting)
							return worker.Wait(ctx)
						}, closePool)
					}()
					select {
					case <-waiting:
					case <-bound.Done():
						t.Fatal("уборка не приступила к ожиданию исполнителя")
					}
					select {
					case <-closed:
						t.Fatal("пул закрыт, пока терминальная запись удерживалась барьером")
					default:
					}
					unblock()
					select {
					case <-finished:
					case <-bound.Done():
						t.Fatal("уборка не завершилась после терминальной записи")
					}
				}
				require.NoError(t, worker.Wait(bound))
				require.True(t, repo.closed.Load())
				require.Equal(t, !drain, repo.wroteAfterClose.Load(), "прежний путь должен воспроизвести гонку; ожидание должно её предотвратить")
				require.Equal(t, alreadyFailed, reporter.failed, "уборка не может отменить ранее объявленный отказ проверки")
				require.Empty(t, reporter.errors)
			})
		}
	}
}

func TestOperationPoolCleanupReportsDrainFailureBeforeClose(t *testing.T) {
	reporter := &operationCleanupWitnessReporter{}
	closed := false
	closeOperationPoolAfterDrain(reporter, func(context.Context) error {
		return context.DeadlineExceeded
	}, func() {
		require.True(t, reporter.failed, "закрытие после неуспешного ожидания требует явной ошибки уборки")
		closed = true
	})
	require.True(t, closed)
	require.Len(t, reporter.errors, 1)
	require.Contains(t, reporter.errors[0], context.DeadlineExceeded.Error())
}
