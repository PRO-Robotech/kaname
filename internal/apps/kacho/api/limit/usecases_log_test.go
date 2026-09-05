// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package limit

// usecases_log_test.go — отказ читающей полосы пределов ОСТАВЛЯЕТ СТРОКУ, и
// строка называет причину (#666).
//
// # Предмет
//
// Тянущий пределы отказывал на каждом подъёме каждого домена, и назвать причину
// было нечем: соответствующей строки в журнале владельца величин нет ни одной.
// Комментарии на пути перевода ошибок обещают журналу деталь — а логгера нет ни
// у хранилища, ни у use-case, и журнала доступа gRPC у сервиса нет вовсе. Деталь
// уничтожалась до того, как становилась наблюдаемой.
//
// # Что утверждается
//
// НАБЛЮДАЕМОЕ с обеих сторон: причина попадает в журнал сервера и НЕ попадает на
// провод. Порознь каждая половина зеленела бы на дефекте другой — молчаливый
// журнал при честном коде либо утечка драйвера клиенту.
//
// Рядом контроль: успех строки не оставляет. Без него годился бы логгер, пишущий
// на каждом вызове, — журнал зарос бы, и отказ в нём было бы не найти, то есть
// свойство «отказ заметен» потерялось бы тем же средством, которым его вводят.

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// failingChangedRepo — хранилище, отказывающее ровно на чтении дельты. Остальные
// глаголы наследуются у обычного дублёра: подменять больше нужного значило бы
// проверять не тот путь.
type failingChangedRepo struct {
	*fakeLimitRepo
	err error
}

func (f *failingChangedRepo) ChangedSince(context.Context, int64, int) ([]domain.Limit, int64, error) {
	f.touched = true
	return nil, 0, f.err
}

// failingStatedRepo — хранилище, отказывающее на чтении назначенных величин.
type failingStatedRepo struct {
	*fakeLimitRepo
	err error
}

func (f *failingStatedRepo) StatedFor(context.Context, string) ([]domain.Limit, bool, error) {
	f.touched = true
	return nil, false, f.err
}

// captureLog — журнал в память плюс сам логгер.
func captureLog() (*bytes.Buffer, *slog.Logger) {
	var buf bytes.Buffer
	return &buf, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

// TestListChanged_StoreFailure_NamesTheCauseInTheLog — отказ дельты называет
// причину серверу и не называет её клиенту.
func TestListChanged_StoreFailure_NamesTheCauseInTheLog(t *testing.T) {
	// Так выглядит цепочка после моста SQLSTATE: код состояния плюс контекст.
	cause := fmt.Errorf("read changed limits: %w",
		iamerr.Wrapf(iamerr.ErrInternal, "database error: sqlstate 53300"))

	buf, logger := captureLog()
	repo := &failingChangedRepo{fakeLimitRepo: newFakeRepo(), err: cause}

	_, err := NewListChangedUseCase(repo, fakeCursors{}).
		WithQuotaReaderChecker(&fakeChecker{answer: true}).
		WithLogger(logger).
		Execute(callerCtx(), "", 10)

	require.Error(t, err)
	require.Equal(t, codes.Internal, grpcstatus.Code(err))
	require.Equal(t, "internal error", grpcstatus.Convert(err).Message(),
		"текст INTERNAL фиксирован — деталь на провод не идёт")

	logged := buf.String()
	require.Contains(t, logged, "sqlstate 53300",
		"причина отказа обязана дожить до журнала: без неё «отказ есть, назвать нечего» "+
			"становится штатным состоянием")
	require.Contains(t, logged, "ListChangedSince",
		"строка обязана называть полосу: иначе непонятно, что именно отказало")
}

// TestListChanged_StoreUnavailable_NamesTheCauseInTheLog — вторая полоса того же
// свойства: недоступность тоже опаковая для клиента, значит причина обязана быть
// у сервера.
func TestListChanged_StoreUnavailable_NamesTheCauseInTheLog(t *testing.T) {
	cause := fmt.Errorf("read changed limits: %w",
		iamerr.Wrapf(iamerr.ErrUnavailable, "database unavailable"))

	buf, logger := captureLog()
	repo := &failingChangedRepo{fakeLimitRepo: newFakeRepo(), err: cause}

	_, err := NewListChangedUseCase(repo, fakeCursors{}).
		WithQuotaReaderChecker(&fakeChecker{answer: true}).
		WithLogger(logger).
		Execute(callerCtx(), "", 10)

	require.Equal(t, codes.Unavailable, grpcstatus.Code(err))
	require.Contains(t, buf.String(), "read changed limits",
		"контекст отказа обязан дожить до журнала")
}

// TestListChanged_Success_LeavesNoLine — контроль: успех строки не оставляет.
func TestListChanged_Success_LeavesNoLine(t *testing.T) {
	buf, logger := captureLog()
	repo := newFakeRepo()

	_, err := NewListChangedUseCase(repo, fakeCursors{}).
		WithQuotaReaderChecker(&fakeChecker{answer: true}).
		WithLogger(logger).
		Execute(callerCtx(), "", 10)

	require.NoError(t, err)
	require.Empty(t, strings.TrimSpace(buf.String()),
		"успешное чтение дельты журнала не касается")
}

// TestResolve_StoreFailure_NamesTheCauseInTheLog — та же полоса у резолва: он
// стоит на пути МУТАЦИИ домена, и его немой отказ обходится дороже.
func TestResolve_StoreFailure_NamesTheCauseInTheLog(t *testing.T) {
	buf, logger := captureLog()
	repo := &failingStatedRepo{
		fakeLimitRepo: newFakeRepo(),
		err: fmt.Errorf("read stated limits: %w",
			iamerr.Wrapf(iamerr.ErrInternal, "database error: sqlstate 57P03")),
	}

	_, err := NewResolveUseCase(repo).
		WithQuotaReaderChecker(&fakeChecker{answer: true}).
		WithLogger(logger).
		Execute(callerCtx(), "prj-x", "vpc")

	require.Error(t, err)
	require.Equal(t, "internal error", grpcstatus.Convert(err).Message())
	require.Contains(t, buf.String(), "sqlstate 57P03")
	require.Contains(t, buf.String(), "Resolve")
}

// TestResolve_TenantFacingRefusal_LeavesNoLine — контроль второй стороны: отказ,
// который САМ называет свою причину клиенту, журнала не касается.
//
// Иначе строка появлялась бы на каждом обращении к несуществующему проекту, то
// есть на обычном поведении арендатора, и в ней потонула бы та единственная,
// из-за которой всё и заводилось.
func TestResolve_TenantFacingRefusal_LeavesNoLine(t *testing.T) {
	buf, logger := captureLog()
	repo := newFakeRepo()
	repo.knownObj = false // проект не найден → отказ несёт свою причину на проводе

	_, err := NewResolveUseCase(repo).
		WithQuotaReaderChecker(&fakeChecker{answer: true}).
		WithLogger(logger).
		Execute(callerCtx(), "prj-missing", "vpc")

	require.Equal(t, codes.NotFound, grpcstatus.Code(err))
	require.Empty(t, strings.TrimSpace(buf.String()),
		"отказ, называющий причину клиенту, в журнале не повторяется")
}
