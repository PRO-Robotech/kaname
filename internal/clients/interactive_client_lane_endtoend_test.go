// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients

// interactive_client_lane_endtoend_test.go — полоса ЦЕЛИКОМ: недоступный
// поставщик доезжает до вызывающего кодом `UNAVAILABLE` (задача #2481).
//
// # Зачем сверх двух половин
//
// Половины порознь доказаны: производитель ставит признак
// (`hydra_interactive_clients_unavailable_test.go`), use-case его чтит
// (`usecases_test.go`). Но «признак ставит» и «признак чтут» — два утверждения
// о РАЗНЫХ предметах, и между ними остаётся шов: производитель мог бы ставить
// один признак, а переводчик читать другой, и обе пробы остались бы зелёными.
// Здесь работает НАСТОЯЩИЙ производитель, поэтому шва нет.
//
// Проба живёт в этом пакете, а не рядом с use-case, по построению: адаптер
// импортирует use-case, обратное направление было бы кольцом.

import (
	"context"
	"net/http"
	"testing"

	gstatuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	interactiveclient "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// laneRepo — хранилище, до которого дойти не должны: поставщика спрашивают
// ПЕРВЫМ, и его отказ обязан прервать вызов до записи. `inserted` это и
// показывает — дублёр, который бы просто отдавал ошибку, не показал бы ничего.
type laneRepo struct{ inserted bool }

func (r *laneRepo) Get(context.Context, domain.InteractiveClientID) (domain.InteractiveClient, error) {
	return domain.InteractiveClient{}, nil
}
func (r *laneRepo) List(context.Context, int, string, string) ([]domain.InteractiveClient, string, error) {
	return nil, "", nil
}
func (r *laneRepo) Insert(_ context.Context, c domain.InteractiveClient, _ domain.LoginVerifier) (domain.InteractiveClient, error) {
	r.inserted = true
	return c, nil
}
func (r *laneRepo) Update(_ context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error) {
	return c, nil
}
func (r *laneRepo) Delete(context.Context, domain.InteractiveClientID) (domain.InteractiveClient, bool, error) {
	return domain.InteractiveClient{}, false, nil
}

// laneOps — журнал операций, запоминающий терминальный исход.
type laneOps struct{ errMarked bool }

func (o *laneOps) Create(context.Context, operations.Operation) error { return nil }
func (o *laneOps) CreateWithPrincipal(context.Context, operations.Operation, operations.Principal) error {
	return nil
}
func (o *laneOps) Get(context.Context, string) (*operations.Operation, error) {
	return nil, operations.ErrNotFound
}
func (o *laneOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}
func (o *laneOps) MarkDone(context.Context, string, *anypb.Any) error { return nil }
func (o *laneOps) MarkError(context.Context, string, *gstatuspb.Status) error {
	o.errMarked = true
	return nil
}
func (o *laneOps) Cancel(context.Context, string) error { return nil }

func TestInteractiveClientLane_ProviderUnreachable_ReachesTheCallerAsUnavailable(t *testing.T) {
	repo := &laneRepo{}
	ops := &laneOps{}
	prov := interactiveProvider(unreachableURL(t))

	uc := interactiveclient.NewCreateUseCase(repo, prov, ops, []string{"https://api.example"}, nil)
	_, err := uc.Execute(context.Background(), &iamv1.CreateInteractiveClientRequest{
		Name:         "console-a",
		RedirectUris: []string{"https://api.example/cb"},
	})

	if err == nil {
		t.Fatal("недостижимый поставщик обязан прервать создание")
	}
	if code := status.Code(err); code != codes.Unavailable {
		t.Fatalf("вызывающий получил %s вместо Unavailable: на крае это 500 вместо 503, "+
			"а на 500 клиент не повторяет (ошибка: %v)", code, err)
	}
	if repo.inserted {
		t.Error("строка записана при незарегистрированном клиенте: имя занято ничем")
	}
	if !ops.errMarked {
		t.Error("операция обязана быть помечена терминальным отказом, а не оставлена на вечный опрос")
	}
}

// Законный близнец на той же полосе и через того же настоящего производителя:
// отвергнутый вход повторяемым не объявляется.
func TestInteractiveClientLane_ProviderRejectedInput_IsNotUnavailable(t *testing.T) {
	repo := &laneRepo{}
	ops := &laneOps{}
	prov := interactiveProvider(srvWithStatus(t, http.StatusBadRequest).URL)

	uc := interactiveclient.NewCreateUseCase(repo, prov, ops, []string{"https://api.example"}, nil)
	_, err := uc.Execute(context.Background(), &iamv1.CreateInteractiveClientRequest{
		Name:         "console-a",
		RedirectUris: []string{"https://api.example/cb"},
	})

	if err == nil {
		t.Fatal("отвергнутый вход обязан дать отказ")
	}
	if code := status.Code(err); code == codes.Unavailable {
		t.Fatalf("отвергнутый вход объявлен повторяемым: вызывающий будет повторять вечно (%v)", err)
	}
	if repo.inserted {
		t.Error("строка записана при незарегистрированном клиенте")
	}
}
