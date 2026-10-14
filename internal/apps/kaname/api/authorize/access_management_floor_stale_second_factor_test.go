// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_management_floor_stale_second_factor_test.go — порог управления
// доступом судит УРОВЕНЬ сессии, а не давность второго фактора (kaname#754).
//
// Страница решений (`advanced/design-decisions.mdx`, строка «Step-up») объявляет:
// управление доступом требует сессии уровня `2`, сессии одного пароля мало.
// Свежести второго фактора она не требует, и страница порога
// (`architecture/authz.mdx#step-up`) говорит то же: «свежесть предъявления этот
// порог не проверяет». Проба держит именно это условие на точке, где служба
// его исполняет сама, — на пороге внутреннего слушателя для глаголов,
// фронтируемых краем: выдача и отзыв роли администратора облака.
//
// Исходов три, и каждый — наблюдаемый ответ порога:
//
//   - сессия `2` с давним вторым фактором — проходит;
//   - та же сессия со свежим вторым фактором — проходит так же (исход от давности
//     не зависит);
//   - сессия `1` со свежим предъявлением — получает указание повысить уровень
//     (законный близнец: порог жив, каталог провязан, режим боевой).
//
// Давность передаётся так, как её передаёт край: доверенным ключом метаданных
// момента второго фактора. Порог, который начал бы его читать с окном свежести,
// сделал бы первый исход отказом — и проба покраснела бы.
package authorize_test

import (
	"context"
	"strconv"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/principalwire"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
)

// accessManagementVerbs — глаголы управления доступом, фронтируемые краем: их
// порог служба исполняет на своём слушателе.
var accessManagementVerbs = []string{
	"/kaname.cloud.iam.v1.InternalClusterService/GrantAdmin",
	"/kaname.cloud.iam.v1.InternalClusterService/RevokeAdmin",
}

// publicAccessManagementVerbs — глаголы управления доступом публичной
// поверхности: их порог исполняет край, служба лишь объявляет его каталогом.
// Проба сверяет объявленный уровень со страницей решений.
var publicAccessManagementVerbs = []string{
	"kaname.cloud.iam.v1.AccessBindingService/Create",
	"kaname.cloud.iam.v1.AccessBindingService/Update",
	"kaname.cloud.iam.v1.AccessBindingService/Delete",
}

// sessionCtx — вызов от края за человека: доверенные уровень и тип субъекта и
// момент второго фактора в метаданных, как их пересылает край.
func sessionCtx(acr string, secondFactorAt time.Time) context.Context {
	md := metadata.Pairs(principalwire.MetaTokenMfaAt, strconv.FormatInt(secondFactorAt.Unix(), 10))
	ctx := metadata.NewIncomingContext(context.Background(), md)
	ctx = grpcsrv.WithTrustedACR(ctx, acr, true)
	return grpcsrv.WithTrustedPrincipal(ctx, operations.Principal{ID: "usr_alice", Type: "user"}, true)
}

func floorVerdict(t *testing.T, floor *authzguard.ACRFloor, ctx context.Context, method string) error {
	t.Helper()
	reached := false
	_, err := floor.Unary()(ctx, nil, &grpc.UnaryServerInfo{FullMethod: method},
		func(context.Context, any) (any, error) {
			reached = true
			return nil, nil
		})
	if err == nil && !reached {
		t.Fatalf("%s: порог не отказал и не передал вызов дальше", method)
	}
	return err
}

func TestAccessManagementFloor_StaleSecondFactorGetsTheDecisionPageOutcome(t *testing.T) {
	reg, err := seed.LoadPermissionRegistry(context.Background(), nil)
	if err != nil {
		t.Fatalf("каталог прав: %v", err)
	}
	fronted := map[string]bool{}
	for _, m := range authzguard.GatewayFrontedInternalRPCs() {
		fronted[m] = true
	}
	for _, m := range accessManagementVerbs {
		if !fronted[m] {
			t.Fatalf("предпосылка: %s не фронтируется краем — порог службы его не судит", m)
		}
		if got := reg.RequiredACRMin(m[1:]); got != "2" {
			t.Fatalf("предпосылка: каталог объявляет %s уровень %q, страница решений — \"2\"", m, got)
		}
	}
	for _, m := range publicAccessManagementVerbs {
		if got := reg.RequiredACRMin(m); got != "2" {
			t.Errorf("%s: каталог объявляет уровень %q, страница решений — \"2\"", m, got)
		}
	}

	floor := authzguard.NewACRFloor(reg, authzguard.GatewayFrontedInternalRPCs()).WithProductionMode(true)
	now := time.Now()
	stale := now.Add(-30 * 24 * time.Hour)

	for _, m := range accessManagementVerbs {
		t.Run(m, func(t *testing.T) {
			if err := floorVerdict(t, floor, sessionCtx("2", stale), m); err != nil {
				t.Errorf("сессия уровня 2 со вторым фактором 30 суток назад: %v; страница решений требует только уровня 2", err)
			}
			if err := floorVerdict(t, floor, sessionCtx("2", now), m); err != nil {
				t.Errorf("сессия уровня 2 со свежим вторым фактором: %v", err)
			}
			err := floorVerdict(t, floor, sessionCtx("1", now), m)
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("близнец: сессия уровня 1 получила %v, ждали указание повысить уровень", err)
			}
			if !carriesStepUp(err, "acr_values:2") {
				t.Errorf("близнец: отказ сессии уровня 1 не несёт указания повысить уровень до 2: %v", status.Convert(err).Details())
			}
		})
	}
}

// carriesStepUp — несёт ли отказ указание повысить уровень до названного.
func carriesStepUp(err error, subject string) bool {
	for _, d := range status.Convert(err).Details() {
		pf, ok := d.(*errdetails.PreconditionFailure)
		if !ok {
			continue
		}
		for _, v := range pf.GetViolations() {
			if v.GetType() == "authz.step_up" && v.GetSubject() == subject {
				return true
			}
		}
	}
	return false
}
