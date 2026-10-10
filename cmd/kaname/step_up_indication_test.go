// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// step_up_indication_test.go — сценарии Ф11-49 и Ф11-50 приёмки «уровень
// уверенности объявляет наша сессия», редакция 9, решение Р11
// (PRO-Robotech/kaname#511): на недостаток уровня публичный слушатель службы
// отвечает УКАЗАНИЕМ повысить уровень — той же формой, что край (KA1-15), — а
// не отказом прав.
//
// # Почему настоящий слушатель и настоящий REST-фронт, а не вызов перехватчика
//
// Указание едет до REST-фронта ОТДЕЛЬНО от статуса — параметрами вызова RFC 9470
// (требуемый и предъявленный уровень), а статус `google.rpc.Status` их не несёт.
// Проба на вызове перехватчика зеленела бы на перехватчике, параметры которого
// не доезжают до провода; здесь запрос идёт тем же путём, что у арендатора:
// HTTP → фронт → собственный gRPC-слушатель с боевой цепочкой → ответ.
//
// # Тексты — литералами
//
// Текст и тело — из Р11 дословно, а не константой производителя: утверждение
// «равно константе» зеленело бы при любом её значении.

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	"github.com/PRO-Robotech/kaname/internal/restfront"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// stepUpText — текст Р11 дословно.
const stepUpText = "authentication level is insufficient: step up with a second factor, or present a credential of another kind"

// stepUpProjects — обработчик ProjectService.Get, отвечающий проектом: предмет
// пробы — перехватчики слушателя, а не глагол.
type stepUpProjects struct {
	iamv1.UnimplementedProjectServiceServer
}

func (stepUpProjects) Get(_ context.Context, req *iamv1.GetProjectRequest) (*iamv1.Project, error) {
	return &iamv1.Project{Id: req.GetProjectId()}, nil
}

// stepUpStand — публичный gRPC-слушатель с БОЕВОЙ цепочкой (читатель
// предъявленного над парой извлечения, затем политика вызывающего с полом
// каталога) и публичный REST-фронт, собранный боевым сборщиком над ним.
type stepUpStand struct {
	front http.Handler
	conn  *grpc.ClientConn
	mint  func(jwt.MapClaims) string
}

func newStepUpStand(t *testing.T, floor string) stepUpStand {
	t.Helper()
	reader, mint := chainMint(t)
	policy := authzguard.NewPublicCallerPolicy(true, authzguard.PublicPeerCallableRPCs(),
		floorCatalog{min: floor}, presentedcred.Presented)
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(append(
		publicIdentityUnary(fwdCfg(fwdGatewaySAN, fwdVPCSAN), reader), policy.Unary())...))
	iamv1.RegisterProjectServiceServer(srv, stepUpProjects{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("слушатель: %v", err)
	}
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}
	front, err := restfront.NewPublic(context.Background(), lis.Addr().String(), opts)
	if err != nil {
		t.Fatalf("сборка публичного фронта: %v", err)
	}
	conn, err := grpc.NewClient(lis.Addr().String(), opts...)
	if err != nil {
		t.Fatalf("клиент слушателя: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return stepUpStand{front: front, conn: conn, mint: mint}
}

func (s stepUpStand) rest(t *testing.T, raw string) (*httptest.ResponseRecorder, string) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/iam/v1/projects/prj-stepup", nil)
	if raw != "" {
		req.Header.Set("Authorization", "Bearer "+raw)
	}
	rec := httptest.NewRecorder()
	s.front.ServeHTTP(rec, req)
	body, _ := io.ReadAll(rec.Result().Body)
	return rec, string(body)
}

func (s stepUpStand) grpcGet(raw string) error {
	ctx := metadata.AppendToOutgoingContext(context.Background(), presentedcred.MetadataKey, "Bearer "+raw)
	_, err := iamv1.NewProjectServiceClient(s.conn).Get(ctx, &iamv1.GetProjectRequest{ProjectId: "prj-stepup"})
	return err
}

// reChallengeParam — параметр вызова RFC 7235: имя="значение".
var reChallengeParam = regexp.MustCompile(`([a-z_]+)="([^"]*)"`)

// challengeParams разбирает вызов `Bearer` на параметры: утверждается РАЗБОР,
// а не сравнение строки (как KA1-15).
func challengeParams(t *testing.T, header string) map[string]string {
	t.Helper()
	if len(header) < len("Bearer ") || header[:len("Bearer ")] != "Bearer " {
		t.Fatalf("вызов %q — не схема Bearer с параметрами", header)
	}
	out := map[string]string{}
	for _, m := range reChallengeParam.FindAllStringSubmatch(header, -1) {
		out[m[1]] = m[2]
	}
	return out
}

// TestF11_49_RESTFrontAnswersTheStepUpIndication — Ф11-49: удостоверение
// человека уровня «1» на глаголе с полом «2» REST-фронтом службы — `401`, тело
// побайтово `{"code":16,"message":"<текст Р11>","details":[]}`, вызов `Bearer` с
// `error`, `acr_values` и `error_description`, называющим требуемый и
// предъявленный уровни. Близнец — `acr` = «2»: проходит пол; отличающий факт —
// один, уровень. Второй близнец — `401` иной природы (удостоверения нет вовсе):
// голая подсказка `Bearer`, как прежде (KAN-REST-1 не тронута).
func TestF11_49_RESTFrontAnswersTheStepUpIndication(t *testing.T) {
	s := newStepUpStand(t, "2")

	rec, body := s.rest(t, s.mint(jwt.MapClaims{"acr": "1"}))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("статус %d, ожидался 401 (Р11); тело %q", rec.Code, body)
	}
	if want := `{"code":16,"message":"` + stepUpText + `","details":[]}`; body != want {
		t.Errorf("тело %q, ожидалось побайтово %q", body, want)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	p := challengeParams(t, rec.Header().Get("WWW-Authenticate"))
	if p["error"] != "insufficient_user_authentication" {
		t.Errorf("error=%q, ожидалось insufficient_user_authentication; вызов %q", p["error"], rec.Header().Get("WWW-Authenticate"))
	}
	if p["acr_values"] != "2" {
		t.Errorf("acr_values=%q, ожидалось 2", p["acr_values"])
	}
	if p["error_description"] != "Required ACR 2 for this resource; presented ACR 1" {
		t.Errorf("error_description=%q", p["error_description"])
	}

	// Близнец: тот же запрос с уровнем «2» — проходит пол.
	if twin, tb := s.rest(t, s.mint(jwt.MapClaims{"acr": "2"})); twin.Code != http.StatusOK {
		t.Fatalf("близнец acr=2: статус %d, тело %q — пол обязан пропускать", twin.Code, tb)
	}

	// Второй близнец: 401 иной природы — подсказка голая, как прежде.
	other, _ := s.rest(t, "")
	if other.Code != http.StatusUnauthorized {
		t.Fatalf("без удостоверения: статус %d, ожидался 401", other.Code)
	}
	if got := other.Header().Get("WWW-Authenticate"); got != restfront.AuthenticationChallenge {
		t.Errorf("подсказка на 401 без удостоверения %q, ожидалась голая %q", got, restfront.AuthenticationChallenge)
	}
}

// TestF11_50_GRPCAnswersTheStepUpIndication — Ф11-50: то же нативным gRPC —
// `UNAUTHENTICATED`, текст Р11 дословно. Близнец — `acr` = «2»: проходит пол.
// Второй близнец — машинный принципал на том же глаголе: проходит пол
// (освобождение общим правилом, Р11 п.2); отличающий факт — вид принципала.
func TestF11_50_GRPCAnswersTheStepUpIndication(t *testing.T) {
	s := newStepUpStand(t, "2")

	err := s.grpcGet(s.mint(jwt.MapClaims{"acr": "1"}))
	st := status.Convert(err)
	if st.Code() != codes.Unauthenticated || st.Message() != stepUpText {
		t.Fatalf("уровень «1» на полу «2»: %s %q, ожидалось %s %q", st.Code(), st.Message(), codes.Unauthenticated, stepUpText)
	}
	if err := s.grpcGet(s.mint(jwt.MapClaims{"acr": "2"})); err != nil {
		t.Fatalf("близнец acr=2 отвергнут: %v", err)
	}
	if err := s.grpcGet(s.mint(jwt.MapClaims{"acr": "1", domain.ClaimPrincipalType: "service_account"})); err != nil {
		t.Fatalf("машинный принципал отвергнут полом: %v — освобождение общим правилом снято", err)
	}
}
