// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repouser "github.com/PRO-Robotech/kaname/internal/repo/kaname/user"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const lookupLaneExternalID = "front-reader-external-1024"

// lookupLaneEvent фиксирует вызовы порта и личность из настоящего серверного context.
// Проверки выполняются в потоке теста после ответа, а не через Fatal в потоке сервера.
type lookupLaneEvent struct {
	Stage         string
	SAN           string
	Verified      bool
	VerifiedChain bool
	ExternalID    domain.ExternalSubject
	Statuses      []domain.InviteStatus
}

type lookupLaneRepo struct {
	mu     sync.Mutex
	events []lookupLaneEvent
}

var _ kanamerepo.Repository = (*lookupLaneRepo)(nil)
var _ kanamerepo.Reader = (*lookupLaneReader)(nil)
var _ repouser.ReaderIface = (*lookupLaneUsers)(nil)

func (r *lookupLaneRepo) record(stage string, ctx context.Context, ext domain.ExternalSubject, statuses []domain.InviteStatus) {
	e := lookupLaneEvent{Stage: stage, ExternalID: ext, Statuses: append([]domain.InviteStatus(nil), statuses...)}
	if ctx != nil {
		e.SAN, e.Verified = grpcsrv.CertIdentityFromContext(ctx)
		if p, ok := peer.FromContext(ctx); ok {
			if info, ok := p.AuthInfo.(credentials.TLSInfo); ok {
				e.VerifiedChain = len(info.State.VerifiedChains) > 0
			}
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *lookupLaneRepo) snapshot() []lookupLaneEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]lookupLaneEvent(nil), r.events...)
}

func (r *lookupLaneRepo) Reader(ctx context.Context) (kanamerepo.Reader, error) {
	r.record("reader", ctx, "", nil)
	return &lookupLaneReader{repo: r}, nil
}

func (r *lookupLaneRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	r.record("unexpected-writer", ctx, "", nil)
	return nil, errors.New("проба LookupSubject не допускает писателя")
}

func (r *lookupLaneRepo) Close() {
	r.record("unexpected-close", nil, "", nil)
}

// Нулевой вложенный интерфейс намерен: любое незаданное обращение паникует,
// а не возвращает правдоподобный успешный ответ. Реализован только ожидаемый порт.
type lookupLaneReader struct {
	kanamerepo.Reader
	repo *lookupLaneRepo
}

func (r *lookupLaneReader) Users() repouser.ReaderIface {
	r.repo.record("users", nil, "", nil)
	return &lookupLaneUsers{repo: r.repo}
}

func (r *lookupLaneReader) Rollback(ctx context.Context) error {
	r.repo.record("rollback", ctx, "", nil)
	return nil
}

type lookupLaneUsers struct {
	repouser.ReaderIface
	repo *lookupLaneRepo
}

func (r *lookupLaneUsers) FindByExternalIDInStatuses(ctx context.Context, ext domain.ExternalSubject, statuses []domain.InviteStatus) ([]domain.User, error) {
	r.repo.record("find", ctx, ext, statuses)
	want := []domain.InviteStatus{domain.InviteStatusActive, domain.InviteStatusBlocked}
	if ext != lookupLaneExternalID || !reflect.DeepEqual(statuses, want) {
		return nil, errors.New("LookupSubject изменил внешний идентификатор или фильтр состояний")
	}
	return []domain.User{{
		ID:           "usr-front-reader-1024",
		ExternalID:   lookupLaneExternalID,
		Email:        "front-reader-1024@example.test",
		DisplayName:  "Читатель внутреннего фронта",
		InviteStatus: domain.InviteStatusActive,
	}}, nil
}

func lookupLaneExpected(san string) []lookupLaneEvent {
	return []lookupLaneEvent{
		{Stage: "reader", SAN: san, Verified: true, VerifiedChain: true},
		{Stage: "users"},
		{Stage: "find", SAN: san, Verified: true, VerifiedChain: true, ExternalID: lookupLaneExternalID,
			Statuses: []domain.InviteStatus{domain.InviteStatusActive, domain.InviteStatusBlocked}},
		{Stage: "rollback", SAN: san, Verified: true, VerifiedChain: true},
	}
}

func lookupLaneAssertUser(t *testing.T, response *iamv1.LookupSubjectResponse) {
	t.Helper()
	require.NotNil(t, response)
	u := response.GetUser()
	require.NotNil(t, u)
	require.Equal(t, "usr-front-reader-1024", u.GetId())
	require.Equal(t, lookupLaneExternalID, u.GetExternalId())
	require.Equal(t, "front-reader-1024@example.test", u.GetEmail())
	require.Equal(t, "Читатель внутреннего фронта", u.GetDisplayName())
}

func lookupLaneHTTP(t *testing.T, w *laneWorld, san string) (int, []byte) {
	t.Helper()
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		Certificates: []tls.Certificate{w.ca.leaf(t, san)},
		RootCAs:      w.ca.pool(),
		MinVersion:   tls.VersionTLS12,
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client := &http.Client{Transport: transport}
	body := []byte(`{"externalId":"front-reader-external-1024"}`)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, w.front+"/iam/v1/internal/iam:lookupSubject", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, raw
}

// TestInternalFront_LookupSubjectKeepsOwnHopDenied закрепляет предел хопа:
// LookupSubject разрешён прямому краю, но отсутствует в пересечении профилей
// собственного фронта. Каждый подслучай имеет собственное состояние.
func TestInternalFront_LookupSubjectKeepsOwnHopDenied(t *testing.T) {
	t.Run("https_front_forbidden_without_downstream", func(t *testing.T) {
		repo := &lookupLaneRepo{}
		w := newLaneWorldWithLookup(t, internal_iam.NewLookupSubjectUseCase(repo))
		code, raw := lookupLaneHTTP(t, w, laneEdgeSAN)
		require.Equal(t, http.StatusForbidden, code, "%s", raw)
		require.JSONEq(t, `{"code":7,"message":"permission denied","details":[]}`, string(raw))
		require.Empty(t, repo.snapshot(), "собственный хоп не вправе вызывать LookupSubject")
	})

	t.Run("direct_grpc_verified_edge_twin", func(t *testing.T) {
		repo := &lookupLaneRepo{}
		w := newLaneWorldWithLookup(t, internal_iam.NewLookupSubjectUseCase(repo))
		conn, err := grpc.NewClient(w.grpc, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{w.ca.leaf(t, laneEdgeSAN)},
			RootCAs:      w.ca.pool(),
			MinVersion:   tls.VersionTLS12,
		})))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		response, err := iamv1.NewInternalIAMServiceClient(conn).LookupSubject(t.Context(), &iamv1.LookupSubjectRequest{
			Key: &iamv1.LookupSubjectRequest_ExternalId{ExternalId: lookupLaneExternalID},
		})
		require.NoError(t, err)
		lookupLaneAssertUser(t, response)
		require.Equal(t, lookupLaneExpected(laneEdgeSAN), repo.snapshot())
	})

	t.Run("outsider_http_forbidden_without_downstream", func(t *testing.T) {
		repo := &lookupLaneRepo{}
		w := newLaneWorldWithLookup(t, internal_iam.NewLookupSubjectUseCase(repo))
		code, raw := lookupLaneHTTP(t, w, laneOutsiderSAN)
		require.Equal(t, http.StatusForbidden, code, "%s", raw)
		require.JSONEq(t, `{"code":7,"message":"permission denied","details":[]}`, string(raw))
		require.Empty(t, repo.snapshot(), "отказ фронта не должен доходить до порта")
	})
}

const checkLaneUnixTime int64 = 1700000000

// checkLaneEvent фиксирует нижние вызовы настоящего AuthorizeService и личность
// серверного контекста. Снимок читается после ответа, утверждения не бегут в сервере.
type checkLaneEvent struct {
	Stage         string
	SAN           string
	Verified      bool
	VerifiedChain bool
	Subject       string
	Relation      string
	Object        string
	Conditions    map[string]any
}

// checkLaneStore подменяет только нижний порт решения. Нулевой вложенный
// интерфейс не позволяет незаданной операции молча вернуть успешный ответ.
type checkLaneStore struct {
	service.Authorizer
	mu     sync.Mutex
	events []checkLaneEvent
}

var _ service.Authorizer = (*checkLaneStore)(nil)
var _ service.SubjectAdmission = (*checkLaneStore)(nil)

func (s *checkLaneStore) record(ctx context.Context, e checkLaneEvent) {
	e.SAN, e.Verified = grpcsrv.CertIdentityFromContext(ctx)
	if p, ok := peer.FromContext(ctx); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			e.VerifiedChain = len(info.State.VerifiedChains) > 0
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
}

func (s *checkLaneStore) snapshot() []checkLaneEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]checkLaneEvent(nil), s.events...)
}

func (s *checkLaneStore) SubjectAdmitted(ctx context.Context, subject string) (bool, error) {
	s.record(ctx, checkLaneEvent{Stage: "admission", Subject: subject})
	if subject != "user:usr_alice" {
		return false, errors.New("сценарий изменил субъект допуска")
	}
	return true, nil
}

func (s *checkLaneStore) CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error) {
	conditions := make(map[string]any, len(condCtx))
	for key, value := range condCtx {
		conditions[key] = value
	}
	s.record(ctx, checkLaneEvent{Stage: "check", Subject: subject, Relation: relation, Object: object, Conditions: conditions})
	if subject != "user:usr_alice" || relation != "viewer" || object != laneForeignObject ||
		!reflect.DeepEqual(conditions, map[string]any{"current_time": checkLaneUnixTime}) {
		return false, errors.New("сценарий изменил вопрос или серверный контекст условия")
	}
	return true, nil
}

func checkLaneExpected(san string) []checkLaneEvent {
	return []checkLaneEvent{
		{Stage: "admission", SAN: san, Verified: true, VerifiedChain: true, Subject: "user:usr_alice"},
		{Stage: "check", SAN: san, Verified: true, VerifiedChain: true,
			Subject: "user:usr_alice", Relation: "viewer", Object: laneForeignObject,
			Conditions: map[string]any{"current_time": checkLaneUnixTime}},
	}
}

func newCheckLaneWorld(t *testing.T) (*laneWorld, *checkLaneStore) {
	t.Helper()
	store := &checkLaneStore{}
	authz := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: store,
		Now:       func() time.Time { return time.Unix(checkLaneUnixTime, 0).UTC() },
	})
	return newLaneWorldWithAuthorizer(t, nil, authz), store
}

// TestInternalFront_CheckExecutesRealHandler проходит тот самый обработчик,
// в начало которого инъекция #1024 вставляет сертификатный reader. Ответ
// производит настоящий AuthorizeService после наблюдаемого нижнего порта.
// Ошибка одного подслучая не мешает переписи двух остальных.
func TestInternalFront_CheckExecutesRealHandler(t *testing.T) {
	t.Run("https_front_verified_hop", func(t *testing.T) {
		w, store := newCheckLaneWorld(t)
		code, body := w.overHTTP(laneEdgeSAN, laneForeignObject)
		require.Equal(t, http.StatusOK, code, "%v", body)
		require.Equal(t, true, body["allowed"])
		require.Equal(t, checkLaneExpected(laneFrontSAN), store.snapshot())
	})

	t.Run("direct_grpc_verified_edge_twin", func(t *testing.T) {
		w, store := newCheckLaneWorld(t)
		conn, err := grpc.NewClient(w.grpc, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{w.ca.leaf(t, laneEdgeSAN)},
			RootCAs:      w.ca.pool(),
			MinVersion:   tls.VersionTLS12,
		})))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		response, err := iamv1.NewInternalIAMServiceClient(conn).Check(t.Context(), &iamv1.CheckRequest{
			SubjectId: "user:usr_alice", Relation: "viewer", Object: laneForeignObject,
		})
		require.NoError(t, err)
		require.True(t, response.GetAllowed())
		require.Equal(t, checkLaneExpected(laneEdgeSAN), store.snapshot())
	})

	t.Run("outsider_http_forbidden_without_downstream", func(t *testing.T) {
		w, store := newCheckLaneWorld(t)
		code, body := w.overHTTP(laneOutsiderSAN, laneForeignObject)
		require.Equal(t, http.StatusForbidden, code, "%v", body)
		require.Equal(t, float64(7), body["code"])
		require.Equal(t, "permission denied", body["message"])
		require.Empty(t, store.snapshot(), "отказ фронта не должен доходить до сценария")
	})
}
