// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// usecase_test.go — ветви справочника, которых мир G0 интеграционной пробы
// (cmd/kaname/recipient_directory_integration_test.go) не создаёт: отказ
// хранилища и двери, вид субъекта вне адресатов, владелец аккаунта вне
// состояния ACTIVE, курсор чужой формы. Порты — дублёры; Postgres не нужен.
//
// У каждого отказа — близнец, отличающийся одним фактом и дающий исход: иначе
// «UNAVAILABLE» зеленело бы и у сценария, который отказывает всегда.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// fakeDoor отвечает «да» на посеянные вопросы; err — сбой на вопросах о v_get.
type fakeDoor struct {
	allow map[string]bool
	err   error
	asked []string
}

func (d *fakeDoor) CheckRelation(_ context.Context, req service.CheckRelationRequest) (*service.CheckResult, error) {
	key := req.Subject + "|" + req.Relation + "|" + req.Object
	d.asked = append(d.asked, key)
	if d.err != nil && req.Relation != relationDirectoryReader {
		return nil, d.err
	}
	return &service.CheckResult{Allowed: d.allow[key]}, nil
}

// fakeStore — записи получателей, владельцы аккаунтов и аудитория.
type fakeStore struct {
	users  map[string]domain.RecipientRecord
	owners map[string]string
	err    error
	ids    []string
}

func (s *fakeStore) ReadRecipient(_ context.Context, kind domain.RecipientKind, id string) (domain.RecipientRecord, bool, error) {
	if s.err != nil {
		return domain.RecipientRecord{}, false, s.err
	}
	if kind != domain.RecipientKindUser {
		return domain.RecipientRecord{}, false, nil
	}
	r, ok := s.users[id]
	return r, ok, nil
}

func (s *fakeStore) ReadAccountOwner(_ context.Context, accountID string) (string, bool, error) {
	if s.err != nil {
		return "", false, s.err
	}
	o, ok := s.owners[accountID]
	return o, ok, nil
}

func (s *fakeStore) ListProjectUsers(_ context.Context, _, afterID string, limit int) ([]string, error) {
	if s.err != nil {
		return nil, s.err
	}
	var out []string
	for _, id := range s.ids {
		if id > afterID && len(out) < limit {
			out = append(out, id)
		}
	}
	return out, nil
}

// driverText — текст «драйвера», который наружу уходить не вправе.
const driverText = "pq: relation kaname.users does not exist (SQLSTATE 42P01)"

// notifyCtx — вызывающий с субъектом. Служебный субъект кладёт звено Р2 на
// проводе (его путь судит интеграционная проба); здесь субъект — пересланный
// принципал, и дублёр двери даёт ему право на справочник тем же ключом.
func notifyCtx() context.Context {
	return operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "usr-notify"})
}

func world() (*fakeDoor, *fakeStore) {
	door := &fakeDoor{allow: map[string]bool{
		"user:usr-notify|reader|" + objectDirectory: true,
		"user:usr-A|v_get|storage_volume:vol-1":     true,
	}}
	store := &fakeStore{
		users: map[string]domain.RecipientRecord{
			"usr-A":   {Active: true, Email: "a@example.test", EmailVerified: true},
			"usr-own": {Active: false, Email: "own@example.test", EmailVerified: true},
		},
		owners: map[string]string{"acc-1": "usr-own", "acc-2": "usr-A"},
	}
	return door, store
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func base() ResolveRequest {
	return ResolveRequest{Namespace: "storage", Subject: "user:usr-A", Audience: AudienceResource,
		Relation: "v_get", Refs: []ResourceRef{{Type: "storage_volume", ID: "vol-1"}}}
}

func requireUnavailableFixed(t *testing.T, err error, want string) {
	t.Helper()
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable || st.Message() != want {
		t.Fatalf("ждали UNAVAILABLE %q, получено %s %q", want, st.Code(), st.Message())
	}
	if strings.Contains(st.Message(), "SQLSTATE") || strings.Contains(st.Message(), "pq:") {
		t.Fatalf("текст хранилища ушёл наружу: %q", st.Message())
	}
}

func TestResolve_StoreFailureIsUnavailableWithAFixedText(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, quiet())
	// Близнец: то же хранилище без сбоя — адрес.
	res, err := uc.Execute(notifyCtx(), base())
	if err != nil || res.Outcome != domain.RecipientAddress {
		t.Fatalf("близнец: %v %v", res, err)
	}
	store.err = errors.New(driverText)
	_, err = uc.Execute(notifyCtx(), base())
	requireUnavailableFixed(t, err, unavailableText)
}

func TestResolve_DoorFailureOnTheAudienceIsUnavailable(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, quiet())
	door.err = errors.New(driverText)
	res, err := uc.Execute(notifyCtx(), base())
	if res.Address != "" {
		t.Fatalf("адрес ушёл при неотвеченном вопросе о праве: %v", res)
	}
	requireUnavailableFixed(t, err, "authz backend unavailable")
}

func TestResolve_SubjectOfANonRecipientKindIsNotFound(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, quiet())
	for _, subject := range []string{"group:grp-1", "service:notify", "usr-A"} {
		req := base()
		req.Subject = subject
		res, err := uc.Execute(notifyCtx(), req)
		if err != nil || res.Outcome != domain.RecipientSubjectNotFound {
			t.Fatalf("%s: ждали SUBJECT_NOT_FOUND, получено %v %v", subject, res, err)
		}
	}
	for _, q := range door.asked {
		if strings.Contains(q, "|v_get|") {
			t.Fatalf("вопрос о праве задан субъекту вне адресатов: %s", q)
		}
	}
}

func TestResolve_AccountOwnerOutsideActiveIsInactive(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, quiet())
	owner := func(acc string) ResolveRequest {
		return ResolveRequest{Namespace: "notify", Audience: AudienceAccountOwner, AccountID: acc}
	}
	res, err := uc.Execute(notifyCtx(), owner("acc-2")) // близнец: владелец ACTIVE
	if err != nil || res.Outcome != domain.RecipientAddress || res.Address != "a@example.test" {
		t.Fatalf("близнец acc-2: %v %v", res, err)
	}
	res, err = uc.Execute(notifyCtx(), owner("acc-1"))
	if err != nil || res.Outcome != domain.RecipientSubjectInactive || res.Address != "" {
		t.Fatalf("acc-1: ждали SUBJECT_INACTIVE без адреса, получено %v %v", res, err)
	}
}

func TestListProjectAudience_CursorOfAnotherFormIsRefused(t *testing.T) {
	door, store := world()
	store.ids = []string{"usr-A", "usr-B", "usr-C"}
	uc := NewListProjectAudienceUseCase(door, store, quiet())
	first, err := uc.Execute(notifyCtx(), "prj-1", "", 2)
	if err != nil || len(first.Subjects) != 2 || first.NextPageToken == "" {
		t.Fatalf("близнец: первая страница %v %v", first, err)
	}
	second, err := uc.Execute(notifyCtx(), "prj-1", first.NextPageToken, 2)
	if err != nil || len(second.Subjects) != 1 || second.Subjects[0] != "user:usr-C" || second.NextPageToken != "" {
		t.Fatalf("вторая страница по своему курсору: %v %v", second, err)
	}
	for _, token := range []string{
		shared.EncodeVisiblePageToken(shared.VisibleCursor{ID: "usr-A"}), // курсор другого списка
		strings.TrimPrefix(first.NextPageToken, "rda1."),                 // тело без метки формы
	} {
		_, err := uc.Execute(notifyCtx(), "prj-1", token, 2)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("курсор %q чужой формы принят: %v", token, err)
		}
	}
	store.err = errors.New(driverText)
	_, err = uc.Execute(notifyCtx(), "prj-1", "", 2)
	requireUnavailableFixed(t, err, unavailableText)
}

func TestCaller_WithoutSubjectIsDeniedWithoutAskingTheDoor(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, quiet())
	_, err := uc.Execute(context.Background(), base())
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ждали PERMISSION_DENIED, получено %v", err)
	}
	if len(door.asked) != 0 {
		t.Fatalf("дверь спрошена без субъекта вызывающего: %v", door.asked)
	}
}
