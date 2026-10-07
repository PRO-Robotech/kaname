// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// usecase_test.go — ветви справочника, которых миры интеграционных проб
// (cmd/kaname/recipient_directory_integration_test.go,
// cmd/kaname/audience_fence_integration_test.go) не создают: отказ хранилища и
// двери, вид субъекта вне адресатов, владелец аккаунта вне состояния ACTIVE,
// токен новее снимка, курсор чужой формы, порядок проверки входа перед
// вопросом об аудитории. Порты — дублёры; Postgres не нужен.
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

	"google.golang.org/genproto/googleapis/rpc/errdetails"
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

// fakeStore — записи получателей, владельцы аккаунтов и аудитория версии
// события. audienceErr — сбой чтения аудитории; verdict — исход чтения, не
// являющийся страницей; questions — заданные вопросы об аудитории.
type fakeStore struct {
	users       map[string]domain.RecipientRecord
	owners      map[string]string
	err         error
	audience    []string
	audienceErr error
	verdict     domain.EventAudienceVerdict
	questions   []domain.EventAudienceQuestion
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

func (s *fakeStore) ReadEventAudience(_ context.Context, q domain.EventAudienceQuestion) (domain.EventAudiencePage, error) {
	s.questions = append(s.questions, q)
	if s.audienceErr != nil {
		return domain.EventAudiencePage{}, s.audienceErr
	}
	if s.verdict != domain.EventAudienceAnswered {
		return domain.EventAudiencePage{Verdict: s.verdict}, nil
	}
	var out []string
	for _, subject := range s.audience {
		if q.Subject != "" && subject != q.Subject {
			continue
		}
		if subject > q.AfterSubject && len(out) < q.Limit {
			out = append(out, subject)
		}
	}
	return domain.EventAudiencePage{Verdict: domain.EventAudienceAnswered, Subjects: out}, nil
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
		"user:usr-A|v_get|account:acc-2":            true,
	}}
	store := &fakeStore{
		users: map[string]domain.RecipientRecord{
			"usr-A":   {Active: true, Email: "a@example.test", EmailVerified: true},
			"usr-own": {Active: false, Email: "own@example.test", EmailVerified: true},
		},
		owners:   map[string]string{"acc-1": "usr-own", "acc-2": "usr-A"},
		audience: []string{"user:usr-A", "user:usr-B", "user:usr-C"},
	}
	return door, store
}

func quiet() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// token — токен версии прав в форме снимка.
const token = "781:781:"

func event() EventRef {
	return EventRef{Object: "storage_volume:vol-1", Generation: 1, AuthzRev: token,
		Facts: domain.EventFacts{ProjectID: "prj-1", AccountID: "acc-1"}}
}

func base() ResolveRequest {
	return ResolveRequest{Namespace: "storage", Subject: "user:usr-A", Audience: AudienceEvent, Event: event()}
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
	uc := NewResolveUseCase(door, store, store, quiet())
	// Близнец: то же хранилище без сбоя — адрес.
	res, err := uc.Execute(notifyCtx(), base())
	if err != nil || res.Outcome != domain.RecipientAddress {
		t.Fatalf("близнец: %v %v", res, err)
	}
	store.err = errors.New(driverText)
	_, err = uc.Execute(notifyCtx(), base())
	requireUnavailableFixed(t, err, unavailableText)
}

func TestResolve_AudienceReadFailureIsUnavailableWithAFixedText(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, store, quiet())
	store.audienceErr = errors.New(driverText)
	res, err := uc.Execute(notifyCtx(), base())
	if res.Address != "" {
		t.Fatalf("адрес ушёл при неотвеченном вопросе об аудитории: %v", res)
	}
	requireUnavailableFixed(t, err, unavailableText)
}

func TestResolve_DoorFailureOnTheAccountReaderIsUnavailable(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, store, quiet())
	req := ResolveRequest{Namespace: "notify", Subject: "user:usr-A", Audience: AudienceAccountReader, AccountID: "acc-2"}
	res, err := uc.Execute(notifyCtx(), req) // близнец: дверь отвечает
	if err != nil || res.Outcome != domain.RecipientAddress {
		t.Fatalf("близнец: %v %v", res, err)
	}
	door.err = errors.New(driverText)
	res, err = uc.Execute(notifyCtx(), req)
	if res.Address != "" {
		t.Fatalf("адрес ушёл при неотвеченном вопросе о праве: %v", res)
	}
	requireUnavailableFixed(t, err, "authz backend unavailable")
}

// TestResolve_UnappliedGenerationIsARefusalNotAnOutcome — барьер поколения —
// отказ кодом с причиной, а не исход по субъекту; близнец — поколение
// применено, субъекта нет в аудитории — исход AUDIENCE_DENIED.
func TestResolve_UnappliedGenerationIsARefusalNotAnOutcome(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, store, quiet())
	store.verdict = domain.EventAudienceGenerationNotApplied
	_, err := uc.Execute(notifyCtx(), base())
	st, _ := status.FromError(err)
	if st.Code() != codes.Unavailable || reasonOf(st) != reasonGenerationNotApplied {
		t.Fatalf("ждали UNAVAILABLE %s, получено %s %q", reasonGenerationNotApplied, st.Code(), st.Message())
	}
	// Текст полосы UNAVAILABLE фиксирован: предмет отказа (объект и поколение)
	// едет машинно в ErrorInfo.metadata, а не вычисляемой строкой сообщения.
	requireUnavailableFixed(t, err, generationNotAppliedText)
	if md := metadataOf(st); md["object"] == "" || md["generation"] == "" {
		t.Fatalf("ErrorInfo.metadata обязано назвать объект и поколение, получено %v", md)
	}
	store.verdict = domain.EventAudienceAnswered
	store.audience = []string{"user:usr-B"}
	res, err := uc.Execute(notifyCtx(), base())
	if err != nil || res.Outcome != domain.RecipientAudienceDenied || res.Address != "" {
		t.Fatalf("близнец: ждали AUDIENCE_DENIED без адреса, получено %v %v", res, err)
	}
}

// TestResolve_TokenAheadOfTheSnapshotIsAFieldRefusal — токен новее снимка
// вопроса не выдан этой службой: INVALID_ARGUMENT с полем токена.
func TestResolve_TokenAheadOfTheSnapshotIsAFieldRefusal(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, store, quiet())
	store.verdict = domain.EventAudienceTokenAhead
	_, err := uc.Execute(notifyCtx(), base())
	requireFieldRefusal(t, err, "audience.event.authz_rev")
}

// TestResolve_InputIsJudgedBeforeTheAudienceQuestion — отказ формы входа
// (токен не в форме снимка, тип вне пространства, элемент цепи без id) —
// раньше вопроса об аудитории: вопросов 0. Близнец — база — вопрос один.
func TestResolve_InputIsJudgedBeforeTheAudienceQuestion(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, store, quiet())
	if _, err := uc.Execute(notifyCtx(), base()); err != nil || len(store.questions) != 1 {
		t.Fatalf("близнец: %v, вопросов %d", err, len(store.questions))
	}
	for _, c := range []struct {
		name  string
		edit  func(*ResolveRequest)
		field string
	}{
		{"токен не снимок", func(r *ResolveRequest) { r.Event.AuthzRev = "R1" }, "audience.event.authz_rev"},
		{"тип чужого пространства", func(r *ResolveRequest) { r.Event.Object = "vpc_network:net-1" }, "audience.event.object"},
		{"тип вне таблицы", func(r *ResolveRequest) { r.Event.Object = "geo_zone:zn-1" }, "audience.event.object"},
		{"объект без типа", func(r *ResolveRequest) { r.Event.Object = "vol-1" }, "audience.event.object"},
		{"элемент цепи без id", func(r *ResolveRequest) { r.Event.Facts.ParentChain = []string{"project:"} },
			"audience.event.facts.parent_chain"},
	} {
		store.questions = nil
		req := base()
		c.edit(&req)
		_, err := uc.Execute(notifyCtx(), req)
		requireFieldRefusal(t, err, c.field)
		if len(store.questions) != 0 {
			t.Fatalf("%s: вопрос об аудитории задан до отказа входа", c.name)
		}
	}
}

func reasonOf(st *status.Status) string {
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetReason()
		}
	}
	return ""
}

func metadataOf(st *status.Status) map[string]string {
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetMetadata()
		}
	}
	return nil
}

func requireFieldRefusal(t *testing.T, err error, field string) {
	t.Helper()
	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("ждали INVALID_ARGUMENT поля %s, получено %s %q", field, st.Code(), st.Message())
	}
	for _, d := range st.Details() {
		if br, ok := d.(*errdetails.BadRequest); ok {
			for _, v := range br.GetFieldViolations() {
				if v.GetField() == field {
					return
				}
			}
		}
	}
	t.Fatalf("в отказе %q нет нарушения поля %s", st.Message(), field)
}

func TestResolve_SubjectOfANonRecipientKindIsNotFound(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, store, quiet())
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
	uc := NewResolveUseCase(door, store, store, quiet())
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

func TestListEventAudience_CursorOfAnotherFormIsRefused(t *testing.T) {
	door, store := world()
	uc := NewListEventAudienceUseCase(door, store, quiet())
	first, err := uc.Execute(notifyCtx(), event(), "", 2)
	if err != nil || len(first.Subjects) != 2 || first.NextPageToken == "" {
		t.Fatalf("близнец: первая страница %v %v", first, err)
	}
	second, err := uc.Execute(notifyCtx(), event(), first.NextPageToken, 2)
	if err != nil || len(second.Subjects) != 1 || second.Subjects[0] != "user:usr-C" || second.NextPageToken != "" {
		t.Fatalf("вторая страница по своему курсору: %v %v", second, err)
	}
	for _, tok := range []string{
		shared.EncodeVisiblePageToken(shared.VisibleCursor{ID: "usr-A"}), // курсор другого списка
		strings.TrimPrefix(first.NextPageToken, "rde1."),                 // тело без метки формы
		"rda1." + strings.TrimPrefix(first.NextPageToken, "rde1."),       // метка снятого ListProjectAudience
	} {
		_, err := uc.Execute(notifyCtx(), event(), tok, 2)
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("курсор %q чужой формы принят: %v", tok, err)
		}
	}
	store.audienceErr = errors.New(driverText)
	_, err = uc.Execute(notifyCtx(), event(), "", 2)
	requireUnavailableFixed(t, err, unavailableText)
}

// TestListEventAudience_EmptyAudienceIsAnEmptyPage — пустая аудитория —
// пустой список без курсора, а не nil-ответ.
func TestListEventAudience_EmptyAudienceIsAnEmptyPage(t *testing.T) {
	door, store := world()
	store.audience = nil
	page, err := NewListEventAudienceUseCase(door, store, quiet()).Execute(notifyCtx(), event(), "", 0)
	if err != nil || page.Subjects == nil || len(page.Subjects) != 0 || page.NextPageToken != "" {
		t.Fatalf("ждали пустую страницу, получено %#v %v", page, err)
	}
}

func TestCaller_WithoutSubjectIsDeniedWithoutAskingTheDoor(t *testing.T) {
	door, store := world()
	uc := NewResolveUseCase(door, store, store, quiet())
	_, err := uc.Execute(context.Background(), base())
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("ждали PERMISSION_DENIED, получено %v", err)
	}
	if len(door.asked) != 0 {
		t.Fatalf("дверь спрошена без субъекта вызывающего: %v", door.asked)
	}
}
