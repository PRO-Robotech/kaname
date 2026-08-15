// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package limit

// usecases_test.go — issue #291 S1: what the use-case layer answers, on fake
// ports.
//
// The database's own invariants (partial uniqueness, revision movement, the
// polymorphic reference) are locked where they live — the integration suite. What
// is here is everything a store cannot decide: which refusals are synchronous,
// which field they name, and whether a gate that cannot answer is read as "yes".

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// fakeLimitRepo — an in-memory store.
//
// It is deliberately NOT more permissive than the real one: Insert refuses a
// duplicate triple, and Get hides withdrawn rows. A stub that accepted everything
// would make invisible exactly the defects it is substituted for.
type fakeLimitRepo struct {
	rows     map[domain.LimitID]domain.Limit
	stated   []domain.Limit
	knownObj bool
	nextRev  int64
	// touched records whether the store was reached at all — a synchronous refusal
	// that still hit the store would be a refusal made too late.
	touched bool
}

func newFakeRepo() *fakeLimitRepo {
	return &fakeLimitRepo{rows: map[domain.LimitID]domain.Limit{}, knownObj: true}
}

func (f *fakeLimitRepo) Get(_ context.Context, id domain.LimitID) (domain.Limit, error) {
	f.touched = true
	l, ok := f.rows[id]
	if !ok || l.Withdrawn() {
		return domain.Limit{}, grpcstatus.Error(codes.NotFound, "Limit "+string(id)+" not found")
	}
	return l, nil
}

func (f *fakeLimitRepo) List(_ context.Context, limit int, _ string, fl domain.LimitFilter) ([]domain.Limit, string, error) {
	f.touched = true
	out := make([]domain.Limit, 0, len(f.rows))
	for _, l := range f.rows {
		if l.Withdrawn() {
			continue
		}
		if fl.Scope != "" && l.Scope != fl.Scope {
			continue
		}
		if fl.ScopeID != "" && l.ScopeID != fl.ScopeID {
			continue
		}
		if fl.Kind != "" && l.Kind != fl.Kind {
			continue
		}
		out = append(out, l)
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, "", nil
}

func (f *fakeLimitRepo) Insert(_ context.Context, l domain.Limit) (domain.Limit, error) {
	f.touched = true
	for _, e := range f.rows {
		if !e.Withdrawn() && e.Scope == l.Scope && e.ScopeID == l.ScopeID && e.Kind == l.Kind {
			return domain.Limit{}, grpcstatus.Error(codes.AlreadyExists, "limit already exists")
		}
	}
	f.nextRev++
	l.Revision = f.nextRev
	f.rows[l.ID] = l
	return l, nil
}

func (f *fakeLimitRepo) Update(_ context.Context, id domain.LimitID, value int64) (domain.Limit, error) {
	f.touched = true
	l, ok := f.rows[id]
	if !ok || l.Withdrawn() {
		return domain.Limit{}, grpcstatus.Error(codes.NotFound, "Limit "+string(id)+" not found")
	}
	if l.Value != value {
		f.nextRev++
		l.Revision = f.nextRev
	}
	l.Value = value
	f.rows[id] = l
	return l, nil
}

func (f *fakeLimitRepo) Withdraw(_ context.Context, id domain.LimitID) (domain.Limit, bool, error) {
	f.touched = true
	l, ok := f.rows[id]
	if !ok || l.Withdrawn() {
		return domain.Limit{}, false, nil
	}
	l.WithdrawnAt = time.Unix(1, 0)
	f.nextRev++
	l.Revision = f.nextRev
	f.rows[id] = l
	return l, true, nil
}

func (f *fakeLimitRepo) StatedFor(_ context.Context, _ string) ([]domain.Limit, bool, error) {
	f.touched = true
	return f.stated, f.knownObj, nil
}

func (f *fakeLimitRepo) ChangedSince(_ context.Context, after int64, limit int) ([]domain.Limit, int64, error) {
	f.touched = true
	out := make([]domain.Limit, 0, len(f.rows))
	next := after
	for _, l := range f.rows {
		if l.Revision > after {
			out = append(out, l)
			if l.Revision > next {
				next = l.Revision
			}
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, next, nil
}

// fakeCursors — the delta codec, mirroring the adapter's contract: empty means
// "from the beginning", garbage is refused.
type fakeCursors struct{}

func (fakeCursors) Encode(rev int64) string { return "c" + strconv.FormatInt(rev, 10) }
func (fakeCursors) Decode(c string) (int64, error) {
	if c == "" {
		return 0, nil
	}
	if len(c) < 2 || c[0] != 'c' {
		return 0, grpcstatus.Error(codes.InvalidArgument, "Illegal argument cursor")
	}
	var v int64
	for _, ch := range c[1:] {
		if ch < '0' || ch > '9' {
			return 0, grpcstatus.Error(codes.InvalidArgument, "Illegal argument cursor")
		}
		v = v*10 + int64(ch-'0')
	}
	return v, nil
}

// fakeChecker — the relation store. `answer` is what it says; `fail` makes it
// unable to answer at all, which must NOT be read as a "yes".
type fakeChecker struct {
	answer bool
	fail   bool
	// subject запоминается затем, что гейт обязан спрашивать про КАЛЛЕРА-МОДУЛЬ,
	// а не про арендатора: без этой записи проба зеленела бы на любом субъекте.
	subject  string
	relation string
	object   string
}

func (f *fakeChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	f.subject, f.relation, f.object = subject, relation, object
	if f.fail {
		return false, grpcstatus.Error(codes.Unavailable, "store unreachable")
	}
	return f.answer, nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func callerCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: "sva-owner"})
}

func newLimitID() string { return ids.NewHyphenID(ids.PrefixLimitHyphen) }

func codeOf(t *testing.T, err error) codes.Code {
	t.Helper()
	require.Error(t, err)
	return grpcstatus.Code(err)
}

func fieldOf(t *testing.T, err error) string {
	t.Helper()
	st, ok := grpcstatus.FromError(err)
	require.True(t, ok)
	for _, d := range st.Details() {
		if br, ok := d.(*errdetails.BadRequest); ok && len(br.GetFieldViolations()) > 0 {
			return br.GetFieldViolations()[0].GetField()
		}
	}
	return ""
}

// ── Create ───────────────────────────────────────────────────────────────────

// TestCreate_KindOutsideCatalogue_RefusedByName — VPCQ-03.
//
// The refusal is synchronous and names `kind`. A ceiling on a kind nobody counts
// would otherwise be accepted and never applied: the administrator sees success,
// the tenant sees no effect.
func TestCreate_KindOutsideCatalogue_RefusedByName(t *testing.T) {
	repo, ops := newFakeRepo(), &fakeOps{}
	uc := NewCreateUseCase(repo, ops, nil)

	_, err := uc.Execute(callerCtx(), &iamv1.CreateLimitRequest{
		Scope: iamv1.Limit_PROJECT, ScopeId: "prj-x", Kind: "vpc.netwrok", Value: 4,
	})

	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.Contains(t, grpcstatus.Convert(err).Message(), "kind")
	require.False(t, ops.created, "a refused request must not leave an operation behind")
	require.False(t, repo.touched, "the refusal is synchronous — the store is never reached")
}

// TestCreate_NegativeValue_RefusedByName — VPCQ-02.
func TestCreate_NegativeValue_RefusedByName(t *testing.T) {
	repo, ops := newFakeRepo(), &fakeOps{}
	uc := NewCreateUseCase(repo, ops, nil)

	_, err := uc.Execute(callerCtx(), &iamv1.CreateLimitRequest{
		Scope: iamv1.Limit_PROJECT, ScopeId: "prj-x", Kind: "vpc.network", Value: -1,
	})

	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.Contains(t, grpcstatus.Convert(err).Message(), "value")
	require.False(t, ops.created)
	require.False(t, repo.touched)
}

// TestCreate_ScopeSubjectPairing — the scope and its subject are one statement.
//
// Both directions are asserted. Only checking the missing subject would leave the
// opposite — a DEFAULT carrying a subject — to be stored and then to lose to
// itself in precedence, which is a far quieter defect.
func TestCreate_ScopeSubjectPairing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		scope   iamv1.Limit_Scope
		scopeID string
	}{
		{"scoped without a subject", iamv1.Limit_PROJECT, ""},
		{"default with a subject", iamv1.Limit_DEFAULT, "prj-x"},
		{"scope not stated at all", iamv1.Limit_SCOPE_UNSPECIFIED, "prj-x"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo, ops := newFakeRepo(), &fakeOps{}
			_, err := NewCreateUseCase(repo, ops, nil).Execute(callerCtx(),
				&iamv1.CreateLimitRequest{Scope: tc.scope, ScopeId: tc.scopeID, Kind: "vpc.network", Value: 1})
			require.Equal(t, codes.InvalidArgument, codeOf(t, err))
			require.False(t, repo.touched)
		})
	}

	// Positive control — without it "refused" is indistinguishable from
	// "everything is refused".
	repo, ops := newFakeRepo(), &fakeOps{}
	op, err := NewCreateUseCase(repo, ops, nil).Execute(callerCtx(),
		&iamv1.CreateLimitRequest{Scope: iamv1.Limit_DEFAULT, Kind: "vpc.network", Value: 16})
	require.NoError(t, err)
	require.True(t, op.GetDone())
	require.True(t, ops.created && ops.doneMarked)
}

// TestCreate_ZeroIsALegalCeiling — zero means "none of this kind", and it is a
// decision an administrator may make. Treating it as "unset" would silently drop
// the strictest ceiling there is.
func TestCreate_ZeroIsALegalCeiling(t *testing.T) {
	repo, ops := newFakeRepo(), &fakeOps{}
	_, err := NewCreateUseCase(repo, ops, nil).Execute(callerCtx(),
		&iamv1.CreateLimitRequest{Scope: iamv1.Limit_DEFAULT, Kind: "vpc.gateway", Value: 0})
	require.NoError(t, err)
	require.Len(t, repo.rows, 1)
	for _, l := range repo.rows {
		require.Equal(t, int64(0), l.Value)
	}
}

// ── Get ──────────────────────────────────────────────────────────────────────

// TestGet_MalformedID_RefusedFirst — VPCQ-05: the format check is the FIRST
// statement, and it carries the lane token as well as the code.
//
// Without it a malformed id reaches the store and comes back NOT_FOUND — an
// assertion about the absence of a resource the caller never named.
func TestGet_MalformedID_RefusedFirst(t *testing.T) {
	repo := newFakeRepo()
	_, err := NewGetUseCase(repo).Execute(callerCtx(), "not-an-id")

	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.Equal(t, "invalid limit id 'not-an-id'", grpcstatus.Convert(err).Message())
	require.False(t, repo.touched, "the store must not be reached with a malformed id")

	st, _ := grpcstatus.FromError(err)
	var token string
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			token = info.GetReason()
			require.Equal(t, "iam.kacho.cloud", info.GetDomain())
		}
	}
	require.Equal(t, "INVALID_RESOURCE_ID", token)
}

// TestGet_EmptyID_RefusedAsRequired — the platform's id validator lets the empty
// string through BY CONTRACT, so the required-check is made here.
//
// Without it an empty id travels on and comes back as `Limit  not found` — an
// assertion about a resource with no name.
func TestGet_EmptyID_RefusedAsRequired(t *testing.T) {
	repo := newFakeRepo()
	_, err := NewGetUseCase(repo).Execute(callerCtx(), "")
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.Equal(t, "limit_id", fieldOf(t, err))
	require.False(t, repo.touched)
}

// ── List ─────────────────────────────────────────────────────────────────────

// TestList_PaginationFormatRefusedBeforeTheStore — the format of a request has ONE
// answer for every caller, so it is decided before anything else.
func TestList_PaginationFormatRefusedBeforeTheStore(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pageSize  int64
		pageToken string
	}{
		{"page size above the bound", 1001, ""},
		{"negative page size", -1, ""},
		{"garbage cursor", 0, "!!!not-base64!!!"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := newFakeRepo()
			_, err := NewListUseCase(repo).Execute(callerCtx(), tc.pageSize, tc.pageToken, domain.LimitFilter{})
			require.Equal(t, codes.InvalidArgument, codeOf(t, err))
			require.False(t, repo.touched)
		})
	}
	// Positive control.
	repo := newFakeRepo()
	_, err := NewListUseCase(repo).Execute(callerCtx(), 10, "", domain.LimitFilter{})
	require.NoError(t, err)
	require.True(t, repo.touched)
}

// TestList_FilterValueOutsideItsDimension_RefusedByName — a narrowing value that
// is not a legal value of its dimension is refused rather than quietly matching
// nothing, because an empty page is indistinguishable from "there is nothing
// here".
func TestList_FilterValueOutsideItsDimension_RefusedByName(t *testing.T) {
	repo := newFakeRepo()
	_, err := NewListUseCase(repo).Execute(callerCtx(), 10, "",
		domain.LimitFilter{Kind: "vpc.netwrok"})
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.Contains(t, grpcstatus.Convert(err).Message(), "kind")
}

// ── Update ───────────────────────────────────────────────────────────────────

// TestUpdate_MaskDiscipline — an immutable field named in the mask is refused BY
// NAME, and the check runs BEFORE the known-set check.
//
// Order matters and is the whole point of the test: the known-set does not contain
// the immutable fields, so a generic "unknown field" would fire first and the
// caller would never learn that the field exists and simply cannot be changed.
func TestUpdate_MaskDiscipline(t *testing.T) {
	for _, path := range []string{"scope", "scope_id", "kind", "id", "revision", "scopeId"} {
		t.Run(path, func(t *testing.T) {
			repo, ops := newFakeRepo(), &fakeOps{}
			_, err := NewUpdateUseCase(repo, ops, nil).Execute(callerCtx(), &iamv1.UpdateLimitRequest{
				LimitId:    newLimitID(),
				UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{path}},
				Value:      2,
			})
			require.Equal(t, codes.InvalidArgument, codeOf(t, err))
			require.Contains(t, grpcstatus.Convert(err).Message(), "is immutable after Limit.Create")
			require.False(t, ops.created)
		})
	}

	t.Run("unknown field", func(t *testing.T) {
		repo, ops := newFakeRepo(), &fakeOps{}
		_, err := NewUpdateUseCase(repo, ops, nil).Execute(callerCtx(), &iamv1.UpdateLimitRequest{
			LimitId:    newLimitID(),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"ceiling"}},
			Value:      2,
		})
		require.Equal(t, codes.InvalidArgument, codeOf(t, err))
		require.NotContains(t, grpcstatus.Convert(err).Message(), "is immutable",
			"an unknown field is not an immutable one — the two answers send the caller to different places")
	})

	// Positive control: the one mutable field goes through.
	t.Run("value", func(t *testing.T) {
		repo, ops := newFakeRepo(), &fakeOps{}
		seeded := domain.Limit{ID: domain.LimitID(newLimitID()), Scope: domain.LimitScopeDefault,
			Kind: "vpc.network", Value: 16, Revision: 1}
		repo.rows[seeded.ID] = seeded

		op, err := NewUpdateUseCase(repo, ops, nil).Execute(callerCtx(), &iamv1.UpdateLimitRequest{
			LimitId:    string(seeded.ID),
			UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"value"}},
			Value:      32,
		})
		require.NoError(t, err)
		require.True(t, op.GetDone())
		require.Equal(t, int64(32), repo.rows[seeded.ID].Value)
	})
}

// TestUpdate_NegativeValue_RefusedBeforeTheStore — the same rule Create applies,
// applied on the other door. A mutable field must not be reachable through Update
// in a shape Create would refuse.
func TestUpdate_NegativeValue_RefusedBeforeTheStore(t *testing.T) {
	repo, ops := newFakeRepo(), &fakeOps{}
	_, err := NewUpdateUseCase(repo, ops, nil).Execute(callerCtx(), &iamv1.UpdateLimitRequest{
		LimitId: newLimitID(), Value: -5,
	})
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.Equal(t, "value", fieldOf(t, err))
	require.False(t, repo.touched)
	require.False(t, ops.created)
}

// ── Delete ───────────────────────────────────────────────────────────────────

// TestDelete_IsIdempotent — withdrawing an already-withdrawn ceiling succeeds and
// reports the same code as the first withdrawal: the caller asked for it to be
// gone, and it is.
func TestDelete_IsIdempotent(t *testing.T) {
	repo, ops := newFakeRepo(), &fakeOps{}
	seeded := domain.Limit{ID: domain.LimitID(newLimitID()), Scope: domain.LimitScopeDefault,
		Kind: "vpc.network", Value: 16}
	repo.rows[seeded.ID] = seeded

	uc := NewDeleteUseCase(repo, ops, nil)
	first, err := uc.Execute(callerCtx(), string(seeded.ID))
	require.NoError(t, err)
	require.True(t, first.GetDone())

	second, err := uc.Execute(callerCtx(), string(seeded.ID))
	require.NoError(t, err, "the repeat must not become an error")
	require.True(t, second.GetDone())
}

// ── Resolve ──────────────────────────────────────────────────────────────────

// TestResolve_NarrowGate — VPCQ-09, both halves.
//
// The four failure modes are asserted TOGETHER because they must all end the same
// way: an anonymous caller, an unwired gate, a store that cannot answer, and an
// explicit deny. A gate that cannot answer is not an answer of "yes".
func TestResolve_NarrowGate(t *testing.T) {
	stated := []domain.Limit{{Scope: domain.LimitScopeDefault, Kind: "vpc.network", Value: 16}}

	t.Run("anonymous caller", func(t *testing.T) {
		repo := newFakeRepo()
		repo.stated = stated
		_, err := NewResolveUseCase(repo).WithQuotaReaderChecker(&fakeChecker{answer: true}).
			Execute(context.Background(), "prj-x", "vpc")
		require.Equal(t, codes.PermissionDenied, codeOf(t, err))
		require.False(t, repo.touched)
	})

	t.Run("gate not wired", func(t *testing.T) {
		repo := newFakeRepo()
		repo.stated = stated
		_, err := NewResolveUseCase(repo).Execute(callerCtx(), "prj-x", "vpc")
		require.Equal(t, codes.PermissionDenied, codeOf(t, err),
			"an unwired gate must fail closed — an unauthorised read of the platform's ceilings is not a lesser failure")
		require.False(t, repo.touched)
	})

	t.Run("store cannot answer", func(t *testing.T) {
		repo := newFakeRepo()
		repo.stated = stated
		_, err := NewResolveUseCase(repo).WithQuotaReaderChecker(&fakeChecker{fail: true}).
			Execute(callerCtx(), "prj-x", "vpc")
		require.Equal(t, codes.PermissionDenied, codeOf(t, err))
		require.False(t, repo.touched)
	})

	t.Run("explicit deny", func(t *testing.T) {
		repo := newFakeRepo()
		repo.stated = stated
		_, err := NewResolveUseCase(repo).WithQuotaReaderChecker(&fakeChecker{answer: false}).
			Execute(callerCtx(), "prj-x", "vpc")
		require.Equal(t, codes.PermissionDenied, codeOf(t, err))
		require.False(t, repo.touched)
	})

	// Positive control, and the question asked is asserted too: the relation must
	// be the NARROW one, on the cluster object. A gate that passed while asking
	// something wider would look identical here.
	t.Run("granted", func(t *testing.T) {
		repo := newFakeRepo()
		repo.stated = stated
		checker := &fakeChecker{answer: true}
		got, err := NewResolveUseCase(repo).WithQuotaReaderChecker(checker).
			Execute(callerCtx(), "prj-x", "vpc")
		require.NoError(t, err)
		require.Len(t, got, 1)
		require.Equal(t, "quota_reader", checker.relation)
		require.Equal(t, "cluster:"+domain.ClusterSingletonID, checker.object)
	})
}

// TestResolve_GateAsksAboutTheCallingMODULE — право читать пределы принадлежит
// МОДУЛЮ, а не арендатору, от чьего имени модуль сейчас работает.
//
// ЧТО ЭТО СТОИЛО. Клиенты пределов пробрасывают личность инициатора
// (`auth.PropagateOutgoing`), потому что без неё внутренний листенер видел бы
// безымянный вызов. Следствие: гейт спрашивал модель прав про АРЕНДАТОРА — а
// членство в группе читателей пределов заведено служебным учётным записям
// модулей. Ни один арендатор его не имеет и иметь не должен, поэтому резолв
// отказывал ВСЕГДА, а списание квоты fail-closed роняло каждую мутацию домена.
// В сквозном прогоне это дало более двух тысяч упавших утверждений, из которых
// прямо о квоте говорили 66 — остальное каскад.
//
// Модуль доказывает себя СЕРТИФИКАТОМ, и iam уже умеет выводить из него учётную
// запись (`SANToServiceAccountID`) — этим же способом работает пол чтения на том
// же листенере. Гейт обязан спрашивать про неё.
func TestResolve_GateAsksAboutTheCallingMODULE(t *testing.T) {
	repo := newFakeRepo()
	repo.stated = []domain.Limit{{Scope: domain.LimitScopeDefault, Kind: "vpc.network", Value: 16}}
	checker := &fakeChecker{answer: true}

	// Контекст стенда: проверенная личность сертификата модуля ПЛЮС проброшенная
	// личность арендатора. Оба присутствуют — вопрос в том, про кого спросят.
	ctx := grpcsrv.WithCertIdentity(context.Background(), "spiffe://kacho.cloud/ns/kacho/sa/kacho-compute", true)
	ctx = operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: "usr-tenant"})

	_, err := NewResolveUseCase(repo).WithQuotaReaderChecker(checker).Execute(ctx, "prj-x", "vpc")
	require.NoError(t, err)
	require.Equal(t, "service_account:"+authzguard.ServiceAccountIDForService("compute"), checker.subject,
		"спрошено должно быть про учётную запись МОДУЛЯ: членство в группе читателей заведено ей, "+
			"а не арендатору, от чьего имени модуль работает")
}

// TestResolve_NoModuleIdentity_FallsBackToPrincipal — в процессной фикстуре
// сертификата нет вовсе, и гейт обязан остаться работоспособным: иначе юниты
// начали бы утверждать не то, что исполняется на стенде.
func TestResolve_NoModuleIdentity_FallsBackToPrincipal(t *testing.T) {
	repo := newFakeRepo()
	repo.stated = []domain.Limit{{Scope: domain.LimitScopeDefault, Kind: "vpc.network", Value: 16}}
	checker := &fakeChecker{answer: true}

	_, err := NewResolveUseCase(repo).WithQuotaReaderChecker(checker).Execute(callerCtx(), "prj-x", "vpc")
	require.NoError(t, err)
	require.Equal(t, "service_account:sva-owner", checker.subject)
}

// TestResolve_UnknownScopeObject_NotFoundLane — an id that names neither a project
// nor an account is the direct-read lane: both are iam's OWN rows.
func TestResolve_UnknownScopeObject_NotFoundLane(t *testing.T) {
	repo := newFakeRepo()
	repo.knownObj = false
	_, err := NewResolveUseCase(repo).WithQuotaReaderChecker(&fakeChecker{answer: true}).
		Execute(callerCtx(), "prj-nowhere", "vpc")
	require.Equal(t, codes.NotFound, codeOf(t, err))
}

// TestResolve_ServiceWithNoCountableKinds_RefusedByName — a service nobody counts
// for is refused rather than answered with an empty list.
//
// An empty answer reads as "this tenant has no ceilings", and the owner would then
// have to decide what that means — the guess this contract exists to remove.
func TestResolve_ServiceWithNoCountableKinds_RefusedByName(t *testing.T) {
	repo := newFakeRepo()
	_, err := NewResolveUseCase(repo).WithQuotaReaderChecker(&fakeChecker{answer: true}).
		Execute(callerCtx(), "prj-x", "no-such-service")
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.Equal(t, "service", fieldOf(t, err))
}

// TestResolve_PrecedenceAndCatalogueOrder — VPCQ-08 at the use-case level: the
// most specific scope wins, the winner names where it came from, and the answer
// comes back in CATALOGUE order.
//
// The order is asserted because a repeated field is read as a fact about the
// tenant: an answer ordered by whatever a map yielded would be a different fact on
// every call.
func TestResolve_PrecedenceAndCatalogueOrder(t *testing.T) {
	repo := newFakeRepo()
	repo.stated = []domain.Limit{
		{Scope: domain.LimitScopeDefault, Kind: "vpc.subnet", Value: 64},
		{Scope: domain.LimitScopeAccount, ScopeID: "acc-1", Kind: "vpc.network", Value: 8},
		{Scope: domain.LimitScopeDefault, Kind: "vpc.network", Value: 16},
		{Scope: domain.LimitScopeProject, ScopeID: "prj-1", Kind: "vpc.network", Value: 4},
		// A kind of ANOTHER service must not travel in this answer.
		{Scope: domain.LimitScopeDefault, Kind: "iam.project", Value: 16},
	}
	got, err := NewResolveUseCase(repo).WithQuotaReaderChecker(&fakeChecker{answer: true}).
		Execute(callerCtx(), "prj-1", "vpc")
	require.NoError(t, err)
	require.Len(t, got, 2)
	require.Equal(t, domain.LimitKind("vpc.network"), got[0].Kind, "catalogue order, not map order")
	require.Equal(t, int64(4), got[0].Value)
	require.Equal(t, domain.LimitScopeProject, got[0].SourceScope)
	require.Equal(t, "prj-1", got[0].SourceScopeID)
	require.Equal(t, domain.LimitKind("vpc.subnet"), got[1].Kind)
	require.Equal(t, domain.LimitScopeDefault, got[1].SourceScope)
	require.Empty(t, got[1].SourceScopeID, "a DEFAULT winner names no subject")
}

// ── ListChangedSince ─────────────────────────────────────────────────────────

// TestListChanged_Gate — the same narrow gate guards the delta. Both halves.
func TestListChanged_Gate(t *testing.T) {
	repo := newFakeRepo()
	_, err := NewListChangedUseCase(repo, fakeCursors{}).WithQuotaReaderChecker(&fakeChecker{answer: false}).
		Execute(callerCtx(), "", 10)
	require.Equal(t, codes.PermissionDenied, codeOf(t, err))
	require.False(t, repo.touched)

	res, err := NewListChangedUseCase(repo, fakeCursors{}).WithQuotaReaderChecker(&fakeChecker{answer: true}).
		Execute(callerCtx(), "", 10)
	require.NoError(t, err)
	require.NotEmpty(t, res.NextCursor, "the cursor comes back even on an empty page")
}

// TestListChanged_GarbageCursor_Refused — an unreadable cursor is refused, not read
// as "from the beginning": the latter would replay the whole history and look
// exactly like a healthy first run.
func TestListChanged_GarbageCursor_Refused(t *testing.T) {
	repo := newFakeRepo()
	_, err := NewListChangedUseCase(repo, fakeCursors{}).WithQuotaReaderChecker(&fakeChecker{answer: true}).
		Execute(callerCtx(), "not-a-cursor", 10)
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.False(t, repo.touched)
}

// TestListChanged_PageSizeOutOfRange_Refused — rejected, never clamped.
func TestListChanged_PageSizeOutOfRange_Refused(t *testing.T) {
	repo := newFakeRepo()
	_, err := NewListChangedUseCase(repo, fakeCursors{}).WithQuotaReaderChecker(&fakeChecker{answer: true}).
		Execute(callerCtx(), "", 1001)
	require.Equal(t, codes.InvalidArgument, codeOf(t, err))
	require.False(t, repo.touched)
}
