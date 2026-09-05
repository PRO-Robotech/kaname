// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

// usecases_test.go — IAM-INT-1 scenarios 04, 05, 06, 07 at the layer that owns
// them: the order of checks inside an RPC and the shape of what comes back.
//
// The ports are fakes, deliberately. Every property below is about the USE-CASE's
// own ordering — malformed id before any store call, immutable before known-set —
// and a real store would make those orderings unobservable rather than clearer.

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// fakeRepo — records whether it was reached. "Was the store touched at all" is
// the observable that scenario 05 is actually about.
type fakeRepo struct {
	touched bool
	get     domain.InteractiveClient
	getErr  error
}

func (f *fakeRepo) Get(_ context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, error) {
	f.touched = true
	if f.getErr != nil {
		return domain.InteractiveClient{}, f.getErr
	}
	c := f.get
	c.ID = id
	return c, nil
}

func (f *fakeRepo) List(_ context.Context, _ int, _, _ string) ([]domain.InteractiveClient, string, error) {
	f.touched = true
	return nil, "", nil
}

func (f *fakeRepo) Insert(_ context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error) {
	f.touched = true
	return c, nil
}

func (f *fakeRepo) Update(_ context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error) {
	f.touched = true
	return c, nil
}

func (f *fakeRepo) Delete(_ context.Context, _ domain.InteractiveClientID) (domain.InteractiveClient, bool, error) {
	f.touched = true
	return domain.InteractiveClient{}, false, nil
}

func validStored() domain.InteractiveClient {
	return domain.InteractiveClient{
		Name:         "console-a",
		RedirectURIs: []string{"https://api.example/cb"},
		Status:       domain.InteractiveClientActive,
		CreatedAt:    time.Now(),
	}
}

// TestGet_MalformedID_IsRefusedBeforeTheStoreIsTouched — scenario 05.
//
// The code is only half the property. The other half is that the store was NOT
// consulted: if the format check ran after the read, a malformed id would come
// back as NOT_FOUND — an assertion that a resource is absent, made about a
// string that could never have named one.
func TestGet_MalformedID_IsRefusedBeforeTheStoreIsTouched(t *testing.T) {
	repo := &fakeRepo{get: validStored()}
	_, err := NewGetUseCase(repo).Execute(context.Background(), "не-идентификатор")

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", st.Code())
	}
	if want := "invalid interactive client id 'не-идентификатор'"; st.Message() != want {
		t.Errorf("message = %q, want %q (contract tone)", st.Message(), want)
	}
	if repo.touched {
		t.Error("the store was consulted for a malformed id — the format check is not the first statement")
	}
}

// TestGet_EmptyID_NamesTheField — corevalidate.ResourceID lets the empty string
// through by contract, so the required-check is the caller's job. Without it an
// empty id travels on and returns `InteractiveClient  not found` — the tone of an
// absent resource, applied to a string the caller never supplied.
func TestGet_EmptyID_NamesTheField(t *testing.T) {
	repo := &fakeRepo{get: validStored()}
	_, err := NewGetUseCase(repo).Execute(context.Background(), "")

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", st.Code())
	}
	if repo.touched {
		t.Error("the store was consulted for an empty id")
	}
}

// TestGet_WellFormedButAbsent_IsNotFoundWithTheContractTone — scenario 04.
// The paired opposite of the test above: a well-formed id DOES reach the store,
// and its absence is NOT_FOUND. Without this half, "malformed is refused" would
// be indistinguishable from "everything is refused".
func TestGet_WellFormedButAbsent_IsNotFoundWithTheContractTone(t *testing.T) {
	repo := &fakeRepo{getErr: iamerr.Wrapf(iamerr.ErrNotFound,
		"InteractiveClient ic-00000000000000000 not found")}
	_, err := NewGetUseCase(repo).Execute(context.Background(), "ic-00000000000000000")

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Fatalf("code = %v, want NotFound", st.Code())
	}
	if want := "InteractiveClient ic-00000000000000000 not found"; st.Message() != want {
		t.Errorf("message = %q, want %q", st.Message(), want)
	}
	if !repo.touched {
		t.Error("a well-formed id must reach the store — otherwise the check above proves nothing")
	}
}

func updateReq(id string, paths ...string) *iamv1.UpdateInteractiveClientRequest {
	return &iamv1.UpdateInteractiveClientRequest{
		InteractiveClientId: id,
		UpdateMask:          &fieldmaskpb.FieldMask{Paths: paths},
		Name:                "console-b",
		RedirectUris:        []string{"https://api.example/cb2"},
	}
}

// TestUpdate_ImmutableInMask_IsNamedNotGenericallyUnknown — scenario 06.
//
// ORDER IS THE PROPERTY. The known-set does not contain the immutable fields, so
// running the known-set check first would answer "unknown field" — technically a
// refusal, but it tells the caller the field does not exist, when in fact it
// exists and simply cannot be changed. Those are different facts and lead to
// different next actions.
func TestUpdate_ImmutableInMask_IsNamedNotGenericallyUnknown(t *testing.T) {
	for _, field := range []string{"audiences", "client_id", "grant_types", "status", "id", "created_at"} {
		t.Run(field, func(t *testing.T) {
			repo := &fakeRepo{get: validStored()}
			_, err := NewUpdateUseCase(repo, nil, nil).
				Execute(context.Background(), updateReq("ic-00000000000000000", field))

			st, _ := status.FromError(err)
			if st.Code() != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument", st.Code())
			}
			want := field + " is immutable after InteractiveClient.Create"
			if st.Message() != want {
				t.Errorf("message = %q, want %q", st.Message(), want)
			}
		})
	}
}

// TestUpdate_ImmutableInMask_AcceptsCamelCase — the same field named the way REST
// spells it. Refusing one spelling and not the other would make the answer depend
// on which door the caller used.
func TestUpdate_ImmutableInMask_AcceptsCamelCase(t *testing.T) {
	repo := &fakeRepo{get: validStored()}
	_, err := NewUpdateUseCase(repo, nil, nil).
		Execute(context.Background(), updateReq("ic-00000000000000000", "clientId"))

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument", st.Code())
	}
	if want := "client_id is immutable after InteractiveClient.Create"; st.Message() != want {
		t.Errorf("message = %q, want %q", st.Message(), want)
	}
}

// TestUpdate_UnknownFieldInMask_IsRefused — scenario 07's negative half.
func TestUpdate_UnknownFieldInMask_IsRefused(t *testing.T) {
	repo := &fakeRepo{get: validStored()}
	_, err := NewUpdateUseCase(repo, nil, nil).
		Execute(context.Background(), updateReq("ic-00000000000000000", "nonexistentField"))

	if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument for an unknown mask path", st.Code())
	}
}

// TestUpdate_MutableFieldInMask_IsAccepted — scenario 06/07's positive half, and
// the control that makes every refusal above meaningful. Without it the mask
// discipline would be indistinguishable from "Update refuses everything".
//
// The operation port is exercised through a fake so the use-case runs to the end.
func TestUpdate_MutableFieldInMask_IsAccepted(t *testing.T) {
	repo := &fakeRepo{get: validStored()}
	ops := &fakeOps{}
	op, err := NewUpdateUseCase(repo, ops, nil).
		Execute(context.Background(), updateReq("ic-00000000000000000", "name"))
	if err != nil {
		t.Fatalf("a mutable field in the mask was refused: %v", err)
	}
	if op == nil || !op.GetDone() {
		t.Fatal("Update must return a terminal Operation")
	}
	if !ops.created || !ops.doneMarked {
		t.Error("the operation row must be created before the mutation and marked done after it")
	}
}

// TestList_PaginationIsJudgedBeforeTheStore — the garbage cursor and the
// out-of-range page size are refused without consulting the store, so the answer
// cannot depend on what the store happens to hold.
func TestList_PaginationIsJudgedBeforeTheStore(t *testing.T) {
	for name, tc := range map[string]struct {
		size  int64
		token string
	}{
		"garbage token": {size: 10, token: "!!!not-base64!!!"},
		"size over max": {size: 1001},
		"negative size": {size: -1},
	} {
		t.Run(name, func(t *testing.T) {
			repo := &fakeRepo{}
			_, err := NewListUseCase(repo).Execute(context.Background(), tc.size, tc.token, "")
			if st, _ := status.FromError(err); st.Code() != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument", st.Code())
			}
			if repo.touched {
				t.Error("the store was consulted despite invalid pagination")
			}
		})
	}

	// Positive control: a legitimate page DOES reach the store.
	repo := &fakeRepo{}
	if _, err := NewListUseCase(repo).Execute(context.Background(), 10, "", ""); err != nil {
		t.Fatalf("a valid List was refused: %v", err)
	}
	if !repo.touched {
		t.Error("a valid List never reached the store — the refusals above prove nothing")
	}
}

// failingProvider — a provider that refuses to register (scenario 08) or refuses
// to deregister (the compensation path). `deregistered` records whether the
// compensation actually ran: that is the whole point of the test, and a fake
// that only returned an error would not show it.
type failingProvider struct {
	registerErr  error
	registered   bool
	deregistered bool
}

func (p *failingProvider) Register(_ context.Context, _ ProviderClientSpec) (ProviderClient, error) {
	if p.registerErr != nil {
		return ProviderClient{}, p.registerErr
	}
	p.registered = true
	return ProviderClient{
		ClientID:                "provider-abc",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethod: "none",
		Audiences:               []string{"https://api.example"},
	}, nil
}

func (p *failingProvider) Deregister(_ context.Context, _ string) error {
	p.deregistered = true
	return nil
}

// insertFailsRepo — accepts nothing, so the compensation path is reached.
type insertFailsRepo struct {
	fakeRepo
	inserted bool
}

func (r *insertFailsRepo) Insert(_ context.Context, _ domain.InteractiveClient) (domain.InteractiveClient, error) {
	r.inserted = true
	return domain.InteractiveClient{}, iamerr.Wrapf(iamerr.ErrAlreadyExists,
		"InteractiveClient with name console-a already exists")
}

func createReq() *iamv1.CreateInteractiveClientRequest {
	return &iamv1.CreateInteractiveClientRequest{
		Name:         "console-a",
		RedirectUris: []string{"https://api.example/cb"},
	}
}

// TestCreate_ProviderUnavailable_LeavesNothingBehind — scenario 08.
//
// The provider is contacted first, so its refusal must end the call with NO row
// written. "No residue" is the substantive half: if a row were inserted anyway,
// the name would stay taken by a client that was never registered, and the
// retry the caller is entitled to make would fail for ever after.
func TestCreate_ProviderUnavailable_LeavesNothingBehind(t *testing.T) {
	repo := &insertFailsRepo{}
	prov := &failingProvider{registerErr: iamerr.Wrapf(iamerr.ErrUnavailable, "identity provider unavailable")}
	ops := &fakeOps{}

	_, err := NewCreateUseCase(repo, prov, ops, []string{"https://api.example"}, nil).
		Execute(context.Background(), createReq())

	if st, _ := status.FromError(err); st.Code() != codes.Unavailable {
		t.Fatalf("code = %v, want Unavailable (fail-closed on a mutation)", st.Code())
	}
	if repo.inserted {
		t.Error("a row was written although the provider never registered the client — the name is now taken by nothing")
	}
	if !ops.errMarked {
		t.Error("the operation must be marked with a terminal error, not left for the caller to poll for ever")
	}
}

// TestCreate_InsertFails_CompensatesTheRegistration — the other half of the same
// ordering decision. The provider succeeded, the row did not, and the client that
// was just registered must be removed again: otherwise the provider holds a
// client the platform has no record of, nothing will ever remove it, and it keeps
// accepting ceremonies.
func TestCreate_InsertFails_CompensatesTheRegistration(t *testing.T) {
	repo := &insertFailsRepo{}
	prov := &failingProvider{}
	ops := &fakeOps{}

	_, err := NewCreateUseCase(repo, prov, ops, []string{"https://api.example"}, nil).
		Execute(context.Background(), createReq())

	if st, _ := status.FromError(err); st.Code() != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", st.Code())
	}
	if !prov.registered {
		t.Fatal("the provider was never reached — this test proves nothing about compensation")
	}
	if !prov.deregistered {
		t.Error("the registration was NOT compensated — an orphan client remains that the platform cannot name")
	}
}

// TestUpdate_EmptyMask_AppliesEveryMutableField — scenario 07's positive half.
// An empty mask is a full-object PATCH over the mutable fields; the immutable
// values carried in the body are ignored rather than refused.
func TestUpdate_EmptyMask_AppliesEveryMutableField(t *testing.T) {
	stored := validStored()
	stored.ClientID = "provider-original"
	repo := &recordingRepo{fakeRepo: fakeRepo{get: stored}}
	ops := &fakeOps{}

	req := &iamv1.UpdateInteractiveClientRequest{
		InteractiveClientId: "ic-00000000000000000",
		Name:                "console-renamed",
		Description:         "new description",
		RedirectUris:        []string{"https://api.example/new"},
	}
	if _, err := NewUpdateUseCase(repo, ops, nil).Execute(context.Background(), req); err != nil {
		t.Fatalf("empty-mask Update was refused: %v", err)
	}
	if got := string(repo.written.Name); got != "console-renamed" {
		t.Errorf("name = %q, want the body value — an empty mask is a full PATCH", got)
	}
	if got := repo.written.RedirectURIs; len(got) != 1 || got[0] != "https://api.example/new" {
		t.Errorf("redirect_uris = %v, want the body value", got)
	}
	if repo.written.ClientID != "provider-original" {
		t.Errorf("client_id = %q — an immutable field must be left alone, not taken from the body",
			repo.written.ClientID)
	}
}

// recordingRepo — captures what Update was asked to write.
type recordingRepo struct {
	fakeRepo
	written domain.InteractiveClient
}

func (r *recordingRepo) Update(_ context.Context, c domain.InteractiveClient) (domain.InteractiveClient, error) {
	r.written = c
	return c, nil
}
