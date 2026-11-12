// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantsource

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

// Нулевые встроенные интерфейсы падают при любом непредусмотренном обращении.
type bindingWriter struct {
	kaname.AuthorityWriter
	at           time.Time
	groups       bindingGroups
	bindings     bindingRows
	roles        bindingRoles
	versions     map[domain.AccessBindingID]int
	versionErr   error
	versionCalls int
}

func (w *bindingWriter) AuthorityFence() kaname.AuthorityFence      { return bindingFence{at: w.at} }
func (w *bindingWriter) Groups() group.ReaderIface                  { return &w.groups }
func (w *bindingWriter) AccessBindings() access_binding.ReaderIface { return &w.bindings }
func (w *bindingWriter) Roles() role.ReaderIface                    { return &w.roles }
func (w *bindingWriter) BindingCapabilityVersions(_ context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID]int, error) {
	w.versionCalls++
	out := map[domain.AccessBindingID]int{}
	for _, id := range ids {
		if v, ok := w.versions[id]; ok {
			out[id] = v
		}
	}
	return out, w.versionErr
}

type bindingFence struct {
	kaname.AuthorityFence
	at time.Time
}

func (f bindingFence) DecisionAt() time.Time { return f.at }

type bindingGroups struct {
	group.ReaderIface
	list func(group.ListFilter) ([]domain.Group, string, error)
}

func (g *bindingGroups) List(_ context.Context, f group.ListFilter) ([]domain.Group, string, error) {
	return g.list(f)
}

type bindingRows struct {
	access_binding.ReaderIface
	list         func(domain.Subject, access_binding.PageFilter) ([]domain.AccessBinding, string, error)
	subjects     map[domain.AccessBindingID][]domain.Subject
	subjectErr   error
	subjectCalls int
}

func (b *bindingRows) ListBySubject(_ context.Context, typ domain.SubjectType, id domain.SubjectID, p access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
	return b.list(domain.Subject{Type: typ, ID: id}, p)
}
func (b *bindingRows) ListSubjectsForBindings(_ context.Context, ids []domain.AccessBindingID) (map[domain.AccessBindingID][]domain.Subject, error) {
	b.subjectCalls++
	out := map[domain.AccessBindingID][]domain.Subject{}
	for _, id := range ids {
		if s, ok := b.subjects[id]; ok {
			out[id] = s
		}
	}
	return out, b.subjectErr
}

type bindingRoles struct {
	role.ReaderIface
	calls int
	err   error
	errOn domain.RoleID
}

func (r *bindingRoles) Get(_ context.Context, id domain.RoleID) (domain.Role, error) {
	r.calls++
	if r.errOn != "" && r.errOn != id {
		return domain.Role{ID: id}, nil
	}
	return domain.Role{ID: id}, r.err
}

var sourceActor = domain.Subject{Type: domain.SubjectTypeUser, ID: "u-actor"}

func sourceBinding(id string) domain.AccessBinding {
	return domain.AccessBinding{ID: domain.AccessBindingID(id), SubjectType: sourceActor.Type, SubjectID: sourceActor.ID, RoleID: "role", ResourceType: "project", ResourceID: "project", Status: domain.AccessBindingStatusActive}
}
func sourceWriter(bs ...domain.AccessBinding) *bindingWriter {
	w := &bindingWriter{at: time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC), versions: map[domain.AccessBindingID]int{}}
	w.groups.list = func(group.ListFilter) ([]domain.Group, string, error) { return nil, "", nil }
	w.bindings.subjects = map[domain.AccessBindingID][]domain.Subject{}
	for _, b := range bs {
		w.versions[b.ID] = 0
		w.bindings.subjects[b.ID] = []domain.Subject{{Type: b.SubjectType, ID: b.SubjectID}}
	}
	w.bindings.list = func(s domain.Subject, page access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		if s != sourceActor {
			return nil, "", nil
		}
		start := 0
		if page.PageToken != "" {
			var err error
			start, err = strconv.Atoi(page.PageToken)
			if err != nil || start < 0 || start > len(bs) {
				return nil, "", errors.New("негодный токен тестового reader")
			}
		}
		if page.PageSize <= 0 {
			return nil, "", errors.New("не задан размер страницы тестового reader")
		}
		end := min(start+int(page.PageSize), len(bs))
		next := ""
		if end < len(bs) {
			next = strconv.Itoa(end)
		}
		return bs[start:end], next, nil
	}
	return w
}
func requireSourceFailure(t *testing.T, w *bindingWriter, want error) {
	t.Helper()
	out, err := CollectBindings(context.Background(), w, sourceActor)
	if !errors.Is(err, want) || out != nil {
		t.Fatalf("out=%v err=%v want=%v", out, err, want)
	}
}

func TestCollectBindingsExhaustionAndRecipientSemantics(t *testing.T) {
	b1, b2 := sourceBinding("b1"), sourceBinding("b2")
	other := domain.Subject{Type: domain.SubjectTypeUser, ID: "u-other"}
	grp := domain.Subject{Type: domain.SubjectTypeGroup, ID: "g1"}
	b1.SubjectID = other.ID
	w := sourceWriter(b1, b2)
	w.versions[b2.ID] = 1
	w.bindings.subjects[b1.ID] = []domain.Subject{other, sourceActor, grp}
	groupPages, bindingPages := 0, 0
	w.groups.list = func(f group.ListFilter) ([]domain.Group, string, error) {
		groupPages++
		if f.Member == nil || *f.Member != sourceActor || f.PageSize == 0 {
			t.Fatal("member filter missing")
		}
		switch f.PageToken {
		case "":
			return []domain.Group{{ID: "g1"}}, "g-next", nil
		case "g-next":
			return []domain.Group{{ID: "g2"}}, "", nil
		default:
			t.Fatal("unexpected group token")
			return nil, "", nil
		}
	}
	w.bindings.list = func(s domain.Subject, p access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		bindingPages++
		if s == sourceActor {
			if p.PageToken == "" {
				return []domain.AccessBinding{b1}, "b-next", nil
			}
			if p.PageToken == "b-next" {
				return []domain.AccessBinding{b2}, "", nil
			}
			t.Fatal("unexpected binding token")
		}
		if s == grp {
			return []domain.AccessBinding{b1}, "", nil
		}
		return nil, "", nil
	}
	out, err := CollectBindings(context.Background(), w, sourceActor)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 || groupPages != 2 || bindingPages != 4 || w.roles.calls != 1 || w.versionCalls != 1 || w.bindings.subjectCalls != 1 {
		t.Fatalf("out=%v groups=%d binding pages=%d role calls=%d", out, groupPages, bindingPages, w.roles.calls)
	}
	if out[0].Recipient != sourceActor || out[1].Recipient != grp || out[2].Binding.ID != b2.ID || out[2].CapabilityVersion != 1 {
		t.Fatalf("lost recipient/version: %+v", out)
	}
	if !reflect.DeepEqual(out[0].Binding.Subjects, []domain.Subject{other, sourceActor, grp}) {
		t.Fatal("lost full subject set")
	}
}

func TestCollectBindingsLifecycleAtFence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  domain.AccessBindingStatus
		expiry  int
		revoked bool
		want    int
	}{
		{"active", domain.AccessBindingStatusActive, 0, false, 1},
		{"strictly after", domain.AccessBindingStatusActive, 1, false, 1},
		{"equal", domain.AccessBindingStatusActive, 2, false, 0},
		{"before", domain.AccessBindingStatusActive, -1, false, 0},
		{"pending", domain.AccessBindingStatusPending, 0, false, 0},
		{"revoked status", domain.AccessBindingStatusRevoked, 0, false, 0},
		{"revoked timestamp", domain.AccessBindingStatusActive, 0, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := sourceBinding("b")
			b.Status = tc.status
			w := sourceWriter()
			switch tc.expiry {
			case 1:
				x := w.at.Add(time.Nanosecond)
				b.ExpiresAt = &x
			case 2:
				b.ExpiresAt = &w.at
			case -1:
				x := w.at.Add(-time.Nanosecond)
				b.ExpiresAt = &x
			}
			if tc.revoked {
				b.RevokedAt = &w.at
			}
			w = sourceWriter(b)
			out, err := CollectBindings(context.Background(), w, sourceActor)
			if err != nil || len(out) != tc.want {
				t.Fatalf("out=%v err=%v", out, err)
			}
			if tc.want == 0 && w.roles.calls != 0 {
				t.Fatal("loaded role for unusable binding")
			}
		})
	}
}

func TestCollectBindingsMetadataFailsClosed(t *testing.T) {
	for _, tc := range []string{"missing version", "unknown version", "missing subjects", "duplicate subjects", "wrong recipient", "legacy mismatch", "too many subjects", "invalid subject", "invalid binding", "zero time"} {
		t.Run(tc, func(t *testing.T) {
			b := sourceBinding("b")
			w := sourceWriter(b)
			switch tc {
			case "missing version":
				delete(w.versions, b.ID)
			case "unknown version":
				w.versions[b.ID] = 2
			case "missing subjects":
				delete(w.bindings.subjects, b.ID)
			case "duplicate subjects":
				w.bindings.subjects[b.ID] = []domain.Subject{sourceActor, sourceActor}
			case "wrong recipient":
				b.SubjectID = "other"
				w = sourceWriter(b)
			case "legacy mismatch":
				w.bindings.subjects[b.ID] = []domain.Subject{{Type: sourceActor.Type, ID: "other"}}
			case "too many subjects":
				w.bindings.subjects[b.ID] = make([]domain.Subject, 33)
			case "invalid subject":
				w.bindings.subjects[b.ID] = []domain.Subject{sourceActor, {Type: "invalid", ID: "other"}}
			case "invalid binding":
				b.GrantedRelation = "system_viewer"
				w = sourceWriter(b)
			case "zero time":
				w.at = time.Time{}
			}
			requireSourceFailure(t, w, ErrBindingSourceInvalid)
		})
	}
}

func TestCollectBindingsSeedForm(t *testing.T) {
	b := sourceBinding("seed")
	b.RoleID = ""
	b.GrantedRelation = "system_viewer"
	b.System = true
	w := sourceWriter(b)
	out, err := CollectBindings(context.Background(), w, sourceActor)
	if err != nil || len(out) != 1 || out[0].Role != nil || out[0].Binding.GrantedRelation != b.GrantedRelation || w.roles.calls != 0 {
		t.Fatalf("out=%v err=%v", out, err)
	}
}

func TestCollectBindingsLegacyPairNeedNotBeFirstOnRead(t *testing.T) {
	b := sourceBinding("legacy-order")
	w := sourceWriter(b)
	other := domain.Subject{Type: domain.SubjectTypeUser, ID: "other"}
	w.bindings.subjects[b.ID] = []domain.Subject{other, sourceActor}
	out, err := CollectBindings(context.Background(), w, sourceActor)
	if err != nil || len(out) != 1 || !reflect.DeepEqual(out[0].Binding.Subjects, []domain.Subject{other, sourceActor}) || out[0].Recipient != sourceActor {
		t.Fatalf("DB-допустимый порядок не должен менять носитель: out=%v err=%v", out, err)
	}
}

func TestCollectBindingsAtomicFailures(t *testing.T) {
	boom := errors.New("backend failure")
	for _, phase := range []string{"groups", "binding second page", "subjects", "versions", "role"} {
		t.Run(phase, func(t *testing.T) {
			b := sourceBinding("b")
			w := sourceWriter(b)
			switch phase {
			case "groups":
				w.groups.list = func(group.ListFilter) ([]domain.Group, string, error) { return nil, "", boom }
			case "binding second page":
				w.bindings.list = func(_ domain.Subject, p access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
					if p.PageToken == "" {
						return []domain.AccessBinding{b}, "next", nil
					}
					return nil, "", boom
				}
			case "subjects":
				w.bindings.subjectErr = boom
			case "versions":
				w.versionErr = boom
			case "role":
				w.roles.err = boom
			}
			requireSourceFailure(t, w, boom)
		})
	}
}

func TestCollectBindingsTokenCycleAndResourceBound(t *testing.T) {
	for _, phase := range []string{"group cycle", "binding cycle", "resource bound"} {
		t.Run(phase, func(t *testing.T) {
			w := sourceWriter()
			if phase == "binding cycle" {
				w.bindings.list = func(_ domain.Subject, p access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
					if p.PageToken == "a" {
						return nil, "b", nil
					}
					return nil, "a", nil
				}
			} else {
				n := 0
				w.groups.list = func(f group.ListFilter) ([]domain.Group, string, error) {
					if phase == "resource bound" {
						n++
						return nil, time.Unix(int64(n), 0).String(), nil
					}
					if f.PageToken == "a" {
						return nil, "b", nil
					}
					return nil, "a", nil
				}
			}
			want := ErrBindingSourceInvalid
			if phase == "resource bound" {
				want = ErrBindingSourceLimit
			}
			requireSourceFailure(t, w, want)
		})
	}
}

func TestCollectBindingsActorValidation(t *testing.T) {
	for _, actor := range []domain.Subject{{}, {Type: domain.SubjectTypeGroup, ID: "g"}, {Type: domain.SubjectTypeUser, ID: "*"}, {Type: domain.SubjectTypeServiceAccount, ID: ""}} {
		out, err := CollectBindings(context.Background(), sourceWriter(), actor)
		if !errors.Is(err, ErrBindingSourceInvalid) || out != nil {
			t.Fatalf("actor=%v out=%v err=%v", actor, out, err)
		}
	}
	actor := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sa"}
	w := sourceWriter()
	w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		if s != actor {
			t.Fatalf("subject=%v", s)
		}
		return nil, "", nil
	}
	if _, err := CollectBindings(context.Background(), w, actor); err != nil {
		t.Fatal(err)
	}
}

func TestCollectBindingsBatchesAndLateFailure(t *testing.T) {
	bs := make([]domain.AccessBinding, bindingPageSize+1)
	for i := range bs {
		bs[i] = sourceBinding(fmt.Sprintf("b%03d", i))
	}
	w := sourceWriter(bs...)
	out, err := CollectBindings(context.Background(), w, sourceActor)
	if err != nil || len(out) != len(bs) || w.versionCalls != 2 || w.bindings.subjectCalls != 2 || w.roles.calls != 1 {
		t.Fatalf("out=%d err=%v version calls=%d subject calls=%d role calls=%d", len(out), err, w.versionCalls, w.bindings.subjectCalls, w.roles.calls)
	}
	// Ошибка поздней роли отбрасывает даже уже собранный первый результат.
	bs[1].RoleID = "broken-role"
	w = sourceWriter(bs[:2]...)
	boom := errors.New("late role failure")
	w.roles.err = boom
	w.roles.errOn = "broken-role"
	requireSourceFailure(t, w, boom)
	if w.roles.calls != 2 {
		t.Fatal("late role failure did not follow first successful role")
	}
}
