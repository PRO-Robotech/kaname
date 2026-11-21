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

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/group"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

// Настоящий compiler проверяет прямые типизированные декларации и creator-arm.
const bindingEffectModel = `model
  schema 1.1
type user
type service_account
type group
  relations
    define member: [user, service_account]
type account
  relations
    define viewer: [user, service_account, group#member]
    define v_get: [user, service_account, group#member] or viewer
    define service_account_creator: [service_account]
type iam_service_account
  relations
    define viewer: [user, service_account, group#member]
    define v_get: [user, service_account, group#member] or viewer
`

func bindingEffectCompiler(t *testing.T) *granteffect.Compiler {
	t.Helper()
	c, err := granteffect.New(bindingEffectModel, catalog.Halves{Live: catalog.Rows{
		Modules: []string{"iam"},
		Resources: []catalog.ResourceRow{
			{Module: "iam", Resource: "account", ObjectType: "account"},
			{Module: "iam", Resource: "serviceAccount", ObjectType: "iam_service_account"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "iam", Resource: "account", Verb: "get", PerObject: true},
			{Module: "iam", Resource: "serviceAccount", Verb: "get", PerObject: true},
			{Module: "iam", Resource: "serviceAccount", Verb: "create", ContainerParent: "account", ContainerRelation: "service_account_creator"},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

type effectRoles struct {
	role.ReaderIface
	value domain.Role
}

func (r effectRoles) Get(context.Context, domain.RoleID) (domain.Role, error) { return r.value, nil }

type effectWriter struct {
	*bindingWriter
	role domain.Role
}

func (w effectWriter) Roles() role.ReaderIface { return effectRoles{value: w.role} }

var effectSA = domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sa-a"}
var effectGroup = domain.Subject{Type: domain.SubjectTypeGroup, ID: "group-a"}

func effectFixture(t *testing.T, actor domain.Subject, subjects []domain.Subject, rule domain.Rule) (effectWriter, domain.AccessBinding) {
	t.Helper()
	b := sourceBinding("effect-binding")
	b.SubjectType, b.SubjectID = subjects[0].Type, subjects[0].ID
	b.ResourceType, b.ResourceID = "account", "acc-a"
	w := sourceWriter(b)
	w.bindings.subjects[b.ID] = subjects
	w.groups.list = func(f group.ListFilter) ([]domain.Group, string, error) {
		if f.Member == nil || *f.Member != actor {
			t.Fatal("потерян типизированный actor в фильтре членства")
		}
		return []domain.Group{{ID: domain.GroupID(effectGroup.ID)}}, "", nil
	}
	w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		for _, recipient := range subjects {
			if s == recipient {
				return []domain.AccessBinding{b}, "", nil
			}
		}
		return nil, "", nil
	}
	return effectWriter{bindingWriter: w, role: domain.Role{ID: b.RoleID, Rules: domain.Rules{rule}}}, b
}
func effectRule(creator bool) domain.Rule {
	return domain.Rule{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}, CreatedBySubject: creator}
}
func collectEffects(t *testing.T, w effectWriter, actor domain.Subject) BindingEffects {
	t.Helper()
	out, err := CollectAndCompileBindings(context.Background(), w, bindingEffectCompiler(t), actor)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
func exactCreators(s granteffect.Set) []domain.Subject {
	var out []domain.Subject
	for _, effect := range s.Effects() {
		for _, constraint := range effect.Constraints {
			if constraint.Region.Creator.Kind == grantcoverage.ExactCreator {
				out = append(out, constraint.Region.Creator.Subject)
			}
		}
	}
	return out
}
func hasContainer(s granteffect.Set) bool {
	for _, effect := range s.Effects() {
		if effect.Provenance.Primitive == "container" {
			return true
		}
	}
	return false
}

func TestCollectAndCompileBindingsGroupPreservesOriginalRecipientAndFullSubjects(t *testing.T) {
	other := domain.Subject{Type: domain.SubjectTypeUser, ID: "other"}
	subjects := []domain.Subject{effectGroup, other}
	w, _ := effectFixture(t, effectSA, subjects, effectRule(false))
	out := collectEffects(t, w, effectSA)
	if len(out.Bindings) != 1 || out.Bindings[0].Source.Recipient != effectGroup || !reflect.DeepEqual(out.Bindings[0].Source.Binding.Subjects, subjects) {
		t.Fatalf("потерян групповой носитель или полный набор: %+v", out.Bindings)
	}
	if !out.Effects.Complete() || len(out.Effects.Effects()) == 0 {
		t.Fatalf("обычная группа не скомпилирована: %+v", out.Effects.Obligations())
	}
}

func TestCollectAndCompileBindingsGroupCreatorDoesNotBecomeActorCreator(t *testing.T) {
	w, _ := effectFixture(t, effectSA, []domain.Subject{effectGroup}, effectRule(true))
	out := collectEffects(t, w, effectSA)
	if out.Effects.Complete() || len(out.Effects.Obligations()) == 0 || len(exactCreators(out.Effects)) != 0 {
		t.Fatalf("группа получила creator учётки: effects=%+v obligations=%+v", out.Effects.Effects(), out.Effects.Obligations())
	}
}

func TestCollectAndCompileBindingsGroupDoesNotGainServiceAccountContainerGrant(t *testing.T) {
	rule := effectRule(false)
	rule.Verbs = []string{"create"}
	w, _ := effectFixture(t, effectSA, []domain.Subject{effectGroup}, rule)
	out := collectEffects(t, w, effectSA)
	if hasContainer(out.Effects) {
		t.Fatal("группа получила контейнерный grant служебной учётки")
	}
	// Контроль: тот же настоящий compiler выдаёт контейнерный эффект прямой SA.
	w, _ = effectFixture(t, effectSA, []domain.Subject{effectSA}, rule)
	if !hasContainer(collectEffects(t, w, effectSA).Effects) {
		t.Fatal("положительный контроль контейнерного producer не сработал")
	}
}

func TestCollectAndCompileBindingsDirectCreatorRetainsTypedIdentity(t *testing.T) {
	w, _ := effectFixture(t, effectSA, []domain.Subject{effectSA}, effectRule(true))
	out := collectEffects(t, w, effectSA)
	creators := exactCreators(out.Effects)
	if !out.Effects.Complete() || len(creators) == 0 {
		t.Fatalf("нет creator-эффекта SA-A: %+v", out.Effects.Obligations())
	}
	for _, creator := range creators {
		if creator != effectSA {
			t.Fatalf("чужой creator: %+v", creator)
		}
	}
}

func TestCollectAndCompileBindingsRejectsMismatchedDirectActor(t *testing.T) {
	for _, actor := range []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: "sa-b"}, {Type: domain.SubjectTypeUser, ID: effectSA.ID}} {
		t.Run(string(actor.Type)+string(actor.ID), func(t *testing.T) {
			w, b := effectFixture(t, actor, []domain.Subject{effectSA}, effectRule(true))
			// Повреждённый reader пытается вернуть SA-A по запросу другого actor.
			w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
				if s == actor {
					return []domain.AccessBinding{b}, "", nil
				}
				return nil, "", nil
			}
			out, err := CollectAndCompileBindings(context.Background(), w, bindingEffectCompiler(t), actor)
			if !errors.Is(err, ErrBindingSourceInvalid) || len(out.Bindings) != 0 || len(out.Effects.Effects()) != 0 {
				t.Fatalf("подмена actor принята: %+v %v", out, err)
			}
		})
	}
}

func TestCollectAndCompileBindingsSeparateCarriersAndUnionRetainsObligations(t *testing.T) {
	w, _ := effectFixture(t, effectSA, []domain.Subject{effectGroup, effectSA}, effectRule(true))
	out := collectEffects(t, w, effectSA)
	if len(out.Bindings) != 2 {
		t.Fatalf("носителей: %d", len(out.Bindings))
	}
	var complete, incomplete int
	for _, carrier := range out.Bindings {
		if carrier.Source.Recipient == effectSA {
			if !carrier.Effects.Complete() || len(exactCreators(carrier.Effects)) == 0 {
				t.Fatal("прямая SA потеряла creator")
			}
			complete++
		} else if carrier.Source.Recipient == effectGroup {
			if carrier.Effects.Complete() || len(exactCreators(carrier.Effects)) != 0 {
				t.Fatal("групповой носитель приобрёл creator")
			}
			incomplete++
		} else {
			t.Fatal("неожиданный носитель")
		}
	}
	if complete != 1 || incomplete != 1 || out.Effects.Complete() || len(out.Effects.Obligations()) == 0 || len(exactCreators(out.Effects)) == 0 {
		t.Fatalf("union потерял эффект или обязательство: %+v", out.Effects.Obligations())
	}
}

func TestCollectAndCompileBindingsSeedUsesActualTypedRelationAndScope(t *testing.T) {
	for _, actor := range []domain.Subject{effectSA, sourceActor} {
		t.Run(string(actor.Type), func(t *testing.T) {
			w, b := effectFixture(t, actor, []domain.Subject{actor}, effectRule(false))
			b.RoleID, b.GrantedRelation, b.System = "", "service_account_creator", true
			w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
				if s == actor {
					return []domain.AccessBinding{b}, "", nil
				}
				return nil, "", nil
			}
			out := collectEffects(t, w, actor)
			if len(out.Bindings) != 1 || out.Bindings[0].Source.Role != nil {
				t.Fatal("потеряна seed-форма")
			}
			if actor.Type == domain.SubjectTypeUser {
				if out.Effects.Complete() || len(out.Effects.Obligations()) == 0 {
					t.Fatal("typed relation приняло user")
				}
				return
			}
			if !out.Effects.Complete() || len(out.Effects.Effects()) == 0 {
				t.Fatalf("typed SA seed не скомпилирован: %+v", out.Effects.Obligations())
			}
			for _, effect := range out.Effects.Effects() {
				if effect.Provenance.Primitive != "direct_fact" {
					t.Fatal("seed компилирован как роль")
				}
				for _, constraint := range effect.Constraints {
					if constraint.Type != "account" || !reflect.DeepEqual(constraint.Region.Objects.IDs, []string{"acc-a"}) {
						t.Fatalf("подмена seed scope: %+v", constraint)
					}
				}
			}
		})
	}
}

func TestCollectAndCompileBindingsNilCompilerAndEmptySource(t *testing.T) {
	if _, err := CollectAndCompileBindings(context.Background(), nil, nil, effectSA); !errors.Is(err, ErrBindingSourceInvalid) {
		t.Fatalf("nil compiler: %v", err)
	}
	out, err := CollectAndCompileBindings(context.Background(), sourceWriter(), bindingEffectCompiler(t), sourceActor)
	if err != nil || len(out.Bindings) != 0 || out.Effects.Complete() {
		t.Fatalf("пустой источник получил полноту: %+v %v", out, err)
	}
}

func TestCollectAndCompileBindingsDoesNotReadUnconfirmedGroup(t *testing.T) {
	w, _ := effectFixture(t, effectSA, []domain.Subject{effectGroup}, effectRule(false))
	w.groups.list = func(group.ListFilter) ([]domain.Group, string, error) { return nil, "", nil }
	w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		if s != effectSA {
			t.Fatalf("прочитан неподтверждённый групповой носитель: %+v", s)
		}
		return nil, "", nil
	}
	out := collectEffects(t, w, effectSA)
	if len(out.Bindings) != 0 || len(out.Effects.Effects()) != 0 {
		t.Fatal("выдан эффект неподтверждённого членства")
	}
}

func TestCollectAndCompileBindingsRejectsAmbiguousScope(t *testing.T) {
	w, b := effectFixture(t, effectSA, []domain.Subject{effectSA}, effectRule(false))
	b.ResourceType, b.ResourceID = "service_account", "sa-target"
	w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		if s == effectSA {
			return []domain.AccessBinding{b}, "", nil
		}
		return nil, "", nil
	}
	out, err := CollectAndCompileBindings(context.Background(), w, bindingEffectCompiler(t), effectSA)
	if !errors.Is(err, ErrBindingSourceInvalid) || len(out.Bindings) != 0 || len(out.Effects.Effects()) != 0 {
		t.Fatalf("необластной тип принят: %+v %v", out, err)
	}
}

// Конечная цель должна дойти до настоящего компилятора: иначе право на один
// объект молча стало бы правом на любой объект той же области.
func TestCollectAndCompileBindingsFiniteOrdinaryTargetDoesNotCoverOtherObject(t *testing.T) {
	w, b := effectFixture(t, effectSA, []domain.Subject{effectSA}, effectRule(false))
	b.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.serviceAccount", ID: "sa-named"}}}
	w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		if s == effectSA {
			return []domain.AccessBinding{b}, "", nil
		}
		return nil, "", nil
	}
	c := bindingEffectCompiler(t)
	out, err := CollectAndCompileBindings(context.Background(), w, c, effectSA)
	if err != nil || !out.Effects.Complete() || len(out.Effects.Effects()) == 0 {
		t.Fatalf("конечная выдача не скомпилирована: %+v %v", out.Effects.Obligations(), err)
	}
	if len(out.Bindings) != 1 || !reflect.DeepEqual(out.Bindings[0].Source.Binding.Target, b.Target) {
		t.Fatal("потеряна исходная конечная цель")
	}
	for _, tc := range []struct {
		id   string
		want bool
	}{{"sa-named", true}, {"sa-other", false}} {
		rule := effectRule(false)
		rule.ResourceNames = []string{tc.id}
		wanted := c.Compile(granteffect.Binding{SourceID: "wanted-" + tc.id, Role: domain.Role{ID: "wanted-role", Rules: domain.Rules{rule}}, Scope: domain.ScopeAnchor{Type: "account", ID: "acc-a"}, Target: domain.AccessTarget{AllInScope: true}, Recipient: effectSA, Subjects: []domain.Subject{effectSA}})
		if !wanted.Complete() || len(wanted.Effects()) == 0 {
			t.Fatalf("контроль %s не скомпилирован: %+v", tc.id, wanted.Obligations())
		}
		got := granteffect.Prove(out.Effects, wanted)
		if (got.Status == grantcoverage.Proved) != tc.want {
			t.Fatalf("покрытие %s: %+v, ожидается %v", tc.id, got, tc.want)
		}
	}
}

func TestCollectAndCompileBindingsFiniteSeedRejectsWithoutPartialResult(t *testing.T) {
	w, good := effectFixture(t, effectSA, []domain.Subject{effectSA}, effectRule(false))
	bad := good
	bad.ID = "finite-seed"
	bad.RoleID = ""
	bad.GrantedRelation = "service_account_creator"
	bad.System = true
	bad.Target = domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "iam.serviceAccount", ID: "sa-named"}}}
	if err := bad.Validate(); err != nil {
		t.Fatalf("цель должна быть допустимой формой домена: %v", err)
	}
	w.versions[bad.ID] = 0
	w.bindings.subjects[bad.ID] = []domain.Subject{effectSA}
	w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		if s == effectSA {
			return []domain.AccessBinding{good, bad}, "", nil
		}
		return nil, "", nil
	}
	out, err := CollectAndCompileBindings(context.Background(), w, bindingEffectCompiler(t), effectSA)
	if !errors.Is(err, ErrBindingSourceInvalid) || len(out.Bindings) != 0 || len(out.Effects.Effects()) != 0 || out.Effects.Complete() {
		t.Fatalf("конечный seed расширен до области или оставлен частичный итог: %+v %v", out, err)
	}
}

func TestCollectAndCompileBindingsSeedRejectsNonScopeObject(t *testing.T) {
	w, b := effectFixture(t, effectSA, []domain.Subject{effectSA}, effectRule(false))
	b.RoleID = ""
	b.GrantedRelation = "viewer"
	b.System = true
	b.ResourceType = "service_account"
	b.ResourceID = "sa-target"
	// Вокабуляр домена допускает только три якоря области. Некорректный
	// системный источник должен быть отвергнут и на входе адаптера.
	if err := b.Validate(); err == nil {
		t.Fatal("домен неожиданно допустил пообъектный тип как якорь")
	}
	w.bindings.list = func(s domain.Subject, _ access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		if s == effectSA {
			return []domain.AccessBinding{b}, "", nil
		}
		return nil, "", nil
	}
	out, err := CollectAndCompileBindings(context.Background(), w, bindingEffectCompiler(t), effectSA)
	if !errors.Is(err, ErrBindingSourceInvalid) || len(out.Bindings) != 0 || len(out.Effects.Effects()) != 0 || out.Effects.Complete() {
		t.Fatalf("необластной seed принят: %+v %v", out, err)
	}
}

// Много допустимых выдач укладываются в сбор строк, но не в общий эффект.
func TestCollectAndCompileBindingsGlobalBudgetReturnsZero(t *testing.T) {
	w, base := effectFixture(t, effectSA, []domain.Subject{effectSA}, effectRule(false))
	total := granteffect.MaxEffects + 1
	bindings := make([]domain.AccessBinding, total)
	for i := range bindings {
		b := base
		b.ID = domain.AccessBindingID(fmt.Sprintf("budget-%d", i))
		bindings[i] = b
		w.versions[b.ID] = 0
		w.bindings.subjects[b.ID] = []domain.Subject{effectSA}
	}
	w.groups.list = func(group.ListFilter) ([]domain.Group, string, error) { return nil, "", nil }
	w.bindings.list = func(s domain.Subject, f access_binding.PageFilter) ([]domain.AccessBinding, string, error) {
		if s != effectSA {
			t.Fatal("чужой получатель")
		}
		start := 0
		if f.PageToken != "" {
			var err error
			start, err = strconv.Atoi(f.PageToken)
			if err != nil {
				t.Fatal(err)
			}
		}
		end := start + bindingPageSize
		if end > total {
			end = total
		}
		next := ""
		if end < total {
			next = strconv.Itoa(end)
		}
		return bindings[start:end], next, nil
	}
	got, err := CollectAndCompileBindings(context.Background(), w, bindingEffectCompiler(t), effectSA)
	if !errors.Is(err, ErrBindingSourceLimit) || !errors.Is(err, granteffect.ErrUnionLimit) || !reflect.DeepEqual(got, BindingEffects{}) {
		t.Fatalf("общий бюджет оставил результат: %+v %v", got, err)
	}
}
