// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// unregister_race_world_integration_test.go — группа G приёмки
// docs/engineering/acceptance/unregistration-revokes-its-grants.md (отпечаток
// 0743cd4f3f4ac1b9519870bce93475a339c7729f202ee6cc1ad5386a87bd97b4, kaname#963):
// URG-24…URG-28.
//
// Гонка читается от момента приёма (Р8): выдача (роль) ПРИНЯТА, пока ключ
// зарегистрирован, и ЗАПИСАНА после снятия. Окно задевается не случайностью, а
// точкой удержания: обёртка порта `Repo` use-case держит открытие транзакции
// записи воркера операции (`create.go`, `operations.Run`) до сигнала пробы. В
// чётных итерациях воркер отпускается только после того, как снятие вернуло OK,
// поэтому запись заведомо идёт после фиксации снятия; в нечётных снятие идёт
// параллельно без удержания. Каждая итерация — на своём ключе.

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
)

// urRaceIterations — число итераций каждого конкурентного сценария (приёмка: 50).
const urRaceIterations = 50

// holdingRepo — порт `Repo`, держащий открытие транзакции записи, пока проба не
// отпустит. Держит только тогда, когда заряжен (`arm`), и ровно один вызов.
type holdingRepo struct {
	kanamerepo.Repository
	mu      sync.Mutex
	gate    chan struct{} // nil — не держать
	reached chan struct{}
}

func (h *holdingRepo) arm() (reached <-chan struct{}, release func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.gate = make(chan struct{})
	h.reached = make(chan struct{})
	gate := h.gate
	return h.reached, func() { close(gate) }
}

func (h *holdingRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	h.mu.Lock()
	gate, reached := h.gate, h.reached
	h.gate, h.reached = nil, nil
	h.mu.Unlock()
	if gate != nil {
		close(reached)
		<-gate
	}
	return h.Repository.Writer(ctx)
}

// raceKey — ключ итерации: реестр prj-A, зарегистрированный перед итерацией.
func raceKey(base, i int) string { return fmt.Sprintf("reg%017d", base+i) }

// holdingCreate — обработчик выдач, чей use-case создания держит воркер на `hold`.
func (w *urxWorld) holdingCreate(hold *holdingRepo) *accessbindingapp.Handler {
	create := accessbindingapp.NewCreateAccessBindingUseCase(hold, w.ops, pcrFacts{w.pcrWorld}).
		WithRelationStore(w.door, nil).
		WithReconciler(w.rec).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool))
	get := accessbindingapp.NewGetAccessBindingUseCase(w.repo).WithRelationStore(w.door, nil).WithRelationQueries(w.door)
	return accessbindingapp.NewHandler(create, nil, get, nil, nil, nil, nil)
}

// URG-24 · выдача, принятая до снятия и записанная после, не остаётся живой.
func TestURG24_GrantAcceptedBeforeUnregisterWrittenAfterNotLive(t *testing.T) {
	w := newURXWorld(t)
	hold := &holdingRepo{Repository: w.repo}
	h := w.holdingCreate(hold)

	var refused, revoked, live, writtenAfter int
	for i := 0; i < urRaceIterations; i++ {
		key := raceKey(1000, i)
		w.registerRegistry(key)
		held := i%2 == 0
		var reached <-chan struct{}
		var release func()
		if held {
			reached, release = hold.arm()
		}
		op, err := h.Create(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), w.rolRegGet, urTarget(key)))
		require.NoErrorf(t, err, "URG-24 #%d: приём выдачи (ключ зарегистрирован)", i)
		var md iamv1.CreateAccessBindingMetadata
		require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
		if held {
			<-reached
			w.withdraw(w.ctx, key)
			writtenAfter++
			release()
		} else {
			require.NoErrorf(t, w.withdrawErr(w.ctx, key), "URG-24 #%d: снятие", i)
		}
		done := awaitOp(t, w.ctx, w.ops, op.GetId())
		var st string
		rowErr := w.pool.QueryRow(w.ctx, `SELECT status FROM kaname.access_bindings WHERE id = $1`, md.GetAccessBindingId()).Scan(&st)
		switch {
		case done.Error != nil:
			assert.Equalf(t, int32(codes.FailedPrecondition), done.Error.Code, "URG-24 #%d: код отказа", i)
			assert.Equalf(t, fmt.Sprintf("target resource %s %s was unregistered before the access binding was written", pcrRegTgt, key),
				done.Error.Message, "URG-24 #%d: текст Т1", i)
			assert.Errorf(t, rowErr, "URG-24 #%d: отказ создания оставил строку выдачи", i)
			refused++
		default:
			require.NoErrorf(t, rowErr, "URG-24 #%d: строки выдачи нет при успешной операции", i)
			b := w.get(md.GetAccessBindingId())
			if b.GetStatus() == iamv1.AccessBinding_REVOKED &&
				b.GetRevocationReason() == iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED {
				revoked++
			} else {
				live++
				t.Errorf("URG-24 #%d: выдача на снятый ключ %s жива: status=%s reason=%s", i, key, b.GetStatus(), b.GetRevocationReason())
			}
		}
	}
	t.Logf("URG-24: итераций %d · запись после снятия %d · отказ Т1 %d · отзыв %d · живых %d",
		urRaceIterations, writtenAfter, refused, revoked, live)
	assert.Zero(t, live, "URG-24: живые выдачи на снятый ключ")
	assert.GreaterOrEqual(t, writtenAfter, 1, "URG-24: окно гонки не задето ни разу")
}

// URG-25 · близнец 24: выдача, принятая после снятия, — выдача на свободный ключ.
func TestURG25_GrantAcceptedAfterUnregisterIsOnFreeKey(t *testing.T) {
	w := newURXWorld(t)
	w.withdrawX()

	id := w.grantTo(w.usrD, w.rolRegGet, urTarget(pcrX), false, "URG-25: выдача на свободный X")
	assert.Equal(t, iamv1.AccessBinding_ACTIVE, w.get(id).GetStatus(), "URG-25: выдача не ACTIVE")
	w.reRegisterX(w.usrC)
	w.pollAsk(w.usr(w.usrD), "v_get", pcrRegType, pcrX, true, "URG-25: после регистрации usr-D не читает X")
}

// roleHandler — обработчик ролей, чьи use-case'ы создания и правки держат воркер на `hold`.
func (w *urxWorld) roleHandler(hold *holdingRepo) *roleapp.Handler {
	src := catalog.Fixed{F: w.facts}
	create := roleapp.NewCreateRoleUseCase(hold, w.ops, src).WithRelationStore(w.door, nil).WithObjectReconciler(w.rec).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool))
	update := roleapp.NewUpdateRoleUseCase(hold, w.ops, src).
		WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool)).
		WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).
		WithMembershipFanout(accessbindingapp.NewRoleMembershipFanout(w.repo, w.rec))
	return roleapp.NewHandler(create, update, nil, nil, nil)
}

func protoNamesRule(ids ...string) *iamv1.Rule {
	return &iamv1.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}, ResourceNames: ids}
}

// roleNames — все названия правил роли строкой хранилища (nil — роли нет).
func (w *urxWorld) roleNames(id domain.RoleID) ([]string, bool) {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() { _ = rd.Rollback(w.ctx) }()
	r, err := rd.Roles().Get(w.ctx, id)
	if err != nil {
		return nil, false
	}
	var out []string
	for _, rule := range r.Rules {
		out = append(out, rule.ResourceNames...)
	}
	return out, true
}

// URG-26 · роль, принятая до снятия и записанная после, не называет снятый ключ.
func TestURG26_RoleAcceptedBeforeUnregisterWrittenAfterDoesNotNameKey(t *testing.T) {
	w := newURXWorld(t)
	hold := &holdingRepo{Repository: w.repo}
	h := w.roleHandler(hold)
	updRole := w.seedRole("rol_reg_names_y", domain.Rules{namesRule(pcrY)})
	t2 := func(i int, key string) string {
		return fmt.Sprintf("rules[%d].resourceNames: resource %s was unregistered before the role was written", i, key)
	}

	var refused, narrowed, naming, writtenAfter int
	judge := func(form string, i int, key string, roleID domain.RoleID, done *operations.Operation) {
		t.Helper()
		if done.Error != nil {
			assert.Equalf(t, int32(codes.FailedPrecondition), done.Error.Code, "URG-26 %s #%d: код отказа", form, i)
			assert.Equalf(t, t2(0, key), done.Error.Message, "URG-26 %s #%d: текст Т2", form, i)
			refused++
			return
		}
		names, ok := w.roleNames(roleID)
		require.Truef(t, ok, "URG-26 %s #%d: роли нет при успешной операции", form, i)
		for _, n := range names {
			if n == key {
				naming++
				t.Errorf("URG-26 %s #%d: роль %s называет снятый ключ %s", form, i, roleID, key)
				return
			}
		}
		narrowed++
	}
	for i := 0; i < urRaceIterations; i++ {
		// Правка роли.
		key := raceKey(2000, i)
		w.registerRegistry(key)
		held := i%2 == 0
		var reached <-chan struct{}
		var release func()
		if held {
			reached, release = hold.arm()
		}
		op, err := h.Update(asUser(w.ctx, w.usrA), &iamv1.UpdateRoleRequest{
			RoleId: string(updRole), UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"rules"}},
			Rules: []*iamv1.Rule{protoNamesRule(key, pcrY)},
		})
		require.NoErrorf(t, err, "URG-26 update #%d: приём правки", i)
		if held {
			<-reached
			w.withdraw(w.ctx, key)
			writtenAfter++
			release()
		} else {
			require.NoErrorf(t, w.withdrawErr(w.ctx, key), "URG-26 update #%d: снятие", i)
		}
		judge("update", i, key, updRole, awaitOp(t, w.ctx, w.ops, op.GetId()))

		// Создание роли.
		ckey := raceKey(3000, i)
		w.registerRegistry(ckey)
		if held {
			reached, release = hold.arm()
		}
		cop, err := h.Create(asUser(w.ctx, w.usrA), &iamv1.CreateRoleRequest{
			AccountId: string(w.accA), Name: fmt.Sprintf("urg26_create_%d", i), Description: "URG-26",
			Rules: []*iamv1.Rule{protoNamesRule(ckey, pcrY)},
		})
		require.NoErrorf(t, err, "URG-26 create #%d: приём создания", i)
		if held {
			<-reached
			w.withdraw(w.ctx, ckey)
			writtenAfter++
			release()
		} else {
			require.NoErrorf(t, w.withdrawErr(w.ctx, ckey), "URG-26 create #%d: снятие", i)
		}
		cdone := awaitOp(t, w.ctx, w.ops, cop.GetId())
		var md iamv1.CreateRoleMetadata
		require.NoError(t, cop.GetMetadata().UnmarshalTo(&md))
		judge("create", i, ckey, domain.RoleID(md.GetRoleId()), cdone)
	}
	t.Logf("URG-26: итераций %d×2 · запись после снятия %d · отказ Т2 %d · сужено %d · называют снятый ключ %d",
		urRaceIterations, writtenAfter, refused, narrowed, naming)
	assert.Zero(t, naming, "URG-26: роли, называющие снятый ключ")
	assert.GreaterOrEqual(t, writtenAfter, 1, "URG-26: окно гонки не задето")
}

// URG-27 · отзыв глаголом и снятие регистрации: ровно один отзыв.
func TestURG27_RevokeVerbAndUnregistrationRevokeOnce(t *testing.T) {
	w := newURXWorld(t)
	var byVerb, byUnreg int
	for i := 0; i < urRaceIterations; i++ {
		key := raceKey(4000, i)
		w.registerRegistry(key)
		id := w.grantTo(w.usrD, w.rolRegGet, urTarget(key), false, fmt.Sprintf("URG-27 #%d: выдача", i))

		var wg sync.WaitGroup
		var opID string
		var revErr, unregErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			op, err := w.abx.Revoke(asUser(w.ctx, w.usrA), &iamv1.RevokeAccessBindingRequest{AccessBindingId: id})
			revErr = err
			if err == nil {
				opID = op.GetId()
			}
		}()
		go func() { defer wg.Done(); unregErr = w.withdrawErr(w.ctx, key) }()
		wg.Wait()
		require.NoErrorf(t, unregErr, "URG-27 #%d: снятие", i)

		var verbErr *operations.Operation
		if revErr == nil {
			verbErr = awaitOp(t, w.ctx, w.ops, opID)
		}
		b := w.get(id)
		require.Equalf(t, iamv1.AccessBinding_REVOKED, b.GetStatus(), "URG-27 #%d: выдача не REVOKED", i)
		switch b.GetRevocationReason() {
		case iamv1.AccessBinding_REVOCATION_REASON_REVOKE:
			assert.Equalf(t, string(w.usrA), b.GetRevokedByUserId(), "URG-27 #%d: revokedBy глагола", i)
			byVerb++
		case iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED:
			assert.Emptyf(t, b.GetRevokedByUserId(), "URG-27 #%d: revokedBy снятия", i)
			if verbErr != nil {
				require.NotNilf(t, verbErr.Error, "URG-27 #%d: отзыв глаголом после снятия завершился без ошибки", i)
				assert.Equalf(t, int32(codes.FailedPrecondition), verbErr.Error.Code, "URG-27 #%d: код", i)
				assert.Equalf(t, fmt.Sprintf("access binding %s is not active (status REVOKED); cannot revoke", id),
					verbErr.Error.Message, "URG-27 #%d: текст", i)
			}
			byUnreg++
		default:
			t.Errorf("URG-27 #%d: причина отзыва %s", i, b.GetRevocationReason())
		}
		audits := w.auditCount("iam.access_binding.revoked", "binding_id", id) +
			w.auditCount("iam.access_binding.resource_unregistered_revoked", "binding_id", id)
		assert.Equalf(t, 1, audits, "URG-27 #%d: строк аудита отзыва", i)
	}
	t.Logf("URG-27: итераций %d · отзыв глаголом %d · отзыв снятием %d", urRaceIterations, byVerb, byUnreg)
}

// URG-28 · два снятия одной цели параллельно.
func TestURG28_TwoParallelUnregistrationsOfOneTarget(t *testing.T) {
	w := newURXWorld(t)
	var revoked int
	for i := 0; i < urRaceIterations; i++ {
		kx, ky := raceKey(5000, i), raceKey(6000, i)
		w.registerRegistry(kx)
		w.registerRegistry(ky)
		id := w.grantTo(w.usrD, w.rolRegGet, urTarget(kx, ky), false, fmt.Sprintf("URG-28 #%d: B2", i))

		var wg sync.WaitGroup
		var ex, ey error
		wg.Add(2)
		go func() { defer wg.Done(); ex = w.withdrawErr(w.ctx, kx) }()
		go func() { defer wg.Done(); ey = w.withdrawErr(w.ctx, ky) }()
		wg.Wait()
		require.NoErrorf(t, ex, "URG-28 #%d: снятие X", i)
		require.NoErrorf(t, ey, "URG-28 #%d: снятие Y", i)

		b := w.get(id)
		if b.GetStatus() == iamv1.AccessBinding_REVOKED &&
			b.GetRevocationReason() == iamv1.AccessBinding_REVOCATION_REASON_RESOURCE_UNREGISTERED {
			revoked++
			continue
		}
		t.Errorf("URG-28 #%d: B2 status=%s reason=%s цель=%v", i, b.GetStatus(), b.GetRevocationReason(), targetIDs(b))
	}
	t.Logf("URG-28: итераций %d · отозвано %d", urRaceIterations, revoked)
	assert.Equal(t, urRaceIterations, revoked, "URG-28: не каждая B2 отозвана")
}
