// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// service_account_creator_d_end_integration_test.go — группа D приёмки
// `service-account-creation-is-its-own-right.md` (PRO-Robotech/kaname#1003):
// конец выдачи, повторная выдача, гонки (SAC-30…SAC-35).

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// sac30Given — «Дано» SAC-30/33: G — выдача Bc, sva-iss создал sva-cr1 и
// выпустил ему K1. Отдаёт Bc, sva-cr1 и K1.
func (w *sacWorld) sac30Given(sc string) (bc, cr1, k1 string) {
	w.t.Helper()
	bc, cr1 = w.sac10(sc)
	iss := asSA(w.ctx, w.svaIss)
	untilDoorPasses(w.t, sc+" Дано: sva-iss выпускает K1", func() error {
		o := w.keyIssue(iss, cr1)
		if o.syncErr != nil {
			return o.syncErr
		}
		requireSACDone(w.t, o, sc+" Дано: K1")
		k1 = w.issuedKeyID(o)
		return nil
	})
	return bc, cr1, k1
}

// requireLostBoth — после конца выдачи: права создавать и вести нет, окно двери
// выжидается, затем оба вызова отвергаются; учётка и K1 на месте.
func (w *sacWorld) requireLostBoth(sc, cr1, k1, newName string) {
	w.t.Helper()
	w.pollRelation("service_account:"+w.svaIss, sacCreatorRelation, "account:"+string(w.accA), false,
		sc+": права создавать нет")
	w.pollRelation("service_account:"+w.svaIss, "v_update", sacSAModelType+":"+cr1, false,
		sc+": ведения sva-cr1 нет")
	w.awaitDoorWindow()
	iss := asSA(w.ctx, w.svaIss)
	requireSACDenied(w.t, w.saCreate(iss, string(w.accA), newName), sc+" a: sva-iss Create")
	requireSACDenied(w.t, w.keyIssue(iss, cr1), sc+" b: sva-iss Issue sva-cr1")
	got, err := w.saGet(asUser(w.ctx, w.usrA), cr1)
	require.NoError(w.t, err, sc+": sva-cr1 на месте")
	require.True(w.t, got.GetEnabled(), sc+": sva-cr1 enabled")
	keys, err := w.keyList(asUser(w.ctx, w.usrA), cr1)
	require.NoError(w.t, err, sc+": ключи sva-cr1 от usr-A")
	require.Contains(w.t, keys, k1, sc+": K1 есть")
}

// SAC-30 — отзыв выдачи снимает и создание, и ведение; учётка и ключ остаются.
func TestServiceAccountCreator_SAC30_RevokeTakesCreationAndManagementKeepsAccountAndKey(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-30")
	bc, cr1, k1 := w.sac30Given("SAC-30")
	w.revokeDone(asUser(w.ctx, w.usrA), bc, "SAC-30: usr-A отзывает Bc")
	w.requireLostBoth("SAC-30", cr1, k1, "cr-9")
}

// SAC-31 — повторная выдача возвращает ведение созданных раньше.
func TestServiceAccountCreator_SAC31_RegrantReturnsManagementOfEarlierAccounts(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-31")
	bc, cr1, k1 := w.sac30Given("SAC-31")
	w.revokeDone(asUser(w.ctx, w.usrA), bc, "SAC-31 Дано: отзыв Bc")
	w.requireLostBoth("SAC-31 Дано (SAC-30)", cr1, k1, "cr-9")

	w.grantC("SAC-31: usr-A снова выдаёт G", w.svaIss)
	w.pollRelation("service_account:"+w.svaIss, "v_update", sacSAModelType+":"+cr1, true,
		"SAC-31: ведение sva-cr1 вернулось")
	untilDoorPasses(t, "SAC-31: sva-iss Issue sva-cr1", func() error {
		o := w.keyIssue(asSA(w.ctx, w.svaIss), cr1)
		if o.syncErr != nil {
			return o.syncErr
		}
		requireSACDone(t, o, "SAC-31: выпуск")
		return nil
	})
	require.Equal(t, 2, w.keyCensus(cr1), "SAC-31: ключей у sva-cr1")
}

// SAC-32 — вторая действующая выдача держит создание и ведение.
func TestServiceAccountCreator_SAC32_SecondLiveGrantHoldsCreationAndManagement(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-32")
	bc, cr1 := w.sac10("SAC-32")
	bc2 := w.grantC("SAC-32 Дано: G' (субъекты sva-iss2, sva-iss)", w.svaIss2, w.svaIss)
	w.pollRelation("service_account:"+w.svaIss, sacCreatorRelation, "account:"+string(w.accA), true,
		"SAC-32 контроль")

	// a) отзыв Bc — вторая выдача держит.
	w.revokeDone(asUser(w.ctx, w.usrA), bc, "SAC-32 a: отзыв Bc")
	w.awaitDoorWindow()
	iss := asSA(w.ctx, w.svaIss)
	requireSACDone(t, w.saCreate(iss, string(w.accA), "cr-32"), "SAC-32 a: sva-iss Create")
	requireSACDone(t, w.keyIssue(iss, cr1), "SAC-32 a: sva-iss Issue sva-cr1")
	w.requireRelation("service_account:"+w.svaIss, "v_update", sacSAModelType+":"+cr1, true, "SAC-32 a")
	w.requireRelation("service_account:"+w.svaIss, sacCreatorRelation, "account:"+string(w.accA), true, "SAC-32 a")
	require.Equal(t, iamv1.AccessBinding_REVOKED, w.getBinding(bc).GetStatus(), "SAC-32 a: Bc REVOKED")

	// b) отзыв Bc' — последней выдачи нет.
	w.revokeDone(asUser(w.ctx, w.usrA), bc2, "SAC-32 b: отзыв Bc'")
	w.pollRelation("service_account:"+w.svaIss, sacCreatorRelation, "account:"+string(w.accA), false, "SAC-32 b")
	w.pollRelation("service_account:"+w.svaIss, "v_update", sacSAModelType+":"+cr1, false, "SAC-32 b")
	w.awaitDoorWindow()
	requireSACDenied(t, w.keyIssue(iss, cr1), "SAC-32 b: sva-iss Issue sva-cr1")
	_, err := w.saGet(asUser(w.ctx, w.usrA), cr1)
	require.NoError(t, err, "SAC-32 b: sva-cr1 на месте")
	require.Equal(t, 1, w.keyCensus(cr1), "SAC-32 b: ключ sva-cr1 на месте")
}

// SAC-33 — удаление выдачи и истечение срока снимают создание и ведение.
func TestServiceAccountCreator_SAC33_DeleteAndExpiryTakeCreationAndManagement(t *testing.T) {
	t.Run("a — Delete", func(t *testing.T) {
		w := newSACWorld(t)
		w.requireCreatorRole("SAC-33 a")
		bc, cr1, k1 := w.sac30Given("SAC-33 a")
		w.awaitRemovalRight(w.usrA, bc, "SAC-33 a: право удалить Bc у usr-A")
		w.deleteBindingDone(asUser(w.ctx, w.usrA), bc, "SAC-33 a: usr-A удаляет Bc")
		w.requireLostBoth("SAC-33 a", cr1, k1, "cr-33")
	})
	t.Run("b — истечение", func(t *testing.T) {
		w := newSACWorld(t)
		w.requireCreatorRole("SAC-33 b")
		bc, cr1, k1 := w.sac30Given("SAC-33 b")
		_, err := w.pool.Exec(w.ctx,
			`UPDATE kaname.access_bindings SET expires_at = now() + interval '2 seconds' WHERE id = $1`, bc)
		require.NoError(t, err, "SAC-33 b: срок Bc")
		deadline := time.Now().Add(10 * time.Second)
		for {
			var past bool
			require.NoError(t, w.pool.QueryRow(w.ctx,
				`SELECT expires_at < now() FROM kaname.access_bindings WHERE id = $1`, bc).Scan(&past))
			if past {
				break
			}
			require.Truef(t, time.Now().Before(deadline), "SAC-33 b: срок Bc за 10 с не прошёл")
			time.Sleep(200 * time.Millisecond)
		}
		require.NoError(t, w.rec.ExpireBinding(w.ctx, domain.AccessBindingID(bc)), "SAC-33 b: проход срока")
		w.requireLostBoth("SAC-33 b", cr1, k1, "cr-33")
		got := w.getBinding(bc)
		require.Equal(t, iamv1.AccessBinding_REVOKED, got.GetStatus(), "SAC-33 b: Bc REVOKED")
		require.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_EXPIRED, got.GetRevocationReason(), "SAC-33 b: причина")
	})
}

// sacRace — исход одного раунда гонки.
type sacRace struct {
	created  []string
	refusals int
}

// raceCreates — 16 созданий учёток от `creator` и `other` одновременно за общим
// барьером старта; каждый вызов доводится до `done` либо отказа двери.
func (w *sacWorld) raceCreates(creator, prefix string, other func()) sacRace {
	w.t.Helper()
	const n = 16
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		start = make(chan struct{})
		out   sacRace
		fails []string
	)
	ctx := asSA(w.ctx, creator)
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			o := w.saCreateNoFail(ctx, string(w.accA), fmt.Sprintf("%s-%d", prefix, i))
			mu.Lock()
			defer mu.Unlock()
			switch {
			case o.err == nil && o.id != "":
				out.created = append(out.created, o.id)
			case o.err != nil && sacIsDoorRefusal(o.err):
				out.refusals++
			default:
				fails = append(fails, fmt.Sprintf("%s-%d: %v", prefix, i, o.err))
			}
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		other()
	}()
	close(start)
	wg.Wait()
	require.Emptyf(w.t, fails, "гонка %s: исходов вне «done | permission denied»", prefix)
	return out
}

// sacCreateResult — исход создания в гонке (без require в горутине).
type sacCreateResult struct {
	id  string
	err error
}

// saCreateNoFail — создание учётки через дверь до `done` без остановки пробы:
// require из горутины не останавливает пробу, поэтому исход возвращается.
func (w *sacWorld) saCreateNoFail(ctx context.Context, acc, name string) sacCreateResult {
	req := &iamv1.CreateServiceAccountRequest{AccountId: acc, Name: name}
	out, _, err := w.viaSACDoor(ctx, sacMethodSACreate, req, func(ctx context.Context) (any, error) {
		return w.sax.Create(ctx, req)
	})
	if err != nil {
		return sacCreateResult{err: err}
	}
	op := out.(interface{ GetId() string })
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		got, gerr := w.ops.Get(w.ctx, op.GetId())
		if gerr != nil {
			return sacCreateResult{err: gerr}
		}
		if got.Done {
			if got.Error != nil {
				return sacCreateResult{err: fmt.Errorf("операция: %d %s", got.Error.Code, got.Error.Message)}
			}
			var md iamv1.CreateServiceAccountMetadata
			if uerr := got.Metadata.UnmarshalTo(&md); uerr != nil {
				return sacCreateResult{err: uerr}
			}
			return sacCreateResult{id: md.GetServiceAccountId()}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return sacCreateResult{err: fmt.Errorf("операция %s за 30 с не done", op.GetId())}
}

// raceCensus — учёток раунда по имени (перепись от usr-A).
func (w *sacWorld) raceCensus(prefix string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT count(*) FROM kaname.service_accounts WHERE account_id = $1 AND name LIKE $2`,
		string(w.accA), prefix+"-%").Scan(&n))
	return n
}

// SAC-34 — гонка: создание учётки против отзыва выдачи.
func TestServiceAccountCreator_SAC34_RaceCreateAgainstRevoke(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-34")
	executed := 0
	for k := 1; k <= 10; k++ {
		issK := seedServiceAccount(t, w.ctx, w.pool, w.accS, fmt.Sprintf("sva-iss-%d", k))
		gk := w.grantC(fmt.Sprintf("SAC-34 раунд %d: Gk", k), issK)
		prefix := fmt.Sprintf("r34-%d", k)
		r := w.raceCreates(issK, prefix, func() {
			op, err := w.revokeBinding(asUser(w.ctx, w.usrA), gk)
			if err == nil {
				awaitOp(t, w.ctx, w.ops, op.GetId())
			}
		})
		t.Logf("SAC-34 раунд %d: |Ck| = %d, отказов %d", k, len(r.created), r.refusals)
		require.Equalf(t, len(r.created), w.raceCensus(prefix), "SAC-34 раунд %d: перепись учёток = |Ck|", k)
		if len(r.created) == 0 {
			t.Logf("SAC-34 раунд %d: не выполнилось (|Ck| = 0)", k)
			continue
		}
		executed++
		for _, c := range r.created {
			w.pollRelation("service_account:"+issK, "v_update", sacSAModelType+":"+c, false,
				fmt.Sprintf("SAC-34 раунд %d: ведения %s нет", k, c))
		}
		w.pollRelation("service_account:"+issK, sacCreatorRelation, "account:"+string(w.accA), false,
			fmt.Sprintf("SAC-34 раунд %d: права создавать нет", k))
		w.drainReconcile()
		require.Zerof(t, w.reconcileQueueEmpty(), "SAC-34 раунд %d: очередь реконсайла пуста", k)
		w.awaitDoorWindow()
		for _, c := range r.created {
			w.requireRelation("service_account:"+issK, "v_update", sacSAModelType+":"+c, false,
				fmt.Sprintf("SAC-34 раунд %d: после дренажа ведения %s нет", k, c))
		}
	}
	require.Positivef(t, executed, "SAC-34: НЕ ВЫПОЛНИЛОСЬ — во всех 10 раундах |Ck| = 0")

	// Близнец — тот же прогон без отзыва: ведение есть.
	issT := seedServiceAccount(t, w.ctx, w.pool, w.accS, "sva-iss-twin")
	w.grantC("SAC-34 (близнец): Gk", issT)
	r := w.raceCreates(issT, "r34-twin", func() {})
	require.NotEmpty(t, r.created, "SAC-34 (близнец): учётки созданы")
	for _, c := range r.created {
		w.pollRelation("service_account:"+issT, "v_update", sacSAModelType+":"+c, true,
			"SAC-34 (близнец): ведение "+c)
	}
}

// SAC-35 — гонка: создание учётки против новой выдачи.
func TestServiceAccountCreator_SAC35_RaceCreateAgainstNewGrant(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-35")
	run := func(k int, grantBefore bool) {
		issK := seedServiceAccount(t, w.ctx, w.pool, w.accS, fmt.Sprintf("sva-iss35-%d", k))
		padK := seedServiceAccount(t, w.ctx, w.pool, w.accS, fmt.Sprintf("sva-pad35-%d", k))
		gk := w.grantC(fmt.Sprintf("SAC-35 раунд %d: Gk", k), issK)
		gPrime := func() {
			op, err := w.abx.Create(asUser(w.ctx, w.usrA), w.gC(padK, issK))
			if err == nil {
				awaitOp(t, w.ctx, w.ops, op.GetId())
			}
		}
		other := gPrime
		if grantBefore {
			w.grantC(fmt.Sprintf("SAC-35 раунд %d (близнец): G'k до барьера", k), padK, issK)
			other = func() {}
		}
		prefix := fmt.Sprintf("r35-%d-%v", k, grantBefore)
		r := w.raceCreates(issK, prefix, other)
		w.revokeDone(asUser(w.ctx, w.usrA), gk, fmt.Sprintf("SAC-35 раунд %d: отзыв Gk", k))
		w.pollRelation("service_account:"+issK, sacCreatorRelation, "account:"+string(w.accA), true,
			fmt.Sprintf("SAC-35 раунд %d: право создавать после отзыва Gk (G'k)", k))
		t.Logf("SAC-35 раунд %d (G'k до барьера: %v): |Ck| = %d", k, grantBefore, len(r.created))
		require.Lenf(t, r.created, 16, "SAC-35 раунд %d: Gk действовала на всём окне создания", k)
		for _, c := range r.created {
			w.pollRelation("service_account:"+issK, "v_update", sacSAModelType+":"+c, true,
				fmt.Sprintf("SAC-35 раунд %d: ведение %s", k, c))
		}
		w.drainReconcile()
		require.Zerof(t, w.reconcileQueueEmpty(), "SAC-35 раунд %d: очередь реконсайла пуста", k)
		w.awaitDoorWindow()
		for _, c := range r.created {
			w.requireRelation("service_account:"+issK, "v_update", sacSAModelType+":"+c, true,
				fmt.Sprintf("SAC-35 раунд %d: после дренажа ведение %s", k, c))
		}
	}
	for k := 1; k <= 10; k++ {
		run(k, false)
	}
	// Близнец — G'k выдана и `done` до барьера создания.
	run(11, true)
}

// sacIsDoorRefusal — отказ `PERMISSION_DENIED` с дословным текстом `permission denied`.
func sacIsDoorRefusal(err error) bool {
	st, ok := status.FromError(err)
	return ok && st.Code() == codes.PermissionDenied && st.Message() == "permission denied"
}
