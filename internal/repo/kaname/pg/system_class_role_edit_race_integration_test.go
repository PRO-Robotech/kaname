// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// system_class_role_edit_race_integration_test.go — SC-22 под конкуренцией:
// правка роли, добавляющая пишущий глагол, и выдача этой роли системному
// классу идут ПАРАЛЛЕЛЬНО, и проходит ровно одна сторона (приёмка
// `docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md`,
// редакция 5, DoD S2 «проба гонки»; задача PRO-Robotech/kaname#829).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОРЯДОК ЗАДАН, И В ОБЕ СТОРОНЫ
//
// Свободная гонка двух горутин сводит пробу к жребию: почти всегда одна
// сторона успевает закоммитить раньше, чем другая начала, и проба мерит
// отсутствие гонки. Здесь чередование СТРОИТСЯ: первая сторона берёт свой
// замок и держит транзакцию открытой; вторая запускается и обязана ВСТАТЬ на
// замке первой (опознаётся по `pg_blocking_pids`, а не паузой); только потом
// первая коммитит. Порядков два:
//
//   - правка первой: вторая — выдача — видит НОВЫЕ правила роли и отвергается
//     стражем выдачи (отказ SC-21);
//   - выдача первой: вторая — правка — видит НОВУЮ выдачу и отвергается
//     стражем правки (отказ SC-22).
//
// Держит это механизм базы, а не порядок вызовов в службе: строка роли берётся
// стражем выдачи под `FOR SHARE`, стражем правки — под `FOR NO KEY UPDATE`,
// замки несовместимы, и вопрос второй стороны задаётся новым оператором после
// коммита первой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЙ БЛИЗНЕЦ НЕСУЩИЙ
//
// У каждого порядка — близнец, отличный ОДНИМ фактом: правка оставляет роль
// читающей (`[get, list]` → `[get]`). Хореография та же, замки те же, вторая
// сторона так же ждёт — и обе стороны проходят. Без близнеца проба зеленела бы
// на стражах, отвергающих любую параллельную пару, то есть на сериализации без
// предмета.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ПРОБА НЕ ПОКРЫВАЕТ — НАЗВАНО
//
// Синхронный отказ use-case до заведения операции (`refuseIfBoundToSystemClass`)
// здесь не участвует: он чтение без замка, и последнее слово у записи. Проба
// идёт по ПИСАТЕЛЯМ хранилища ровно в том порядке, в каком их зовёт тело
// операции правки (`GuardSystemClassReads` → `UpdateCAS`) и создание выдачи
// (`Insert` → `InsertSubjects`).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// sc22Scene — роль `[get, list]`, выданная пока НИКОМУ из классов, и аккаунт,
// на который её будут выдавать.
type sc22Scene struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	repo    *kanamepg.Repository
	role    domain.Role
	version string
	account domain.AccountID
}

func sc22ReadRules() domain.Rules {
	return domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get", "list"}}}
}

func newSC22Scene(t *testing.T, suffix string) *sc22Scene {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "sc22"+suffix)
	acc := seedAccount(t, ctx, repo, "acc-sc22-"+suffix, uid)

	rules := sc22ReadRules()
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	role, err := w.RolesW().Insert(ctx, domain.Role{
		ID:          domain.RoleID(ids.NewID(domain.PrefixRole)),
		AccountID:   acc.ID,
		Name:        domain.RoleName("sc22_read_" + suffix),
		Rules:       rules,
		Permissions: compiled,
	})
	require.NoError(t, err, "фикстура: роль только чтения")
	require.NoError(t, w.Commit(ctx))
	require.True(t, role.GrantsReadsOnly(), "предпосылка: роль фикстуры только читает")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	_, version, err := rd.Roles().GetWithVersion(ctx, role.ID)
	_ = rd.Rollback(ctx)
	require.NoError(t, err)
	require.NotEmpty(t, version)

	return &sc22Scene{ctx: ctx, pool: pool, repo: repo, role: role, version: version, account: acc.ID}
}

// edited — роль после правки: `withUpdate` добавляет пишущий глагол (предмет),
// иначе правка оставляет роль читающей (близнец). Отличие — один факт.
func (s *sc22Scene) edited(t *testing.T, withUpdate bool) domain.Role {
	t.Helper()
	verbs := []string{"get"}
	if withUpdate {
		verbs = []string{"get", "list", "update"}
	}
	rules := domain.Rules{{Module: "compute", Resources: []string{"instance"}, Verbs: verbs}}
	compiled, err := domain.CompileRules(rules)
	require.NoError(t, err)
	r := s.role
	r.Rules = rules
	r.Permissions = compiled
	require.Equal(t, !withUpdate, r.GrantsReadsOnly(), "предпосылка: правка меняет ровно глагольный набор")
	return r
}

// sc22Side — одна сторона гонки в своей транзакции: шаг до замка, держание и
// коммит по сигналу. Ошибка шага или коммита — исход стороны.
type sc22Side struct {
	name string
	step func(ctx context.Context, w kaname.Writer) error
}

// roleEditSide — тело операции правки роли: страж под замком строки роли,
// затем CAS-запись правил (`role.UpdateRoleUseCase.doUpdate`).
func (s *sc22Scene) roleEditSide(r domain.Role) sc22Side {
	return sc22Side{name: "правка роли", step: func(ctx context.Context, w kaname.Writer) error {
		if err := w.RolesW().GuardSystemClassReads(ctx, r.ID, r.GrantsReadsOnly()); err != nil {
			return err
		}
		_, err := w.RolesW().UpdateCAS(ctx, r, []string{"rules"}, s.version)
		return err
	}}
}

// grantSide — создание выдачи роли классу «вошедшие» на аккаунте: строка
// выдачи, затем её субъект (страж класса стоит на субъекте).
func (s *sc22Scene) grantSide(id domain.AccessBindingID) sc22Side {
	return sc22Side{name: "выдача классу", step: func(ctx context.Context, w kaname.Writer) error {
		if _, err := w.AccessBindingsW().Insert(ctx, domain.AccessBinding{
			ID:           id,
			SubjectType:  domain.SubjectTypeSystemClass,
			SubjectID:    domain.SubjectID(domain.ClassAuthenticated),
			RoleID:       s.role.ID,
			ResourceType: "account",
			ResourceID:   string(s.account),
			Target:       domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "compute.instance", ID: "obj-1"}}},
		}); err != nil {
			return err
		}
		return w.AccessBindingsW().InsertSubjects(ctx, id, []domain.Subject{
			{Type: domain.SubjectTypeSystemClass, ID: domain.SubjectID(domain.ClassAuthenticated)},
		})
	}}
}

// sc22Outcome — исход обеих сторон.
type sc22Outcome struct{ first, second error }

// race строит чередование: первая сторона исполняет шаг и держит транзакцию;
// вторая запускается и обязана ВСТАТЬ на замке первой; затем первая коммитит,
// и исход второй дочитывается. Если вторая завершилась, не встав на замок, —
// это исход о предмете (стороны не сериализованы), а не сорванная сцена: обе
// стороны доводятся до конца, и утверждение об исходе их и судит.
func (s *sc22Scene) race(t *testing.T, first, second sc22Side) sc22Outcome {
	t.Helper()
	ctx := s.ctx

	w1, err := s.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w1.Rollback(ctx) }()
	firstErr := first.step(ctx, w1)
	require.NoErrorf(t, firstErr, "первая сторона (%s) обязана пройти свой шаг до коммита — иначе гонки нет", first.name)

	// Перепись ожидающих ДО запуска второй: чужого ожидания на замке в базе
	// пробы быть не должно, иначе опознание ниже приняло бы его за вторую сторону.
	require.Zero(t, sc22LockWaiters(t, s), "посторонний ожидающий на замке до запуска второй стороны")

	done := make(chan error, 1)
	go func() {
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		w2, e := s.repo.Writer(c)
		if e != nil {
			done <- e
			return
		}
		if e = second.step(c, w2); e != nil {
			_ = w2.Rollback(c)
			done <- e
			return
		}
		done <- w2.Commit(c)
	}()

	finishedEarly, earlyErr := sc22AwaitBlockedOrDone(t, s, done, second.name)

	require.NoErrorf(t, w1.Commit(ctx), "коммит первой стороны (%s)", first.name)
	if finishedEarly {
		t.Logf("вторая сторона (%s) завершилась, НЕ встав на замок первой: стороны не сериализованы", second.name)
		return sc22Outcome{first: nil, second: earlyErr}
	}
	select {
	case secondErr := <-done:
		return sc22Outcome{first: nil, second: secondErr}
	case <-time.After(30 * time.Second):
		t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: вторая сторона (%s) не завершилась за 30 с после коммита первой", second.name)
		return sc22Outcome{}
	}
}

// sc22LockWaiters — сколько процессов базы пробы стоят на замке сейчас.
func sc22LockWaiters(t *testing.T, s *sc22Scene) int {
	t.Helper()
	var n int
	require.NoError(t, s.pool.QueryRow(s.ctx, `
		SELECT count(*) FROM pg_stat_activity
		 WHERE datname = current_database()
		   AND wait_event_type = 'Lock'
		   AND cardinality(pg_blocking_pids(pid)) > 0`).Scan(&n))
	return n
}

// sc22AwaitBlockedOrDone — ждёт УСЛОВИЯ: вторая сторона встала на замке
// (единственный ожидающий в базе пробы) либо уже завершилась. Опознание — по
// `pg_blocking_pids`, а не по паузе.
func sc22AwaitBlockedOrDone(t *testing.T, s *sc22Scene, done <-chan error, who string) (bool, error) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case e := <-done:
			return true, e
		default:
		}
		var query string
		err := s.pool.QueryRow(s.ctx, `
			SELECT query FROM pg_stat_activity
			 WHERE datname = current_database()
			   AND wait_event_type = 'Lock'
			   AND cardinality(pg_blocking_pids(pid)) > 0
			 ORDER BY pid LIMIT 1`).Scan(&query)
		if err == nil {
			t.Logf("вторая сторона (%s) стоит на замке первой; оператор: %s", who, sc22OneLine(query))
			return false, nil
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			require.NoError(t, err, "наблюдатель замков")
		}
		if time.Now().After(deadline) {
			t.Fatalf("НЕ ВЫПОЛНИЛОСЬ: вторая сторона (%s) за 15 с ни встала на замке, ни завершилась — "+
				"чередование не построено, вердикта о предмете у сцены нет", who)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func sc22OneLine(s string) string {
	out := make([]rune, 0, len(s))
	space := false
	for _, r := range s {
		if r == '\n' || r == '\t' || r == ' ' {
			if !space {
				out = append(out, ' ')
			}
			space = true
			continue
		}
		space = false
		out = append(out, r)
	}
	return string(out)
}

// stored — что осталось в базе после гонки: глаголы роли только читают? сколько
// субъектов-классов у выдач этой роли?
func (s *sc22Scene) stored(t *testing.T) (readsOnly bool, classSubjects int) {
	t.Helper()
	rd, err := s.repo.Reader(s.ctx)
	require.NoError(t, err)
	got, err := rd.Roles().Get(s.ctx, s.role.ID)
	_ = rd.Rollback(s.ctx)
	require.NoError(t, err)
	require.NoError(t, s.pool.QueryRow(s.ctx, `
		SELECT count(*) FROM kaname.access_binding_subjects bs
		  JOIN kaname.access_bindings b ON b.id = bs.binding_id
		 WHERE b.role_id = $1 AND bs.subject_type = 'system_class'`, string(s.role.ID)).Scan(&classSubjects))
	return got.GrantsReadsOnly(), classSubjects
}

// sc22RequireRefusal — отказ стороны: предусловие (FAILED_PRECONDITION) и
// дословный текст приёмки.
func sc22RequireRefusal(t *testing.T, err error, text, who string) {
	t.Helper()
	require.Errorf(t, err, "%s прошла — обе стороны гонки приняты, роль классу получила пишущий глагол", who)
	assert.Truef(t, errors.Is(err, iamerr.ErrFailedPrecondition), "%s: класс отказа — предусловие, получено %v", who, err)
	assert.Equalf(t, text, iamerr.StripSentinel(err), "%s: текст отказа", who)
}

// TestSystemClass_SC22_RoleEditFirst_GrantToClassRefused — правка роли берёт
// строку первой и добавляет `update`; выдача той же роли классу встаёт на
// замке и после коммита правки отвергается (отказ SC-21). Роль пишет, выдачи
// классу нет.
func TestSystemClass_SC22_RoleEditFirst_GrantToClassRefused(t *testing.T) {
	s := newSC22Scene(t, "ef")
	grant := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))

	got := s.race(t, s.roleEditSide(s.edited(t, true)), s.grantSide(grant))

	require.NoError(t, got.first, "правка роли (первая сторона) проходит")
	sc22RequireRefusal(t, got.second,
		"Role "+string(s.role.ID)+" grants verbs beyond get and list; a system class subject accepts read-only roles",
		"выдача классу (вторая сторона)")
	readsOnly, classSubjects := s.stored(t)
	assert.False(t, readsOnly, "правка применена: роль получила пишущий глагол")
	assert.Zero(t, classSubjects, "выдачи роли классу нет")
}

// Близнец: та же хореография, правка оставляет роль читающей — проходят обе.
func TestSystemClass_SC22_RoleEditFirst_ReadOnlyEditTwin_BothPass(t *testing.T) {
	s := newSC22Scene(t, "eft")
	grant := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))

	got := s.race(t, s.roleEditSide(s.edited(t, false)), s.grantSide(grant))

	require.NoError(t, got.first, "правка роли (первая сторона) проходит")
	require.NoError(t, got.second, "выдача классу роли, оставшейся читающей, проходит")
	readsOnly, classSubjects := s.stored(t)
	assert.True(t, readsOnly, "роль осталась читающей")
	assert.Equal(t, 1, classSubjects, "выдача роли классу есть")
}

// TestSystemClass_SC22_GrantFirst_RoleEditRefused — выдача роли классу берёт
// строку роли первой; правка, добавляющая `update`, встаёт на замке и после
// коммита выдачи отвергается (отказ SC-22). Выдача есть, роль только читает.
func TestSystemClass_SC22_GrantFirst_RoleEditRefused(t *testing.T) {
	s := newSC22Scene(t, "gf")
	grant := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))

	got := s.race(t, s.grantSide(grant), s.roleEditSide(s.edited(t, true)))

	require.NoError(t, got.first, "выдача классу (первая сторона) проходит")
	sc22RequireRefusal(t, got.second,
		"Role "+string(s.role.ID)+" is bound to a system class subject; it accepts read verbs only",
		"правка роли (вторая сторона)")
	readsOnly, classSubjects := s.stored(t)
	assert.True(t, readsOnly, "правка не применена: роль только читает")
	assert.Equal(t, 1, classSubjects, "выдача роли классу есть")
}

// Близнец: та же хореография, правка оставляет роль читающей — проходят обе.
func TestSystemClass_SC22_GrantFirst_ReadOnlyEditTwin_BothPass(t *testing.T) {
	s := newSC22Scene(t, "gft")
	grant := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))

	got := s.race(t, s.grantSide(grant), s.roleEditSide(s.edited(t, false)))

	require.NoError(t, got.first, "выдача классу (первая сторона) проходит")
	require.NoError(t, got.second, "правка, оставляющая роль читающей, проходит при выдаче классу")
	readsOnly, classSubjects := s.stored(t)
	assert.True(t, readsOnly, "роль осталась читающей")
	assert.Equal(t, 1, classSubjects, "выдача роли классу есть")
}
