// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/scalegrid"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

// Только R7-1-10/12: committed Given не копит journal advisory locks на 10000
// выдач в одной TX. Число строк, IDs и две неудобные стороны вопроса прежние.
const r7CostSeedBatch = 128

type r7CostSeed struct {
	pool    *pgxpool.Pool
	capture *verdictCapture
	fixture *gridFixture
}

func newR7CostSeed(t *testing.T) *r7CostSeed {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("разбор строки подключения R7 cost: %v", err)
	}
	h := &r7CostSeed{capture: &verdictCapture{}}
	cfg.ConnConfig.Tracer = h.capture
	cfg.MaxConns = 1
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	h.pool, err = pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("пул R7 cost: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, h.pool)
	h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
		h.fixture = newR7CostGridFixture(t, ctx, tx)
		h.fixture.growN(t, ctx, 200)
		h.fixture.setR(t, ctx, 1, scalegrid.RecruitDirect)
	})
	return h
}

// Cleanup регистрируется сразу при получении TX, до проверок/посева. Он имеет
// независимый 5s deadline даже после Fatal или истечения 30s request context.
func (h *r7CostSeed) transaction(t *testing.T, commit bool, run func(context.Context, pgx.Tx)) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tx, err := h.pool.Begin(ctx)
	if tx != nil {
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
			defer stop()
			if e := tx.Rollback(cleanup); e != nil && !errors.Is(e, pgx.ErrTxClosed) {
				t.Errorf("rollback R7 cost: %v", e)
			}
			if h.fixture != nil {
				h.fixture.tx = nil
			}
		}()
	}
	if err != nil {
		t.Fatalf("транзакция R7 cost: %v", err)
	}
	if h.fixture != nil {
		h.fixture.tx = tx
	}
	run(ctx, tx)
	if commit {
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit R7 cost seed: %v", err)
		}
	}
}

func (h *r7CostSeed) growB(t *testing.T, target int) {
	t.Helper()
	for h.fixture.seedB < target {
		next := min(h.fixture.seedB+r7CostSeedBatch, target)
		h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
			h.fixture.growR7CostB(t, ctx, next)
		})
	}
}

func (h *r7CostSeed) elsewhere(t *testing.T, n int) {
	t.Helper()
	for first := 0; first < n; first += r7CostSeedBatch {
		last := min(first+r7CostSeedBatch, n)
		h.transaction(t, true, func(ctx context.Context, tx pgx.Tx) {
			s := scalegrid.NewSeeder(tx)
			for i := first; i < last; i++ {
				pid := fmt.Sprintf("prj-e%07d", i)
				bid := fmt.Sprintf("acb-e%07d", i)
				must(t, s.QueueRaw(ctx,
					`INSERT INTO kaname.projects (id, account_id, name) VALUES ($1, 'acc-1', $1)`, pid))
				must(t, s.QueueRaw(ctx,
					`INSERT INTO kaname.access_bindings
					   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
					 VALUES ($1, 'user', 'usr-1', 'rol-anchor', 'project', $2, 'ACTIVE')`, bid, pid))
				must(t, s.QueueRaw(ctx,
					`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
					 VALUES ($1, 'user', 'usr-1')`, bid))
			}
			must(t, s.Flush(ctx))
		})
	}
}

// До измерения подтверждаем полный committed Given, а не успешный префикс
// посева. Эти запросы не входят в Ask -> capture -> EXPLAIN и не меняют прибор.
func (h *r7CostSeed) census(t *testing.T, foreign, elsewhere int) {
	t.Helper()
	h.transaction(t, false, func(ctx context.Context, tx pgx.Tx) {
		var mirrors, local, bindings, subjects, users, roles, projects, remote, remoteSubjects int
		err := tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_mirror WHERE object_type=$1 AND object_id LIKE 'repo-%'),
 (SELECT count(*) FROM kaname.access_bindings b JOIN kaname.access_binding_subjects s ON s.binding_id=b.id
  WHERE b.id='acb-r00000' AND b.role_id='rol-r00000' AND b.resource_type='project' AND b.resource_id='prj-1'
    AND b.status='ACTIVE' AND s.subject_type='user' AND s.subject_id='usr-1'),
 (SELECT count(*) FROM kaname.access_bindings WHERE id LIKE 'acb-b%'),
 (SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id LIKE 'acb-b%'),
 (SELECT count(*) FROM kaname.users WHERE id LIKE 'usr-b%'),
 (SELECT count(*) FROM kaname.roles WHERE id LIKE 'rol-b%'),
 (SELECT count(*) FROM kaname.projects WHERE id LIKE 'prj-e%'),
 (SELECT count(*) FROM kaname.access_bindings WHERE id LIKE 'acb-e%'),
 (SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id LIKE 'acb-e%')`, probeCatalogType).Scan(&mirrors, &local, &bindings, &subjects, &users, &roles, &projects, &remote, &remoteSubjects)
		if err != nil {
			t.Fatalf("перепись R7 cost: %v", err)
		}
		if mirrors != 200 || local != 1 || bindings != foreign || subjects != foreign || users != min(foreign, bSubjectPool) || roles != (foreign+bSubjectPool-1)/bSubjectPool || projects != elsewhere || remote != elsewhere || remoteSubjects != elsewhere {
			t.Fatalf("неполный R7 cost Given: N=%d R=%d B=%d subjects=%d users=%d roles=%d elsewhere=%d/%d/%d; want N=200 R=1 B=%d elsewhere=%d", mirrors, local, bindings, subjects, users, roles, projects, remote, remoteSubjects, foreign, elsewhere)
		}
		var shapedB, shapedElsewhere int
		err = tx.QueryRow(ctx, `SELECT
 (SELECT count(*) FROM generate_series(0,$1::integer-1) i
  JOIN kaname.access_bindings b ON b.id='acb-b'||lpad(i::text,7,'0')
  JOIN kaname.access_binding_subjects s ON s.binding_id=b.id
  WHERE b.subject_type='user' AND b.subject_id='usr-b'||lpad((i%1000)::text,7,'0')
    AND b.role_id='rol-b'||lpad((i/1000)::text,5,'0') AND b.resource_type='project' AND b.resource_id='prj-1'
    AND b.status='ACTIVE' AND s.subject_type=b.subject_type AND s.subject_id=b.subject_id),
 (SELECT count(*) FROM generate_series(0,$2::integer-1) i
  JOIN kaname.projects p ON p.id='prj-e'||lpad(i::text,7,'0') AND p.account_id='acc-1'
  JOIN kaname.access_bindings b ON b.id='acb-e'||lpad(i::text,7,'0') AND b.resource_id=p.id
  JOIN kaname.access_binding_subjects s ON s.binding_id=b.id
  WHERE b.subject_type='user' AND b.subject_id='usr-1' AND b.role_id='rol-anchor'
    AND b.resource_type='project' AND b.status='ACTIVE' AND s.subject_type='user' AND s.subject_id='usr-1')`, foreign, elsewhere).Scan(&shapedB, &shapedElsewhere)
		if err != nil {
			t.Fatalf("форма R7 cost Given: %v", err)
		}
		if shapedB != foreign || shapedElsewhere != elsewhere {
			t.Fatalf("изменена форма R7 cost Given: same-scope foreign %d/%d; same-subject elsewhere %d/%d", shapedB, foreign, shapedElsewhere, elsewhere)
		}
	})
}

// Узкая копия bootstrap: единственная семантическая добавка — lawful WayIn
// для committed ACTIVE usr-1, той же TX. Общий newGridFixture не меняется.
func newR7CostGridFixture(t *testing.T, ctx context.Context, tx pgx.Tx) *gridFixture {
	t.Helper()
	f := &gridFixture{tx: tx}

	// Кластер — СИНГЛТОН, и его строку кладёт миграция. `DO NOTHING` здесь не
	// проглатывание ошибки, а признание факта: идентификатор фиксирован
	// ограничением схемы, вставить второй нельзя, и наличие первого — норма.
	exec(t, ctx, tx, `INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho')
		 ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ('acc-1', 'probe-account', 'usr-1')`)
	exec(t, ctx, tx,
		activewayin.WithWayIn(`INSERT INTO kaname.users (id, external_id, email, account_id)
		 VALUES ('usr-1', 'ext-1', 'usr-1@kacho.local', 'acc-1')`))
	exec(t, ctx, tx,
		`INSERT INTO kaname.projects (id, account_id, name) VALUES ('prj-1', 'acc-1', 'probe-project')`)
	exec(t, ctx, tx,
		`INSERT INTO kaname.groups (id, account_id, name) VALUES ($1, 'acc-1', 'probe-group')`, probeGroupID)
	exec(t, ctx, tx,
		`INSERT INTO kaname.group_members (group_id, member_type, member_id) VALUES ($1, 'user', 'usr-1')`,
		probeGroupID)

	seedProbeRole(t, ctx, tx, "rol-anchor", "probe.anchor")

	// Звенья цепи — своими объектами со своими цепями.
	s := scalegrid.NewSeeder(tx)
	must(t, s.Queue(ctx, scalegrid.MirrorRow{
		ObjectType: "iam.project", ObjectID: "prj-1",
		ParentAccountID: "acc-1", ParentChain: []string{"account:acc-1"},
	}))
	must(t, s.Queue(ctx, scalegrid.MirrorRow{
		ObjectType: "registry.registries", ObjectID: "reg-1",
		ParentProjectID: "prj-1", ParentAccountID: "acc-1",
		ParentChain: []string{"project:prj-1", "account:acc-1"},
	}))
	must(t, s.Flush(ctx))
	return f
}

// Узкая копия growB: исходные IDs, modulo/quotient, роли и scope сохранены.
// Новые ACTIVE users получают WithWayIn в том же QueueRaw statement.
func (f *gridFixture) growR7CostB(t *testing.T, ctx context.Context, target int) {
	t.Helper()
	if target-f.seedB > r7CostSeedBatch {
		t.Fatal("R7 cost seed превышает 128 complete bindings в одной TX")
	}
	if target <= f.seedB {
		return
	}
	s := scalegrid.NewSeeder(f.tx)

	// Пул субъектов — до нужного, считая от заведённых.
	wantSubjects := target
	if wantSubjects > bSubjectPool {
		wantSubjects = bSubjectPool
	}
	for i := f.seedBSubjects; i < wantSubjects; i++ {
		uid := fmt.Sprintf("usr-b%07d", i)
		must(t, s.QueueRaw(ctx,
			activewayin.WithWayIn(`INSERT INTO kaname.users (id, external_id, email, account_id)
			 VALUES ($1, $1, $1 || '@kacho.local', 'acc-1')`), uid))
	}
	if wantSubjects > f.seedBSubjects {
		f.seedBSubjects = wantSubjects
	}

	// Пул ролей: столько, чтобы пятёрка уникальности не столкнулась.
	wantRoles := (target + bSubjectPool - 1) / bSubjectPool
	for i := f.seedBRoles; i < wantRoles; i++ {
		roleID := fmt.Sprintf("rol-b%05d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
			 VALUES ($1, $2, '[]'::jsonb,
			         jsonb_build_array(jsonb_build_object(
			             'module', 'probe', 'resources', jsonb_build_array('*'),
			             'verbs',  jsonb_build_array($3::text))),
			         'cluster_root')`, roleID, fmt.Sprintf("probe.b%05d", i), probeVerb))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
			roleID, probeCatalogType, probeVerb))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.role_rule_selectors (role_id, rule_fp, arm, object_types, match_labels, verbs_by_type)
			 VALUES ($1, 'fp-1', 'anchor', ARRAY[$2::text], '{}'::jsonb, jsonb_build_object($2::text, jsonb_build_array($3::text)))`,
			roleID, probeCatalogType, probeVerb))
	}
	if wantRoles > f.seedBRoles {
		f.seedBRoles = wantRoles
	}

	for i := f.seedB; i < target; i++ {
		uid := fmt.Sprintf("usr-b%07d", i%bSubjectPool)
		roleID := fmt.Sprintf("rol-b%05d", i/bSubjectPool)
		bid := fmt.Sprintf("acb-b%07d", i)
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ($1, 'user', $2, $3, 'project', 'prj-1', 'ACTIVE')`, bid, uid, roleID))
		must(t, s.QueueRaw(ctx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ($1, 'user', $2)`, bid, uid))
	}
	must(t, s.Flush(ctx))
	f.seedB = target
}
