// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// system_role_ids_world_integration_test.go — посев и общие части проб приёмки
// docs/engineering/acceptance/system-roles-carry-canonical-ids.md
// (kaname#543, отпечаток 27295473fda44228a6fc8426db12bacbbcc6c9a436e151a59e738ecf50375877).
//
// # ИСПЫТУЕМЫЙ НАХОДИТСЯ, А НЕ ВЫПИСЫВАЕТСЯ
//
// Предмет изменения — НОВАЯ миграция, номера которой нет в момент написания проб,
// и новые значения двух констант домена. Миграция узнаётся по тому, что она
// цитирует эту приёмку (`TestNewMigrationCitesAnApprovedAcceptance` требует цитаты
// от каждой новой миграции), константы — по тому, что они перестали равняться
// прежним идентификаторам и проходят судью формы фундамента. Нет ни того, ни
// другого — проба падает текстом «ИСПЫТУЕМОГО НЕТ», и только ПОСЛЕ проверки
// собственной фикстуры: сломанный посев обязан покраснеть раньше, чем выдать себя
// за отсутствующую возможность.
//
// # ПРЕЖНИЕ ИДЕНТИФИКАТОРЫ — РАЗБОРОМ, НЕ ЛИТЕРАЛОМ
//
// Литерала прежнего id в этом файле нет (предикат DoD п.6 приёмки): обе строки
// берутся разбором вставки ролей `0001_initial.sql` по имени роли, которое та
// вставка пишет. Применённая миграция не правится (ban #5), поэтому разбор
// устойчив by construction.
//
// # МИР
//
// Части — те же, что корень службы (`wireSCWorld`, общий с миром П1): дверь
// решения, реконсайлер, use-case'ы выдачи. Дублёра, отвечающего «да», нет.
// Выдачи на ПРЕЖНИЕ id сеются писателем выдач в той же форме, что пишет глагол
// `Create` на ревизии 092bee4fb (строка, набор субъектов, кортеж уровня выдачи,
// реестр выпущенного, событие смены субъекта, запись аудита), и материализуются
// реконсайлером. Глагол здесь не годится: на новом коде он прежние id не
// принимает (§5 приёмки).

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliamapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	abrepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// srciAcceptance — имя приёмки, которое цитирует испытуемая миграция.
const srciAcceptance = "system-roles-carry-canonical-ids.md"

// Имена, которыми вставка `0001_initial.sql` сеет две роли предмета, и имена,
// которые они носят после всей цепочки (`domain` — единственное объявление).
const (
	srciSeedNameAdmin  = "kacho-system.admin"
	srciSeedNameViewer = "kacho-system.viewer"
)

// srciObj — объект O1 (`vpc.network` в P1): id канонической формы `enp…`.
const srciObj = "enp00000000000000543"

// srciSubject — что о предмете известно из дерева.
type srciSubject struct {
	versions  []int64
	migration int64 // 0 — миграции, цитирующей приёмку, нет
	file      string
	oldAdmin  string // прежний id admin — разбором 0001
	oldViewer string // прежний id viewer — разбором 0001
	seeded    []string
}

var reSRCIRoleInsert = regexp.MustCompile(`^INSERT INTO kaname\.roles \(id, [^)]*\) VALUES \('([^']*)', (?:NULL|'[^']*'), '([^']*)'`)

// srciReadSubject — перепись каталога миграций и разбор посева ролей.
func srciReadSubject(t *testing.T) srciSubject {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций читается")
	var s srciSubject
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".sql") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "_")
		require.True(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): имя миграции %s без версии", name)
		v, err := strconv.ParseInt(prefix, 10, 64)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): версия миграции %s", name)
		s.versions = append(s.versions, v)
		body, err := fs.ReadFile(migrations.FS, name)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): тело миграции %s", name)
		if strings.Contains(string(body), srciAcceptance) && (s.migration == 0 || v < s.migration) {
			s.migration, s.file = v, name
		}
		if name != "0001_initial.sql" {
			continue
		}
		for _, line := range strings.Split(string(body), "\n") {
			m := reSRCIRoleInsert.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			s.seeded = append(s.seeded, m[1])
			switch m[2] {
			case srciSeedNameAdmin:
				s.oldAdmin = m[1]
			case srciSeedNameViewer:
				s.oldViewer = m[1]
			}
		}
	}
	sort.Slice(s.versions, func(i, j int) bool { return s.versions[i] < s.versions[j] })
	require.NotEmpty(t, s.versions, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): каталог миграций пуст")
	require.Len(t, s.seeded, 48, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): разбор вставок ролей 0001 (§0.1 приёмки — 48)")
	require.NotEmpty(t, s.oldAdmin, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вставка роли %s в 0001 не разобрана", srciSeedNameAdmin)
	require.NotEmpty(t, s.oldViewer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вставка роли %s в 0001 не разобрана", srciSeedNameViewer)
	// Контроль разборщика: найдено ровно два прежних id, и оба судье формы фундамента
	// негодны — иначе разобрано не то, о чём приёмка.
	require.NotEqual(t, s.oldAdmin, s.oldViewer, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): прежние id admin и viewer совпали")
	require.False(t, ids.HasKnownPrefix(s.oldAdmin), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): разобранный прежний id admin годен судье формы")
	require.False(t, ids.HasKnownPrefix(s.oldViewer), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): разобранный прежний id viewer годен судье формы")
	return s
}

// head — старшая миграция дерева.
func (s srciSubject) head() int64 { return s.versions[len(s.versions)-1] }

// preceding — версия «все миграции кроме новой»: старшая ниже испытуемой, а без
// испытуемого — голова.
func (s srciSubject) preceding() int64 {
	var best int64
	for _, v := range s.versions {
		if (s.migration == 0 || v < s.migration) && v > best {
			best = v
		}
	}
	return best
}

// absent — чего из предмета нет; пусто — предмет есть.
func (s srciSubject) absent() []string {
	var out []string
	if s.migration == 0 {
		out = append(out, fmt.Sprintf("миграции, цитирующей %s, нет (миграций %d, голова %d)",
			srciAcceptance, len(s.versions), s.head()))
	}
	for _, c := range []struct{ name, now, old string }{
		{"domain.SystemAdminRoleID", domain.SystemAdminRoleID, s.oldAdmin},
		{"domain.SystemViewerRoleID", domain.SystemViewerRoleID, s.oldViewer},
	} {
		switch {
		case c.now == c.old:
			out = append(out, c.name+" равна прежнему id — нового id нет")
		case !ids.HasKnownPrefix(c.now):
			out = append(out, fmt.Sprintf("%s=%q не проходит ids.HasKnownPrefix", c.name, c.now))
		}
	}
	return out
}

// requireSubject — испытуемый обязан существовать. Зовётся ПОСЛЕ проверки фикстуры.
func (s srciSubject) requireSubject(t *testing.T, scenario string) {
	t.Helper()
	if a := s.absent(); len(a) > 0 {
		t.Fatalf("%s: ИСПЫТУЕМОГО НЕТ: %s", scenario, strings.Join(a, "; "))
	}
}

// srciWorld — мир проб: части службы над своей базой и посев сценариев.
type srciWorld struct {
	*scWorld
	subj  srciSubject
	dsn   string
	db    *sql.DB // для наката и отката: goose ходит через database/sql
	roles *roleapp.Handler
	iiam  *internaliamapp.Handler

	k  domain.UserID // кластерный администратор объявленным путём (SRCI-04)
	u3 domain.UserID // получатель без выдач

	// Посев SRCI-05.
	a1     domain.AccountID
	p1     domain.ProjectID
	u1, u2 domain.UserID
	g1     string
	b1, b2 string

	// Получатели вставок SRCI-11: посеяны до гонки, разбираются по одному.
	racersMu sync.Mutex
	racers   []domain.UserID
}

// newSRCIWorldAt — мир над СВОЕЙ пустой базой, доведённой до версии `version`.
// version == 0 — вся цепочка дерева.
func newSRCIWorldAt(t *testing.T, version int64) *srciWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("нужен Postgres: пропуск в -short")
	}
	subj := srciReadSubject(t)
	dsn := pgtest.NewEmptyDB(t)
	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	if version == 0 {
		require.NoError(t, goose.Up(db, "."), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): вся цепочка накатывается")
	} else {
		require.NoError(t, goose.UpTo(db, ".", version), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): накат до %d", version)
	}

	ctx := context.Background()
	sc := wireSCWorld(t, ctx, poolFromDSN(t, dsn))
	w := &srciWorld{scWorld: sc, subj: subj, dsn: dsn, db: db}
	cat := catalogfixture.Source()
	w.roles = roleapp.NewHandler(nil, nil, nil,
		roleapp.NewGetRoleUseCase(sc.repo, cat),
		roleapp.NewListRolesUseCase(sc.repo, cat).WithRelationStore(sc.door))
	w.iiam = internaliamapp.NewHandler(nil, nil).
		WithRoleCompiledReader(roleapp.NewGetRoleCompiledUseCase(sc.repo)).
		WithSubjectChange(service.NewSubjectChangeService(kanamepg.NewSubjectChangeRepo(sc.pool, nil)))
	sc.ab.WithListByRole(accessbindingapp.NewListByRoleUseCase(sc.repo).WithRelationStore(sc.door, nil))

	// Старт службы пересчитывает проекции системных ролей (`cmd/kaname/serve.go`):
	// без этого шага мир был бы базой, которую служба ни разу не поднимала.
	_, err = seed.ReseedSystemRoleVerbs(ctx, sc.repo, sc.pool, catalogfixture.Facts(), nil)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): пересчёт проекции глаголов системных ролей")
	_, err = seed.ReseedSystemRoleRuleRefs(ctx, sc.repo, sc.pool, nil)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): пересчёт проекции сегментов правил системных ролей")

	// K — кластерный администратор объявленным путём (роль `admin`, не предмет),
	// с подтверждённым адресом и живой сессией уровня «2»; U3 — без выдач.
	w.k = mustSeedUser(t, ctx, sc.pool, "srcik")
	w.u3 = mustSeedUser(t, ctx, sc.pool, "srciu3")
	verifyAddresses(t, ctx, sc.pool)
	_, err = sc.pool.Exec(ctx, `SELECT kaname.restore_cluster_admin('user', $1)`, string(w.k))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): кластерный администратор объявленным путём")
	seedLiveHumanSession(t, sc, w.k)
	return w
}

// seedSRCI05 — посев SRCI-05: A1/P1, O1 в зеркале, U1–U2, G1 с членом U2, выдачи
// B1 (U1 → system.admin, кластер, allInScope) и B2 (G1#member → system.viewer,
// аккаунт A1, цель O1) на ПРЕЖНИЕ id.
func (w *srciWorld) seedSRCI05() {
	t := w.t
	ctx := w.ctx
	w.u1 = mustSeedUser(t, ctx, w.pool, "srciu1")
	w.u2 = mustSeedUser(t, ctx, w.pool, "srciu2")
	w.a1 = seedAccountByOwner(t, ctx, w.pool, "acc-srci-a1", w.u1)
	w.p1 = seedProjectInAccount(t, ctx, w.pool, w.a1, "prj-srci-p1")
	w.g1 = seedGroup(t, ctx, w.pool, w.a1, "grp-srci-g1")
	_, err := w.pool.Exec(ctx, `
		INSERT INTO kaname.group_members (group_id, member_type, member_id, added_at)
		VALUES ($1, 'user', $2, now())`, w.g1, string(w.u2))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): член группы G1")
	verifyAddresses(t, ctx, w.pool)
	seedMirrorObject(t, ctx, w.pool, scTargetType, srciObj, string(w.p1), string(w.a1))

	w.b1 = w.seedBinding(domain.AccessBinding{
		SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(w.u1),
		RoleID:       domain.RoleID(w.roleIDByName(domain.SystemAdminRoleName)),
		ResourceType: "cluster", ResourceID: domain.ClusterSingletonID, Scope: domain.ScopeCluster,
		Target: domain.AccessTarget{AllInScope: true},
	}, "B1")
	w.b2 = w.seedBinding(domain.AccessBinding{
		SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(w.g1),
		RoleID:       domain.RoleID(w.roleIDByName(domain.SystemViewerRoleName)),
		ResourceType: "account", ResourceID: string(w.a1), Scope: domain.ScopeAccount,
		Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: scTargetType, ID: srciObj}}},
	}, "B2")
}

// roleIDByName — id системной роли по имени: роль адресуется чтением, а не литералом.
func (w *srciWorld) roleIDByName(name string) string {
	w.t.Helper()
	var id string
	require.NoErrorf(w.t, w.pool.QueryRow(w.ctx,
		`SELECT id FROM kaname.roles WHERE name = $1 AND is_system`, name).Scan(&id),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): системная роль %s", name)
	return id
}

// seedBinding — выдача в форме, которую пишет `Create` (doCreate), затем
// материализация реконсайлером. Отдаёт id выдачи.
func (w *srciWorld) seedBinding(b domain.AccessBinding, what string) string {
	t := w.t
	ctx := w.ctx
	b.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	b.Status = domain.AccessBindingStatusActive
	b.GrantedByUserID = w.k
	b.Subjects = []domain.Subject{{Type: b.SubjectType, ID: b.SubjectID}}

	wr, err := w.repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = wr.Rollback(ctx) }()
	role, err := wr.Roles().Get(ctx, b.RoleID)
	require.NoErrorf(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура) %s: роль %s", what, b.RoleID)
	// Роль с правилами выпускает на создании только указатель выдачи на родителя
	// (buildBindingTuples), доступ к объектам разворачивает реконсайлер.
	require.NotEmptyf(t, role.Rules, "НЕ-ВЫПОЛНИЛОСЬ(фикстура) %s: роль %s без правил — форма кортежей иная", what, b.RoleID)
	created, err := bindingset.Insert(ctx, wr.AccessBindingsW(), b)
	require.NoErrorf(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура) %s: вставка выдачи", what)
	st, ok := created.StructuralParent()
	require.Truef(t, ok, "НЕ-ВЫПОЛНИЛОСЬ(фикстура) %s: указатель на родителя", what)
	tuples := []abrepo.RelationTuple{{User: st.User, Relation: st.Relation, Object: st.Object}}
	require.NoError(t, wr.AccessBindingsW().EmitRelationWrite(ctx, tuples))
	require.NoError(t, wr.AccessBindingsW().InsertEmittedTuples(ctx, created.ID, tuples))
	tenant := ""
	if b.ResourceType == "account" {
		tenant = b.ResourceID
	}
	for _, s := range b.Subjects {
		require.NoError(t, wr.AccessBindingsW().EmitSubjectChangeEvent(ctx, abrepo.SubjectChangeEvent{
			SubjectID: string(s.ID), SubjectType: string(s.Type), EventType: "binding_grant", Op: "binding_upsert",
		}))
		require.NoError(t, wr.AccessBindingsW().EmitAuditEvent(ctx, abrepo.AuditEvent{
			EventType: abrepo.AuditEventTypeGranted, Actor: string(w.k),
			SubjectType: string(s.Type), SubjectID: string(s.ID),
			ResourceType: string(created.ResourceType), ResourceID: created.ResourceID,
			RoleID: string(created.RoleID), BindingID: string(created.ID), TenantAccountID: tenant,
		}))
	}
	require.NoError(t, wr.Commit(ctx))
	require.NoErrorf(t, w.rec.ReconcileBindingForward(ctx, created.ID), "НЕ-ВЫПОЛНИЛОСЬ(фикстура) %s: материализация", what)
	return string(created.ID)
}

// srciKernelTables — таблицы схемы kaname по каталогу (не перечнем), кроме ленты
// подписки: её имя берётся у производителя.
func (w *srciWorld) tables(withJournal bool) []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT table_name FROM information_schema.tables
		 WHERE table_schema = 'kaname' AND table_type = 'BASE TABLE' ORDER BY 1`)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		require.NoError(w.t, rows.Scan(&n))
		if !withJournal && "kaname."+n == subscriptionjournal.Table {
			continue
		}
		out = append(out, n)
	}
	require.NoError(w.t, rows.Err())
	require.NotEmpty(w.t, out, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): обход каталога схемы kaname пуст")
	return out
}

func srciQualified(table string) string { return pgx.Identifier{"kaname", table}.Sanitize() }

// countWith — по таблице: число строк, чей текст содержит id.
func (w *srciWorld) countWith(tables []string, id string) map[string]int {
	w.t.Helper()
	out := map[string]int{}
	for _, tb := range tables {
		var n int
		require.NoError(w.t, w.pool.QueryRow(w.ctx,
			`SELECT count(*) FROM `+srciQualified(tb)+` t WHERE t::text LIKE '%' || $1 || '%'`, id).Scan(&n),
			"счёт строк с id в %s", tb)
		if n > 0 {
			out[tb] = n
		}
	}
	return out
}

// countInBytea — по байтовой колонке схемы kaname: число строк, чьи байты содержат id.
func (w *srciWorld) countInBytea(id string) map[string]int {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT table_name, column_name FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND data_type = 'bytea' ORDER BY 1, 2`)
	require.NoError(w.t, err)
	var cols [][2]string
	for rows.Next() {
		var tb, col string
		require.NoError(w.t, rows.Scan(&tb, &col))
		cols = append(cols, [2]string{tb, col})
	}
	require.NoError(w.t, rows.Err())
	rows.Close()
	out := map[string]int{}
	for _, c := range cols {
		var n int
		require.NoError(w.t, w.pool.QueryRow(w.ctx,
			`SELECT count(*) FROM `+srciQualified(c[0])+` WHERE position(convert_to($1, 'UTF8') IN `+
				pgx.Identifier{c[1]}.Sanitize()+`) > 0`, id).Scan(&n), "байты %s.%s", c[0], c[1])
		if n > 0 {
			out[c[0]+"."+c[1]] = n
		}
	}
	return out
}

// snapshot — мультимножество `<строка>::text` по таблице (полный срез SRCI-10).
func (w *srciWorld) snapshot(tables []string) map[string][]string {
	w.t.Helper()
	out := map[string][]string{}
	for _, tb := range tables {
		rows, err := w.pool.Query(w.ctx, `SELECT t::text FROM `+srciQualified(tb)+` t`)
		require.NoError(w.t, err, "срез %s", tb)
		var lines []string
		for rows.Next() {
			var s string
			require.NoError(w.t, rows.Scan(&s))
			lines = append(lines, s)
		}
		require.NoError(w.t, rows.Err())
		rows.Close()
		sort.Strings(lines)
		out[tb] = lines
	}
	return out
}

// journalUpTo — строки ленты с номером не больше `seq`, мультимножеством.
func (w *srciWorld) journalUpTo(seq int64) []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx,
		`SELECT t::text FROM `+subscriptionjournal.Table+` t WHERE sequence_no <= $1`, seq)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		require.NoError(w.t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(w.t, rows.Err())
	sort.Strings(out)
	return out
}

// journalHead — наибольший номер ленты.
func (w *srciWorld) journalHead() int64 {
	w.t.Helper()
	var n int64
	require.NoError(w.t, w.pool.QueryRow(w.ctx,
		`SELECT COALESCE(max(sequence_no), 0) FROM `+subscriptionjournal.Table).Scan(&n))
	return n
}

// srciEvent — строка ленты, как её отдаёт сервер потока: вид, id, изменение.
type srciEvent struct {
	seq        int64
	kind, id   string
	change     string
	rowContent string
}

// journalAfter — строки ленты с номером больше `seq`, по возрастанию номера.
func (w *srciWorld) journalAfter(seq int64) []srciEvent {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT sequence_no, resource_kind, resource_id, event_type, t::text
		  FROM `+subscriptionjournal.Table+` t WHERE sequence_no > $1 ORDER BY sequence_no`, seq)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []srciEvent
	for rows.Next() {
		var e srciEvent
		require.NoError(w.t, rows.Scan(&e.seq, &e.kind, &e.id, &e.change, &e.rowContent))
		out = append(out, e)
	}
	require.NoError(w.t, rows.Err())
	return out
}

// bindingsOnRoles — id выдач, чей role_id — один из названных.
func (w *srciWorld) bindingsOnRoles(roleIDs ...string) []string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx,
		`SELECT id FROM kaname.access_bindings WHERE role_id = ANY($1) ORDER BY id`, roleIDs)
	require.NoError(w.t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(w.t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(w.t, rows.Err())
	return out
}

// countRows — число строк таблицы.
func (w *srciWorld) countRows(table string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM `+table).Scan(&n))
	return n
}

// up — накат испытуемой миграции.
func (w *srciWorld) up(what string) {
	w.t.Helper()
	require.NoErrorf(w.t, goose.UpTo(w.db, ".", w.subj.migration), "%s: накат %s", what, w.subj.file)
}

// down — откат испытуемой миграции.
func (w *srciWorld) down(what string) {
	w.t.Helper()
	require.NoErrorf(w.t, goose.DownTo(w.db, ".", w.subj.preceding()), "%s: откат %s", what, w.subj.file)
}

// getBinding — выдача глазами K.
func (w *srciWorld) getBinding(id string) *iamv1.AccessBinding {
	w.t.Helper()
	pb, err := w.ab.Get(asUser(w.ctx, w.k), &iamv1.GetAccessBindingRequest{AccessBindingId: id})
	require.NoErrorf(w.t, err, "Get выдачи %s", id)
	return pb
}

// clusterAllInScope — тело SRCI-08: U3 → роль, кластер, «все объекты области».
func (w *srciWorld) clusterAllInScope(role string) *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{userSubject(w.u3)}, RoleId: role,
		ScopeType: "iam.cluster", ScopeId: domain.ClusterSingletonID, Target: allInScopeTarget(),
	}
}

// opsCount — число строк kaname.operations.
func (w *srciWorld) opsCount() int { return w.countRows("kaname.operations") }

// listAllRoles — все страницы `List` глазами K.
func (w *srciWorld) listAllRoles() []*iamv1.Role {
	w.t.Helper()
	var out []*iamv1.Role
	token := ""
	for page := 0; ; page++ {
		require.Less(w.t, page, 100, "List: страниц больше 100 — обход не сходится")
		resp, err := w.roles.List(asUser(w.ctx, w.k), &iamv1.ListRolesRequest{PageSize: 1000, PageToken: token})
		require.NoError(w.t, err, "List ролей")
		out = append(out, resp.GetRoles()...)
		token = resp.GetNextPageToken()
		if token == "" {
			return out
		}
	}
}
