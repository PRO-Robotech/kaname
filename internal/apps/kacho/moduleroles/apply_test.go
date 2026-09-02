// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// apply_test.go — применитель ролей модуля (приёмка
// `services/iam/docs/engineering/acceptance/roles-come-as-data-not-migrations.md`
// §3.1, §3.5; сценарии MOD-RD-12 … MOD-RD-15, MOD-RD-08, MOD-RD-09).
//
// Дублёр писателя ведёт СВОЮ таблицу и отвечает как продукт: приведение при
// отличии, ноль записей при совпадении, отказ на удалении. Дублёр,
// принимающий больше настоящего, сделал бы невидимым ровно тот дефект, ради
// которого его подставляют.
package moduleroles_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/moduleroles"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// fakeStore — строки ролей и их проекция сегментов. Ключ — `id`.
type fakeStore struct {
	rows  map[domain.RoleID]domain.Role
	refs  map[domain.RoleID][]domain.RoleRuleRef
	calls int // вызовов писателя строки
}

func newStore() *fakeStore {
	return &fakeStore{
		rows: map[domain.RoleID]domain.Role{},
		refs: map[domain.RoleID][]domain.RoleRuleRef{},
	}
}

// RunInWriteTx — дублёр ИСПОЛНИТЕЛЯ транзакций, а не только хранилища.
//
// Приведение отказа к статусу стоит здесь не для красоты: настоящий исполнитель
// (`NewRepoTxRunner` → `shared.DoWithWriteTx`) зовёт `shared.MapRepoErr` на
// отказе действия, и цепочка `%w` в этом месте ТЕРЯЕТСЯ. Дублёр, отдающий отказ
// сырым, СОХРАНЯЛ бы цепочку, которую продукт теряет, — то есть был бы
// снисходительнее продукта ровно на той оси, которую пробы полосы и измеряют
// (задача #1880). Границы транзакции у дублёра нет, и он её не изображает:
// границу проверяет интеграционная проба на настоящей базе.
func (s *fakeStore) RunInWriteTx(ctx context.Context, fn func(context.Context, moduleroles.RoleWriter) error) error {
	return shared.MapRepoErr(fn(ctx, s))
}

// UpsertSystemRole — то же поведение, что у оператора: приведение ТОЛЬКО при
// отличии объявленных полей, иначе ноль затронутых строк.
func (s *fakeStore) UpsertSystemRole(_ context.Context, r domain.Role) (domain.Role, bool, error) {
	s.calls++
	if r.ClusterID == "" {
		return domain.Role{}, false, errors.New("cluster_id пуст: строка не была бы системной")
	}
	prev, ok := s.rows[r.ID]
	if ok && prev.Name == r.Name && prev.Description == r.Description &&
		string(mustEncode(prev.Rules)) == string(mustEncode(r.Rules)) {
		return domain.Role{}, false, nil
	}
	if ok {
		// Приведение сохраняет метки и время создания — их манифест не объявляет.
		r.Labels = prev.Labels
		r.CreatedAt = prev.CreatedAt
	}
	r.IsSystem = true
	s.rows[r.ID] = r
	return r, true, nil
}

// mustEncode — отпечаток правила в том же кодеке, что кладёт строку в базу.
// Своё сравнение полей разошлось бы с оператором молча.
func mustEncode(rs domain.Rules) []byte {
	b, err := domain.EncodeRules(rs)
	if err != nil {
		panic(err)
	}
	return b
}

func (s *fakeStore) ReplaceRuleRefs(_ context.Context, id domain.RoleID, refs []domain.RoleRuleRef) error {
	if _, ok := s.rows[id]; !ok {
		return errors.New("проекция сегментов пишется по несуществующей строке")
	}
	s.refs[id] = refs
	return nil
}

// vpcManifest — манифест vpc с ролью кластерного яруса.
func vpcManifest(t *testing.T, id, class string) *manifest.Manifest {
	t.Helper()
	doc := "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: " + id + "\n" +
		"    description: Распоряжается сетями модуля.\n" +
		"    tier: {tierType: iam.cluster, tierId: cluster_kacho_root}\n" +
		"    rules:\n      - {module: vpc, resources: [network], classes: [" + class + "]}\n"
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("фикстура манифеста отвергнута: %v", err)
	}
	return m
}

// TestMODRD12AppliedRoleIsSystemAndAnchoredAtTheCluster — MOD-RD-12.
func TestMODRD12AppliedRoleIsSystemAndAnchoredAtTheCluster(t *testing.T) {
	store := newStore()
	rep, err := moduleroles.NewApplier(store).Apply(context.Background(), vpcManifest(t, "vpc.network.admin", "get"))
	if err != nil {
		t.Fatalf("применение отвергнуто: %v", err)
	}
	if rep.Declared != 1 || rep.Written != 1 || rep.Unchanged != 0 {
		t.Fatalf("перепись применения не та: %s", rep)
	}
	want := domain.SystemRoleID("vpc.network.admin")
	row, ok := store.rows[want]
	if !ok {
		t.Fatalf("строки под id %q нет — применитель адресовал её иначе, и выдачи "+
			"перестали бы резолвиться молча: %v", want, store.rows)
	}
	if row.ClusterID != domain.ClusterSingletonID {
		t.Errorf("якорь строки не кластерный: %q", row.ClusterID)
	}
	if row.AccountID != "" || row.ProjectID != "" {
		t.Errorf("у системной строки заняты чужие якоря: acc=%q prj=%q", row.AccountID, row.ProjectID)
	}
	if string(row.Name) != "vpc.network.admin" {
		t.Errorf("имя строки не дословно объявленное: %q", row.Name)
	}
	if len(store.refs[want]) == 0 {
		t.Errorf("проекция объявленных сегментов не записана — правило пережило бы свой " +
			"референт, и ключ каталога не увидел бы этого by construction")
	}
}

// TestMODRD13SecondRunWithoutAnEditWritesNothing — MOD-RD-13.
func TestMODRD13SecondRunWithoutAnEditWritesNothing(t *testing.T) {
	store := newStore()
	ap := moduleroles.NewApplier(store)
	m := vpcManifest(t, "vpc.network.admin", "get")
	if _, err := ap.Apply(context.Background(), m); err != nil {
		t.Fatalf("первое применение отвергнуто: %v", err)
	}
	rep, err := ap.Apply(context.Background(), m)
	if err != nil {
		t.Fatalf("повторное применение отвергнуто: %v", err)
	}
	if rep.Written != 0 || rep.Unchanged != 1 {
		t.Fatalf("повторное применение записало %d при объявленных %d — повторный прогон "+
			"есть ШТАТНЫЙ режим применителя, а не край: %s", rep.Written, rep.Declared, rep)
	}
}

// TestMODRD14RuleEditIsBroughtOverWithoutChangingTheID — MOD-RD-14 и MOD-RD-08:
// правило приведено, `id` не изменился, а значит выдачи целы.
func TestMODRD14RuleEditIsBroughtOverWithoutChangingTheID(t *testing.T) {
	store := newStore()
	ap := moduleroles.NewApplier(store)
	if _, err := ap.Apply(context.Background(), vpcManifest(t, "vpc.network.admin", "get")); err != nil {
		t.Fatalf("первое применение отвергнуто: %v", err)
	}
	id := domain.SystemRoleID("vpc.network.admin")
	before := store.rows[id]

	rep, err := ap.Apply(context.Background(), vpcManifest(t, "vpc.network.admin", "list"))
	if err != nil {
		t.Fatalf("применение правки отвергнуто: %v", err)
	}
	if rep.Written != 1 {
		t.Fatalf("правка правила не доехала до строки: %s", rep)
	}
	after, ok := store.rows[id]
	if !ok {
		t.Fatalf("после правки строка под прежним id пропала — выдачи перестали бы " +
			"резолвиться, оставаясь синтаксически верными")
	}
	if after.ID != before.ID {
		t.Fatalf("идентификатор изменился: %q → %q", before.ID, after.ID)
	}
	if len(store.rows) != 1 {
		t.Errorf("правка правила завела ВТОРУЮ строку: %v", store.rows)
	}
	if got := store.refs[id]; len(got) != 1 || got[0].Verb != "list" {
		t.Errorf("проекция сегментов не приведена вместе с правилом: %v", got)
	}
}

// TestMODRD09ARenamedRoleIsADifferentRole — MOD-RD-09: имя, отличающееся хотя
// бы символом, есть ДРУГАЯ роль, и старая строка цела.
func TestMODRD09ARenamedRoleIsADifferentRole(t *testing.T) {
	store := newStore()
	ap := moduleroles.NewApplier(store)
	if _, err := ap.Apply(context.Background(), vpcManifest(t, "vpc.network.admin", "get")); err != nil {
		t.Fatalf("первое применение отвергнуто: %v", err)
	}
	if _, err := ap.Apply(context.Background(), vpcManifest(t, "vpc.network.admins", "get")); err != nil {
		t.Fatalf("применение переименованной отвергнуто: %v", err)
	}
	if _, ok := store.rows[domain.SystemRoleID("vpc.network.admin")]; !ok {
		t.Errorf("прежняя строка исчезла — применитель принял переименование за правку")
	}
	if _, ok := store.rows[domain.SystemRoleID("vpc.network.admins")]; !ok {
		t.Errorf("новая строка не заведена")
	}
}

// TestMODRD15AForeignTierOrModuleNeverReachesTheWriter — применитель пишет
// ТОЛЬКО кластерные роли своего модуля. Роль яруса аккаунта уезжает своим путём
// (RoleService.Create), и её строка кластерным писателем не производится.
func TestMODRD15AForeignTierOrModuleNeverReachesTheWriter(t *testing.T) {
	doc := "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: vpc.viewer\n    description: Читает сети модуля.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - {module: vpc, resources: [network], classes: [get]}\n"
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("фикстура отвергнута: %v", err)
	}
	store := newStore()
	rep, err := moduleroles.NewApplier(store).Apply(context.Background(), m)
	if err != nil {
		t.Fatalf("применение отвергнуто: %v", err)
	}
	if store.calls != 0 {
		t.Errorf("писатель кластерной строки позван на роли яруса проекта: вызовов %d", store.calls)
	}
	if rep.Declared != 0 || rep.Skipped != 1 {
		t.Errorf("перепись не различает ярусов: %s", rep)
	}
}

// TestApplierRefusesARoleThatTheDomainRejects — самопроверяющийся домен: роль,
// негодная по имени или правилу, до писателя не доходит, а отказ называет её.
func TestApplierRefusesARoleThatTheDomainRejects(t *testing.T) {
	// Правило называет модуль вне закрытого набора платформы.
	doc := "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: vpc.network.admin\n" +
		"    description: Распоряжается сетями модуля.\n" +
		"    tier: {tierType: iam.cluster, tierId: cluster_kacho_root}\n" +
		"    rules:\n      - {module: vpc, resources: [network], classes: [get]}\n"
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("фикстура отвергнута: %v", err)
	}
	// Портим уже разобранное: форму манифеста это не проверяет, а домен — да.
	m.Roles[0].Rules[0].Classes = []string{"НЕ-ЛАТИНСКИЙ"}

	store := newStore()
	_, err = moduleroles.NewApplier(store).Apply(context.Background(), m)
	if err == nil {
		t.Fatalf("роль, негодная по домену, записана")
	}
	if !errors.Is(err, moduleroles.ErrRoleRejectedByDomain) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if !strings.Contains(err.Error(), "vpc.network.admin") {
		t.Errorf("отказ не называет роль: %v", err)
	}
	if store.calls != 0 {
		t.Errorf("негодная роль дошла до писателя: вызовов %d", store.calls)
	}
}
