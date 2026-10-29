// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// class_grants_only_on_containers_integration_test.go — стадия S7: модуль решает
// публичность своих объектов сам (задача PRO-Robotech/kaname#950).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 17, отпечаток d44a9bbbdfef42e5f33d0ded13754ff103a4ae33f7ad6d7695be3865b65f9ae7:
// Р11, посевы П7, «П7 без ключа», П7 с ролями И и «П7 без ключа» с ролями И;
// сценарии SC-78, SC-79, SC-81. Каждая строка «И» и каждый близнец — свой
// случай пробы с кодом и текстом.
//
// # Порядок несущий
//
// П7 строится из П6 (`newPCRWorld`, живость которого доказана его положительным
// контролем) доставкой документа с ключом тем же путём, что старт. Перед
// предметом — контроли фикстуры: близнец без ключа загружается, проекция
// глаголов роли `rol-reg-repo-read` несёт ОБА типа (R1 круга 1 дельты S7), роли
// И и И2 — системные, модуля registry, без правила-якоря. Сломанная фикстура
// краснеет на контроле с именем типа или роли и не выдаёт себя за исход ворот.

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

const (
	s7RepoTgt = "registry.repositories"
	// Тексты отказа ворот S7 — дословно приёмочные (SC-78, SC-81).
	s7TextObjects   = "Module registry admits system class grants on its public read containers only; type registry.repositories is not one"
	s7TextWholeRole = "Module registry admits system class grants on its public read containers only; the whole scope is not one, and role %s covers type registry.repositories"
	// s7TrunkRule — правило кластера ствола (SC-28), дословно.
	s7TrunkRule = "GLOBAL scope requires names or labels selector for non-cluster-admin roles"
	// s7TextAnonymousAllInScope — отказ вида цели SC-24, дословно.
	s7TextAnonymousAllInScope = "Illegal argument target: a grant to system class anonymous names its objects (allInScope is not accepted)"
)

// s7World — П7 (либо «П7 без ключа») одной базы.
type s7World struct {
	*pcrWorld
	keyed          bool
	rolRegRepoRead domain.RoleID
	usrK           domain.UserID // кластерный администратор (только с ролями И)
}

// newS7World — П6, затем доставка документа П7 (keyed) либо П6 (без ключа), с
// ролями И (rolesI) либо без них; затем посев `rol-reg-repo-read` и контроли.
func newS7World(t *testing.T, sc string, keyed, rolesI bool) *s7World {
	t.Helper()
	p := newPCRWorld(t)
	w := &s7World{pcrWorld: p, keyed: keyed}

	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	require.NoError(t, err, "фикстура П6")
	keyless := doc
	_, err = manifest.Load(keyless)
	require.NoError(t, err, "контроль фикстуры П7: близнец без ключа S7 обязан загружаться")
	if keyed {
		doc, err = publicreadfixture.WithClassGrantsKey(keyless)
		require.NoError(t, err, "фикстура П7: ключ S7")
	}

	// ── Предмет S7 начинается здесь ──────────────────────────────────────────
	m, err := manifest.Load(doc)
	if err != nil {
		t.Fatalf("%s: доставка П7 — загрузчик отверг манифест registry с ключом %s (предмета S7 нет): %v",
			sc, publicreadfixture.ClassGrantsKey, err)
	}
	if rolesI {
		// Роли И — строки, доставленные до запрета имён в манифесте модуля
		// (kaname#965): загрузчик их отверг бы, поэтому они дописываются в
		// разобранный документ и уходят применителю напрямую (как ND-05 (б)).
		m.Roles = append(m.Roles, namedRolesI()...)
	}
	p.applyDelivered(sc+": доставка П7", m)
	p.delivered = true

	w.rolRegRepoRead = p.seedRole("pcr_reg_repo_read", domain.Rules{
		{Module: "registry", Resources: []string{"registries", "repositories"}, Verbs: []string{"get", "list"}},
	})
	w.controlRoleCoversBothTypes()
	if rolesI {
		w.controlModuleRoles()
		w.usrK = mustSeedUser(t, p.ctx, p.pool, "s7adm")
		verifyAddresses(t, p.ctx, p.pool)
		_, err := p.pool.Exec(p.ctx, `SELECT kaname.restore_cluster_admin('user', $1)`, string(w.usrK))
		require.NoError(t, err, "посев П7: кластерный администратор usr-K путём SC-28")
		seedLiveHumanSession(t, p.scWorld, w.usrK)
	}
	return w
}

// controlRoleCoversBothTypes — положительный контроль фикстуры по каждому типу
// (R1 круга 1 дельты S7): проекция глаголов `rol-reg-repo-read` несёт пару и
// для реестра, и для репозитория.
func (w *s7World) controlRoleCoversBothTypes() {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `SELECT DISTINCT object_type FROM kaname.role_verb WHERE role_id = $1`, string(w.rolRegRepoRead))
	require.NoError(w.t, err)
	defer rows.Close()
	seen := map[string]bool{}
	for rows.Next() {
		var typ string
		require.NoError(w.t, rows.Scan(&typ))
		seen[typ] = true
	}
	require.NoError(w.t, rows.Err())
	for _, typ := range []string{pcrRegTgt, s7RepoTgt} {
		require.Truef(w.t, seen[typ], "контроль фикстуры П7: в проекции глаголов rol-reg-repo-read нет пары для типа %s (есть %v)", typ, seen)
	}
}

// controlModuleRoles — контроль ролей И, И2 и `registry.reader`: id по формуле,
// роли системные, модуля registry, только чтение; у И и И2 правила-якоря нет.
func (w *s7World) controlModuleRoles() {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() { _ = rd.Rollback(w.ctx) }()
	for _, c := range []struct {
		name, id string
		anchor   bool
	}{
		{publicreadfixture.NamedRoleIName, publicreadfixture.NamedRoleIID, false},
		{publicreadfixture.NamedRoleI2Name, publicreadfixture.NamedRoleI2ID, false},
		{publicreadfixture.ReaderRoleName, publicreadfixture.ReaderRoleID, true},
	} {
		require.Equalf(w.t, domain.RoleID(c.id), domain.SystemRoleID(domain.RoleName(c.name)),
			"контроль фикстуры П7: id роли %s не по формуле", c.name)
		role, err := rd.Roles().Get(w.ctx, domain.RoleID(c.id))
		require.NoErrorf(w.t, err, "контроль фикстуры П7: роли %s (%s) в базе нет", c.name, c.id)
		require.Truef(w.t, role.IsSystem, "контроль фикстуры П7: роль %s не системная", c.name)
		require.Equalf(w.t, "registry", role.OwnerModule, "контроль фикстуры П7: модуль-владелец роли %s", c.name)
		require.Truef(w.t, role.GrantsReadsOnly(), "контроль фикстуры П7: роль %s не только читает", c.name)
		require.Equalf(w.t, c.anchor, role.Rules.HasAnchorRule(), "контроль фикстуры П7: правило-якорь роли %s", c.name)
	}
}

// grantR — тело «выдача Р» с заданными субъектами.
func (w *s7World) grantR(subs ...*iamv1.Subject) *iamv1.CreateAccessBindingRequest {
	return withSubjects(w.grantRequest(classSubject("anonymous"), w.rolRegRepoRead,
		resourcesTarget(&iamv1.ResourceRef{Type: s7RepoTgt, Id: pcrXApp})), subs...)
}

// grantWO — тело «выдача ВО»: роль на всю область кластера, субъект задан.
func grantWO(sub *iamv1.Subject, role string) *iamv1.CreateAccessBindingRequest {
	return &iamv1.CreateAccessBindingRequest{
		Subjects: []*iamv1.Subject{sub}, RoleId: role,
		ScopeType: "iam.cluster", ScopeId: domain.ClusterSingletonID, Target: allInScopeTarget(),
	}
}

func (w *s7World) countOps() int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&n))
	return n
}

func (w *s7World) classGrantsOfRole(role string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `
		SELECT count(*) FROM kaname.access_bindings
		 WHERE subject_type = 'system_class' AND role_id = $1`, role).Scan(&n))
	return n
}

// refusedWithoutOperation — синхронный отказ кодом и текстом дословно; ни
// операции, ни выдачи классу этой ролью отказ не заводит.
func (w *s7World) refusedWithoutOperation(ctx context.Context, req *iamv1.CreateAccessBindingRequest, code codes.Code, text, why string) {
	w.t.Helper()
	ops, grants := w.countOps(), w.classGrantsOfRole(req.GetRoleId())
	_, err := w.ab.Create(ctx, req)
	requireSyncRefusal(w.t, err, code, text, why)
	require.Equalf(w.t, ops, w.countOps(), "%s: отказ создал Operation", why)
	require.Equalf(w.t, grants, w.classGrantsOfRole(req.GetRoleId()), "%s: отказ завёл выдачу классу", why)
}

// TestClassGrantsOnContainers_SC78_ModuleWithKeyRefusesAClassGrantOnAnUndeclaredType — SC-78.
func TestClassGrantsOnContainers_SC78_ModuleWithKeyRefusesAClassGrantOnAnUndeclaredType(t *testing.T) {
	t.Run("Когда_анониму", func(t *testing.T) {
		w := newS7World(t, "SC-78", true, false)
		w.refusedWithoutOperation(asUser(w.ctx, w.usrA), w.grantR(classSubject("anonymous")),
			codes.FailedPrecondition, s7TextObjects, "SC-78")
		w.requireAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, false, "SC-78: чтение репозитория не открыто")
	})
	t.Run("И_второй_класс", func(t *testing.T) {
		w := newS7World(t, "SC-78 И (второй класс)", true, false)
		w.refusedWithoutOperation(asUser(w.ctx, w.usrA), w.grantR(classSubject("authenticated")),
			codes.FailedPrecondition, s7TextObjects, "SC-78 И (второй класс)")
	})
	t.Run("И_класс_рядом_с_человеком", func(t *testing.T) {
		w := newS7World(t, "SC-78 И (класс рядом с человеком)", true, false)
		w.refusedWithoutOperation(asUser(w.ctx, w.usrA), w.grantR(classSubject("anonymous"), userSubject(w.usrD)),
			codes.FailedPrecondition, s7TextObjects, "SC-78 И (класс рядом с человеком)")
	})
	t.Run("И_человеку_отказа_нет", func(t *testing.T) {
		w := newS7World(t, "SC-78 И (человеку отказа нет)", true, false)
		w.createDone(asUser(w.ctx, w.usrA), w.grantR(userSubject(w.usrD)), "SC-78 И (человеку отказа нет)")
	})
	t.Run("И_право_выдавать_раньше", func(t *testing.T) {
		w := newS7World(t, "SC-78 И (право выдавать — раньше)", true, false)
		// Текст SC-20: тот же отправитель без права выдаёт человеку.
		_, humanErr := w.ab.Create(asUser(w.ctx, w.usrB), w.grantR(userSubject(w.usrD)))
		require.Error(t, humanErr, "SC-78 контроль: usr-B без права не выдаёт и человеку")
		require.Equal(t, codes.PermissionDenied, status.Code(humanErr), "SC-78 контроль: код отказа человеку")
		sc20 := status.Convert(humanErr).Message()
		w.refusedWithoutOperation(asUser(w.ctx, w.usrB), w.grantR(classSubject("anonymous")),
			codes.PermissionDenied, sc20, "SC-78 И (право выдавать — раньше)")
		require.NotContains(t, sc20, "Module registry", "SC-78: текст отказа в праве не называет модуль")
		require.NotContains(t, sc20, publicreadfixture.ClassGrantsKey, "SC-78: текст отказа в праве не называет ключ")
	})
	t.Run("И_прочие_модули_не_меняются", func(t *testing.T) {
		w := newS7World(t, "SC-78 И (прочие модули не меняются)", true, false)
		w.createDone(asUser(w.ctx, w.usrA), w.sc01Request(), "SC-78 И (прочие модули не меняются): SC-01 на П7")
	})
	t.Run("И_публикация_модуля_своим_путём", func(t *testing.T) {
		w := newS7World(t, "SC-78 И (публикация модуля — своим путём)", true, false)
		w.registerRepository(pcrY, "pub")
		w.requireAsk(pcrAnon, "v_get", pcrRepoType, pcrYPub, false, "SC-78 И (публикация): без публикации")
		require.NoError(t, w.reg.Register(w.ctx, &iamv1.RegisterResourceRequest{
			SubjectId: "user:*", Relation: "v_get", Object: pcrRepoType + ":" + pcrYPub,
		}), "SC-78 И (публикация): публикация репозитория владельцем")
		w.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrYPub, true, "SC-78 И (публикация): исход SC-67 на П7")
	})
	t.Run("Близнец_без_ключа", func(t *testing.T) {
		w := newS7World(t, "SC-78 близнец (П7 без ключа)", false, false)
		w.createDone(asUser(w.ctx, w.usrA), w.grantR(classSubject("anonymous")), "SC-78 близнец: выдача Р без ключа")
		w.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, true, "SC-78 близнец: выдача открывает чтение репозитория")
	})
}

// TestClassGrantsOnContainers_SC79_ModuleWithKeyAdmitsAClassGrantOnADeclaredContainer — SC-79.
func TestClassGrantsOnContainers_SC79_ModuleWithKeyAdmitsAClassGrantOnADeclaredContainer(t *testing.T) {
	t.Run("Когда_цель_контейнер", func(t *testing.T) {
		w := newS7World(t, "SC-79", true, false)
		req := w.grantRequest(classSubject("anonymous"), w.rolRegRepoRead, pcrXTarget())
		w.createDone(asUser(w.ctx, w.usrA), req, "SC-79: выдача классу на объявленный контейнер")
		w.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, true, "SC-79: реестр X открыт")
		w.requireAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, false, "SC-79: репозиторий X без вложенного правила не открыт")
	})
	t.Run("И_механизм_SC60_при_ключе", func(t *testing.T) {
		w := newS7World(t, "SC-79 И (механизм SC-60)", true, false)
		w.createDone(asUser(w.ctx, w.usrA), w.pchRequest(), "SC-79 И: выдача ПЧ на П7")
		for _, rel := range []string{"v_get", "v_list"} {
			w.pollAsk(pcrAnon, rel, pcrRepoType, pcrXApp, true, "SC-79 И: исход SC-60")
		}
	})
	t.Run("Близнец_отрицательный_SC78", func(t *testing.T) {
		w := newS7World(t, "SC-79 близнец (SC-78)", true, false)
		w.refusedWithoutOperation(asUser(w.ctx, w.usrA), w.grantR(classSubject("anonymous")),
			codes.FailedPrecondition, s7TextObjects, "SC-79 близнец: тип цели не объявлен")
	})
}

// caseOf — случай пробы над ОБЩИМ миром: помощники мира судят случай его же
// `t`, а не `t` пробы, — отказ случая не роняет пробу из чужой горутины.
func (w *s7World) caseOf(t *testing.T, name string, f func(t *testing.T)) {
	t.Run(name, func(st *testing.T) {
		prev := w.scWorld.t
		w.scWorld.t = st
		defer func() { w.scWorld.t = prev }()
		f(st)
	})
}

// TestClassGrantsOnContainers_SC81_ModuleWithKeyRefusesAWholeScopeClassGrantByARoleCoveringAnUndeclaredType — SC-81.
//
// Строки «И» идут над одним миром П7 с ролями И, каждая своим случаем. Порядок
// несущий (N4 круга 2): строка «правило над контейнером» — первая выдача,
// дошедшая до `done`, и исход `Check` для реестра X снят после неё одной.
func TestClassGrantsOnContainers_SC81_ModuleWithKeyRefusesAWholeScopeClassGrantByARoleCoveringAnUndeclaredType(t *testing.T) {
	w := newS7World(t, "SC-81", true, true)

	w.caseOf(t, "Когда_роль_И", func(t *testing.T) {
		w.refusedWithoutOperation(asUser(w.ctx, w.usrK), grantWO(classSubject("authenticated"), publicreadfixture.NamedRoleIID),
			codes.FailedPrecondition, fmt.Sprintf(s7TextWholeRole, publicreadfixture.NamedRoleIID), "SC-81")
	})
	w.caseOf(t, "И_якорь_и_вложенное_правило", func(t *testing.T) {
		w.refusedWithoutOperation(asUser(w.ctx, w.usrK), grantWO(classSubject("authenticated"), publicreadfixture.ReaderRoleID),
			codes.FailedPrecondition, fmt.Sprintf(s7TextWholeRole, publicreadfixture.ReaderRoleID), "SC-81 И (якорь и вложенное правило)")
	})
	w.caseOf(t, "И_правило_над_контейнером", func(t *testing.T) {
		usrC := fmtSubject("user", string(w.usrC))
		w.requireAsk(usrC, "v_get", pcrRegType, pcrX, false, "SC-81 И (правило над контейнером): до выдачи")
		w.createDone(asUser(w.ctx, w.usrK), grantWO(classSubject("authenticated"), publicreadfixture.NamedRoleI2ID),
			"SC-81 И (правило над контейнером)")
		w.pollAsk(usrC, "v_get", pcrRegType, pcrX, true, "SC-81 И (правило над контейнером): реестр X вошедшему")
		w.requireAsk(usrC, "v_get", pcrRepoType, pcrXApp, false, "SC-81 И (правило над контейнером): репозиторий X")
	})
	w.caseOf(t, "И_человеку_отказа_нет", func(t *testing.T) {
		w.createDone(asUser(w.ctx, w.usrK), grantWO(userSubject(w.usrB), publicreadfixture.NamedRoleIID), "SC-81 И (человеку отказа нет)")
	})
	w.caseOf(t, "И_anonymous_прежний_отказ", func(t *testing.T) {
		w.refusedWithoutOperation(asUser(w.ctx, w.usrK), grantWO(classSubject("anonymous"), publicreadfixture.NamedRoleIID),
			codes.InvalidArgument, s7TextAnonymousAllInScope, "SC-81 И (anonymous — прежний отказ)")
	})
	w.caseOf(t, "И_право_выдавать_раньше", func(t *testing.T) {
		// Текст первой строки SC-28, захваченный ответом (N2 круга 2): usr-A
		// выдаёт классу на кластере системную роль чтения сетей.
		_, sc28Err := w.ab.Create(asUser(w.ctx, w.usrA), grantWO(classSubject("authenticated"), scClusterViewRole))
		require.Error(t, sc28Err, "SC-81 контроль: первая строка SC-28")
		require.Equal(t, codes.PermissionDenied, status.Code(sc28Err), "SC-81 контроль: код первой строки SC-28")
		sc28 := status.Convert(sc28Err).Message()
		w.refusedWithoutOperation(asUser(w.ctx, w.usrA), grantWO(classSubject("authenticated"), publicreadfixture.NamedRoleIID),
			codes.PermissionDenied, sc28, "SC-81 И (право выдавать — раньше)")
		for _, leak := range []string{publicreadfixture.NamedRoleIID, "Module registry", publicreadfixture.ClassGrantsKey} {
			require.NotContainsf(t, sc28, leak, "SC-81: текст отказа в праве называет %q", leak)
		}
	})
}

// TestClassGrantsOnContainers_SC81_Twin_KeylessModuleAdmitsTheWholeScopeGrant —
// близнецы SC-81 на «П7 без ключа» с ролями И: выдача ВО принята, строка
// «якорь» получает текст правила кластера. Отличие — один факт: ключ.
func TestClassGrantsOnContainers_SC81_Twin_KeylessModuleAdmitsTheWholeScopeGrant(t *testing.T) {
	w := newS7World(t, "SC-81 близнец («П7 без ключа» с ролями И)", false, true)
	w.caseOf(t, "Близнец_выдача_ВО", func(t *testing.T) {
		w.createDone(asUser(w.ctx, w.usrK), grantWO(classSubject("authenticated"), publicreadfixture.NamedRoleIID),
			"SC-81 близнец: выдача ВО без ключа")
		require.Equal(t, 1, w.classGrantsOfRole(publicreadfixture.NamedRoleIID), "SC-81 близнец: выдача классу ролью И одна")
	})
	w.caseOf(t, "Близнец_строки_якорь", func(t *testing.T) {
		w.refusedWithoutOperation(asUser(w.ctx, w.usrK), grantWO(classSubject("authenticated"), publicreadfixture.ReaderRoleID),
			codes.InvalidArgument, s7TrunkRule, "SC-81 близнец строки «якорь»: правило кластера")
	})
}

// namedRolesI — роли И и И2 приёмки (редакция 17, SC-81) структурой манифеста:
// роли модуля registry яруса кластера, сужённые именами. И — одно правило над
// `repositories` с `resourceNames: [app]`, И2 — одно правило над `registries` с
// `resourceNames: [reg00000000000000001]` (реестр X).
//
// Текстом документа они не доставляются: манифест модуля конкретных объектов
// не называет (kaname#965), и загрузчик такую роль отвергает. Строка такой роли
// остаётся возможной как доставленная до запрета, а ворота S7 судят выдачу ею
// по-прежнему — ровно это и утверждает SC-81.
func namedRolesI() []manifest.Role {
	tier := &manifest.Tier{TierType: "iam.cluster", TierID: "cluster_root"}
	return []manifest.Role{
		{
			ID:          publicreadfixture.NamedRoleIName,
			Description: "Пробная роль S7: чтение репозиториев, сужено именами.",
			Tier:        tier,
			Rules: []manifest.Rule{{
				Module: "registry", Resources: []string{"repositories"}, Classes: []string{"get"},
				ResourceNames: []string{"app"},
			}},
		},
		{
			ID:          publicreadfixture.NamedRoleI2Name,
			Description: "Пробная роль S7: чтение реестра X, сужено именами.",
			Tier:        tier,
			Rules: []manifest.Rule{{
				Module: "registry", Resources: []string{"registries"}, Classes: []string{"get"},
				ResourceNames: []string{pcrX},
			}},
		},
	}
}
