// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// scope_grant_authority_cost_test.go — сколько вопросов к хранилищу отношений
// стоит право выдавать на областях действующих выдач (Р2, Р3), и что исходы при
// этом прежние.
//
// Число вопросов — предмет, а не подробность: набор областей растёт с тем, что
// уже выдано, и ничем не ограничен до проверки. Вопрос на область делал цену
// правки роли (и добавления участника в группу) равной числу различных областей;
// здесь она — один вопрос надзора и по партии на тип области.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
)

// sgaCountingDoor — дверь решения с обеими формами вопроса, считающая каждую
// отдельно. Партия с объектами двух типов — ошибка, как у настоящей двери
// (`authzcascade.Client.BatchCheckWithContext`): дублёр не принимает того, на чём
// настоящая отказывает.
type sgaCountingDoor struct {
	mu       sync.Mutex
	admin    map[string]bool // объект «тип:id» → держит `admin`
	batchErr error

	checks      int
	batches     int
	tuples      int
	batchTypes  []string
	askedPerObj map[string]int
}

func newSGACountingDoor() *sgaCountingDoor {
	return &sgaCountingDoor{admin: map[string]bool{}, askedPerObj: map[string]int{}}
}

func (d *sgaCountingDoor) Check(_ context.Context, _, relation, object string) (bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.checks++
	d.askedPerObj[object]++
	return relation == "admin" && d.admin[object], nil
}

func (d *sgaCountingDoor) BatchCheckWithContext(_ context.Context, _, relation string, objects []string,
	_ map[string]any) ([]bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.batches++
	d.tuples += len(objects)
	typ := ""
	for _, o := range objects {
		t, _, _ := strings.Cut(o, ":")
		if typ == "" {
			typ = t
		} else if t != typ {
			return nil, fmt.Errorf("партия несёт два типа объектов (%q и %q)", typ, t)
		}
		d.askedPerObj[o]++
	}
	d.batchTypes = append(d.batchTypes, typ)
	if d.batchErr != nil {
		return nil, d.batchErr
	}
	out := make([]bool, len(objects))
	for i, o := range objects {
		out[i] = relation == "admin" && d.admin[o]
	}
	return out, nil
}

// sgaScopes — области: n проектов, три аккаунта и кластер.
func sgaScopes(nProjects int) []grantScope {
	out := make([]grantScope, 0, nProjects+4)
	for i := 0; i < nProjects; i++ {
		out = append(out, grantScope{resourceType: "project", resourceID: fmt.Sprintf("prj-sga-%03d", i)})
	}
	for i := 0; i < 3; i++ {
		out = append(out, grantScope{resourceType: "account", resourceID: fmt.Sprintf("acc-sga-%d", i)})
	}
	return append(out, grantScope{resourceType: "cluster", resourceID: "cluster_root"})
}

// Цена — один вопрос надзора и по партии на тип области, а не вопрос на область.
// 120 проектов при партии в authzfilter.MaxBatchChecksPerRequest — три партии;
// аккаунты — одна; кластер — одна.
func TestScopeGrantAuthority_RelationQuestionsDoNotGrowWithScopes(t *testing.T) {
	const nProjects = 120
	require.Equal(t, 50, authzfilter.MaxBatchChecksPerRequest,
		"предпосылка: число партий ниже посчитано от размера партии")

	scopes := sgaScopes(nProjects)
	door := newSGACountingDoor()
	for _, s := range scopes {
		door.admin[fgaAdminObject(s.resourceType, s.resourceID)] = true
	}
	a := NewScopeGrantAuthority(nil, door)

	err := a.requireOnScopes(newOwnerContext("usr-sga-caller"), scopes)

	require.NoError(t, err, "ярус admin на каждой области — право выдавать есть")
	assert.Equal(t, 1, door.checks,
		"одиночный вопрос — только надзор администратора облака, один на всю проверку; "+
			"вопрос на область делает цену равной числу областей")
	assert.Equal(t, 3+1+1, door.batches, "партий: проекты 120/50 → 3, аккаунты → 1, кластер → 1")
	assert.Equal(t, len(scopes), door.tuples, "каждая область спрошена, и ровно однажды")
	for obj, n := range door.askedPerObj {
		if strings.HasPrefix(obj, "cluster:") && n == 2 {
			continue // объект кластера спрошен надзором и партией — это разные отношения
		}
		assert.Equalf(t, 1, n, "объект %s спрошен %d раз", obj, n)
	}
}

// Отказ на одной области — та же форма, что отказ без права; владелец аккаунта
// области проходит Путём 1 без вопроса к модели (близнец).
func TestScopeGrantAuthority_DeniedScopeFallsToOwnerAndRefusesOthers(t *testing.T) {
	const owner, acc, prj = "usr-sga-owner", "acc-sga-own", "prj-sga-own"
	scopes := []grantScope{{"account", acc}, {"project", prj}}

	door := newSGACountingDoor()
	door.admin[fgaAdminObject("account", acc)] = true // project — без яруса admin
	repo := newABFakeRepo(owner, acc, prj, "rol-sga", "viewer", nil)
	a := NewScopeGrantAuthority(repo, door)

	err := a.requireOnScopes(newOwnerContext("usr-sga-other"), scopes)
	require.Error(t, err, "не владелец и без яруса admin на prj — отказ")
	assert.Equal(t, authzguard.PermissionDenied().Error(), err.Error(), "отказ побайтово как отказ без права")

	twinDoor := newSGACountingDoor()
	twinDoor.admin[fgaAdminObject("account", acc)] = true
	twin := NewScopeGrantAuthority(repo, twinDoor)
	require.NoError(t, twin.requireOnScopes(newOwnerContext(owner), scopes),
		"близнец: тот же набор, вызывающий — владелец аккаунта проекта")
	assert.Equal(t, 1, twinDoor.checks, "близнец: Путь 1 не задаёт вопроса к модели сверх надзора")
}

// Хранилище отношений не ответило на партию — «спросить не удалось», а не отказ в
// праве: повтор осмыслен.
func TestScopeGrantAuthority_BatchOutageIsUnavailable(t *testing.T) {
	const owner, acc, prj = "usr-sga-owner2", "acc-sga-own2", "prj-sga-own2"
	door := newSGACountingDoor()
	door.batchErr = errors.New("инъекция: хранилище отношений не ответило")
	repo := newABFakeRepo(owner, acc, prj, "rol-sga", "viewer", nil)
	a := NewScopeGrantAuthority(repo, door)

	err := a.requireOnScopes(newOwnerContext("usr-sga-other2"), []grantScope{{"project", prj}})
	require.Error(t, err)
	assert.Equal(t, authzguard.AuthzBackendUnavailable().Error(), err.Error())
	assert.Positive(t, door.batches, "контроль: партия спрошена — инъекция не вакуумна")
}

// Без провязанной двери право даёт только Путь 1 (владелец), как и прежде.
func TestScopeGrantAuthority_UnwiredDoorLeavesOnlyTheOwnerPath(t *testing.T) {
	const owner, acc, prj = "usr-sga-owner3", "acc-sga-own3", "prj-sga-own3"
	repo := newABFakeRepo(owner, acc, prj, "rol-sga", "viewer", nil)
	a := NewScopeGrantAuthority(repo, nil)
	scopes := []grantScope{{"account", acc}, {"project", prj}}

	require.NoError(t, a.requireOnScopes(newOwnerContext(owner), scopes), "владелец — право есть")
	err := a.requireOnScopes(newOwnerContext("usr-sga-other3"), scopes)
	require.Error(t, err)
	assert.Equal(t, authzguard.PermissionDenied().Error(), err.Error())
}
