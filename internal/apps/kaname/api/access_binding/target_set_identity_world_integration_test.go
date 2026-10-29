// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// target_set_identity_world_integration_test.go — две цели выдачи с разным
// составом объектов — две разные цели (PRO-Robotech/kaname#1004, приёмка
// docs/engineering/acceptance/access-target-object-id-follows-the-object-grammar.md,
// сценарии ATI-02, ATI-02b, ATI-05).
//
// Повтор действующей выдачи (тот же субъект, роль, область и состав цели)
// отвергается ALREADY_EXISTS. Состав цели сверяется по его записи:
// отсортированные «тип:id» объектов, склеенные переводом строки. Цель из ОДНОГО
// объекта, чей идентификатор дословно несёт разделитель записи и второй
// «тип:id», записалась бы так же, как цель из двух объектов, и выдача на неё
// отвергалась бы как повтор чужой выдачи. Поэтому такой идентификатор
// отвергается синхронно кодом формата по грамматике объекта — той же, что у
// регистрации, — а способ сверки состава не меняется.
//
// Шаги идут в одном мире и при одном «Дано», каждый утверждает исход целиком —
// код, путь (синхронно или Operation.error), текст и число выдач. ATI-05 и
// ATI-02 меряют «одну выдачу» и потому стоят раньше ATI-02b, после которого
// выдач у usr-D две.
//
// Мир — П6 (`newPCRWorld`), те же части, что корень службы.

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// objectIDRefusal — дословный текст отказа ATI-02…04 для позиции i.
func objectIDRefusal(i int) string {
	return fmt.Sprintf("Illegal argument target.resources[%d].id "+
		"(not a valid object id: space, tab, newline, '#' and ':' are not allowed)", i)
}

// activeGrantsOf — число действующих выдач получателя по роли в проекте мира
// (база пробы своя и снимается вместе с ней).
func (p *pcrWorld) activeGrantsOf(user domain.UserID, role domain.RoleID) int {
	p.t.Helper()
	var n int
	require.NoError(p.t, p.pool.QueryRow(p.ctx, `
		SELECT count(*) FROM kaname.access_bindings
		 WHERE subject_id = $1 AND role_id = $2
		   AND resource_type = 'project' AND resource_id = $3
		   AND revoked_at IS NULL`,
		string(user), string(role), string(p.prjA)).Scan(&n))
	return n
}

func TestAccessTarget_DistinctObjectSetsAreDistinctTargets(t *testing.T) {
	w := newPCRWorld(t)
	legit, deeper := slashBase+"/one", slashBase+"/one/two"
	ver := time.Now()
	registerSlashRepo(w, legit, ver)
	registerSlashRepo(w, deeper, ver)
	role := w.seedRole("target_set_identity",
		domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}}})
	ctx := asUser(w.ctx, w.usrA)

	w.createDone(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(legit, deeper)),
		"Дано: выдача usr-D на два объекта")
	require.Equal(t, 1, w.activeGrantsOf(w.usrD, role), "Дано: выдач usr-D по роли и области")

	// ATI-05 — сверка состава прежняя: та же цель в обратном порядке — повтор
	// действующей выдачи, отказ в Operation.error, а не синхронно.
	op, err := w.ab.Create(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(deeper, legit)))
	require.NoError(t, err, "ATI-05: синхронный отказ на повтор цели в обратном порядке")
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.NotNil(t, done.Error, "ATI-05: повтор той же цели в обратном порядке принят — сверка состава не работает")
	assert.Equal(t, int32(codes.AlreadyExists), done.Error.Code, "ATI-05: код Operation.error")
	assert.Equal(t, fmt.Sprintf("these permissions are already granted to %s on project:%s", w.usrD, w.prjA),
		done.Error.Message, "ATI-05: текст Operation.error")
	assert.Equal(t, 1, w.activeGrantsOf(w.usrD, role), "ATI-05: выдач usr-D по роли и области")

	// ATI-02 — один объект, чей идентификатор дословно равен записи состава из
	// двух, отвергнут синхронно кодом формата.
	glued := legit + "\nregistry.repositories:" + deeper
	op, err = w.ab.Create(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(glued)))
	requireSyncRefusal(t, err, codes.InvalidArgument, objectIDRefusal(0), "ATI-02")
	assert.Nil(t, op, "ATI-02: у синхронного отказа Operation не создаётся")
	assert.Equal(t, 1, w.activeGrantsOf(w.usrD, role), "ATI-02: выдач usr-D по роли и области")

	// ATI-02b — близнец ATI-02: тот же вход без хвоста — отдельная цель,
	// сосуществующая с действующей.
	w.createDone(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(legit)), "ATI-02b: выдача usr-D на "+legit)
	assert.Equal(t, 2, w.activeGrantsOf(w.usrD, role), "ATI-02b: выдач usr-D по роли и области")
}
