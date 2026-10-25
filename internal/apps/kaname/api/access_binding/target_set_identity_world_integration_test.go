// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// target_set_identity_world_integration_test.go — две цели выдачи с разным
// составом объектов — две разные цели (находка PRO-Robotech/kaname#1004).
//
// Повтор действующей выдачи (тот же субъект, роль, область и состав цели)
// отвергается ALREADY_EXISTS. Состав цели сверяется не сам, а по его записи:
// отсортированные «тип:id» объектов, склеенные переводом строки. Идентификатор
// объекта цели грамматикой объекта не проверяется — пустым он быть не может, а
// пробел, перевод строки, `#` и двоеточие проходят. Поэтому цель из ОДНОГО
// объекта, чей идентификатор дословно несёт разделитель записи и второй
// «тип:id», записывается так же, как цель из двух объектов, и выдача на неё
// отвергается как повтор чужой выдачи. Два разных входа дают одну цель.
//
// Исход, который проба принимает: такой идентификатор отвергнут синхронно кодом
// формата (грамматика объекта — та же, что у регистрации), либо выдача на него
// принята как отдельная цель. Отказ «уже выдано» — не исход: он называет
// повтором выдачу, которой не было.
//
// Мир — П6 (`newPCRWorld`), те же части, что корень службы.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestAccessTarget_DistinctObjectSetsAreDistinctTargets(t *testing.T) {
	w := newPCRWorld(t)
	in := slashInputs()
	legit, deeper := in[0].id, in[1].id
	role := w.seedRole("target_set_identity",
		domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}}})
	ctx := asUser(w.ctx, w.usrA)

	w.createDone(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(legit, deeper)),
		"выдача usr-D на два объекта")

	// Положительный контроль: та же цель повторно (в другом порядке) — повтор
	// действующей выдачи. Без него «не отвергнуто» ниже ничего не различало бы.
	op, err := w.ab.Create(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(deeper, legit)))
	if err == nil {
		done := awaitOp(t, w.ctx, w.ops, op.GetId())
		require.NotNil(t, done.Error, "контроль: повтор той же цели (в другом порядке) принят — сверка состава не работает")
	}

	// Предмет: один объект, чей идентификатор дословно равен записи состава из двух.
	glued := legit + "\nregistry.repositories:" + deeper
	op, err = w.ab.Create(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(glued)))
	if err != nil {
		require.Equalf(t, codes.InvalidArgument, status.Code(err), "отказ цели %q не кодом формата: %v", glued, err)
		return
	}
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	assert.Nilf(t, done.Error,
		"цель из одного объекта %q отвергнута как повтор цели {%q, %q}: %v", glued, legit, deeper, done.Error)
}
