// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// slash_object_id_world_integration_test.go — идентификатор объекта модуля с
// `/` проходит регистрацию, цель выдачи и вопрос о доступе ОДНОЗНАЧНО
// (PRO-Robotech/kaname#1004).
//
// Объекты модуля registry адресуются идентификатором с `/` (репозиторий под
// реестром). Грамматика объекта `<type>:<id>` требует одно двоеточие и
// запрещает пробелы и `#`; о `/` она не говорит ничего, и разбор по ней
// держится на одном свойстве: идентификатор НЕПРОЗРАЧЕН — kaname его не
// режет, не нормализует и не раскодирует. Пробы ниже мерят это свойство на
// всех трёх частях сразу, теми же частями, что корень службы (мир П6,
// `newPCRWorld`): регистрация (`InternalIAMService.RegisterResource`), выдача
// (`AccessBindingService.Create` с целью «названные объекты»), решение
// (`AuthorizeService.Check` и `InternalIAMService.Check`).
//
// Границы `/` — пустой сегмент (начальный, конечный, двойной), лишний сегмент,
// экранированный разделитель (`%2F`, `\/`) — каждая регистрируется как СВОЙ
// объект: два разных входа не дают одного объекта, выдача на один не открывает
// другой ни в одну сторону. Отказ на такой границе — решение грамматики
// владельца объекта (служба registry), а не посредника: посредник, режущий или
// склеивающий сегменты, и сделал бы два входа одним объектом.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Реестр-основа проб: не X и не Y мира П6, чтобы чужие регистрации мира не
// попадали в сверку числа строк.
const slashBase = "reg0000000000000s1a9"

// slashInputs — законный идентификатор и его границы по `/`. Ключ — имя
// границы в тексте отказа, значение — идентификатор дословно.
func slashInputs() []struct{ name, id string } {
	return []struct{ name, id string }{
		{"законный", slashBase + "/one"},
		{"лишний сегмент", slashBase + "/one/two"},
		{"пустой конечный сегмент", slashBase + "/one/"},
		{"пустой двойной сегмент", slashBase + "//one"},
		{"пустой начальный сегмент", "/" + slashBase + "/one"},
		{"экранированный разделитель %2F", slashBase + "%2Fone"},
		{"экранированный разделитель \\/", slashBase + `\/one`},
	}
}

// registerSlashRepo — регистрация объекта службой-владельцем с цепью
// `[project, account]`, как в задаче; владелец объекта — usr-A.
func registerSlashRepo(w *pcrWorld, id string, ver time.Time) {
	w.t.Helper()
	req := &iamv1.RegisterResourceRequest{
		SubjectId:       "user:" + string(w.usrA),
		Relation:        "owner",
		Object:          pcrRepoType + ":" + id,
		ParentProjectId: string(w.prjA),
		ParentAccountId: string(w.accA),
		ParentChain:     []string{"project:" + string(w.prjA), "account:" + string(w.accA)},
		SourceVersion:   timestamppb.New(ver),
	}
	require.NoErrorf(w.t, w.reg.Register(w.ctx, req), "регистрация %q с цепью [project, account]", id)
}

// parentEdges — цепь объекта, как её хранит решение: (тип, id, глубина).
func parentEdges(w *pcrWorld, id string) [][3]string {
	w.t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT parent_type, parent_id, depth::text FROM kaname.resource_parent_edge
		 WHERE object_type = $1 AND object_id = $2
		 ORDER BY depth`, pcrRepoType, id)
	require.NoError(w.t, err)
	defer rows.Close()
	var out [][3]string
	for rows.Next() {
		var e [3]string
		require.NoError(w.t, rows.Scan(&e[0], &e[1], &e[2]))
		out = append(out, e)
	}
	require.NoError(w.t, rows.Err())
	return out
}

func repoTarget(ids ...string) *iamv1.AccessTarget {
	refs := make([]*iamv1.ResourceRef, 0, len(ids))
	for _, id := range ids {
		refs = append(refs, &iamv1.ResourceRef{Type: "registry.repositories", Id: id})
	}
	return resourcesTarget(refs...)
}

// TestSlashObjectID_RegistrationGrantAndCheckAreVerbatim — законный
// идентификатор с `/` регистрируется с переданной цепью, на него выдаётся роль,
// вопрос о доступе по нему отвечает «да»; каждая граница `/` — свой объект, и
// выдача на один не открывает ни одного другого ни в одну сторону.
func TestSlashObjectID_RegistrationGrantAndCheckAreVerbatim(t *testing.T) {
	w := newPCRWorld(t)
	in := slashInputs()
	legit, deeper := in[0].id, in[1].id
	ver := time.Now()

	for _, c := range in {
		registerSlashRepo(w, c.id, ver)
	}

	// Регистрация: строка зеркала на каждый вход дословно, и строк ровно столько,
	// сколько входов, — склейка двух входов в один объект уменьшила бы число.
	all := make([]string, 0, len(in))
	for _, c := range in {
		all = append(all, c.id)
		var n int
		require.NoError(t, w.pool.QueryRow(w.ctx,
			`SELECT count(*) FROM kaname.resource_mirror WHERE object_type = 'registry.repositories' AND object_id = $1`,
			c.id).Scan(&n))
		assert.Equalf(t, 1, n, "%s: строка зеркала для %q не одна", c.name, c.id)
	}
	var distinct int
	require.NoError(t, w.pool.QueryRow(w.ctx,
		`SELECT count(DISTINCT object_id) FROM kaname.resource_mirror
		  WHERE object_type = 'registry.repositories' AND object_id = ANY($1)`, all).Scan(&distinct))
	assert.Equal(t, len(in), distinct, "два разных входа дали один объект зеркала")

	// Цепь читается та, что передана: [project, account] с глубинами 1, 2.
	wantChain := [][3]string{{"project", string(w.prjA), "1"}, {"account", string(w.accA), "2"}}
	for _, c := range in {
		assert.Equalf(t, wantChain, parentEdges(w, c.id), "%s: цепь %q не та, что передана", c.name, c.id)
	}

	role := w.seedRole("slash_repo_get",
		domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}}})

	// Выдача usr-B на законный идентификатор: положительный контроль, без него
	// «нет» на границах ниже ничего не различало бы.
	w.createDone(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrB), role, repoTarget(legit)),
		"выдача usr-B на "+legit)
	usrB := fmtSubject("user", string(w.usrB))
	w.pollAsk(usrB, "v_get", pcrRepoType, legit, true, "выдача на идентификатор с `/` материализуется")
	assert.True(t, w.askInternal(usrB, "v_get", pcrRepoType, legit),
		"InternalIAMService.Check разбирает объект с `/` не так, как AuthorizeService.Check")

	for _, c := range in[1:] {
		assert.Falsef(t, w.ask(usrB, "v_get", pcrRepoType, c.id),
			"%s: выдача на %q открыла %q", c.name, legit, c.id)
		assert.Falsef(t, w.askInternal(usrB, "v_get", pcrRepoType, c.id),
			"%s: выдача на %q открыла %q (внутренний вопрос)", c.name, legit, c.id)
	}
	// Префикс до `/` — не объект и не предок: выдача на репозиторий не открывает
	// одноимённого с реестром идентификатора.
	assert.False(t, w.ask(usrB, "v_get", pcrRepoType, slashBase), "выдача на репозиторий открыла префикс до `/`")

	// Обратная сторона: выдача usr-D на объект с лишним сегментом не открывает
	// законный, лежащий «выше» по написанию.
	usrD := fmtSubject("user", string(w.usrD))
	w.createDone(asUser(w.ctx, w.usrA), w.grantRequest(userSubject(w.usrD), role, repoTarget(deeper)),
		"выдача usr-D на "+deeper)
	w.pollAsk(usrD, "v_get", pcrRepoType, deeper, true, "выдача на объект с лишним сегментом материализуется")
	assert.False(t, w.ask(usrD, "v_get", pcrRepoType, legit),
		"выдача на объект с лишним сегментом открыла объект короче по написанию")
}

// TestSlashObjectID_TargetSetsDifferAsInputsDiffer — две цели выдачи с разным
// составом объектов — две разные цели: выдача на {one, one/two} не отвергается
// как повтор выдачи на один объект, чей идентификатор несёт разделитель записи
// состава. Положительный контроль — повтор той же цели отвергается.
func TestSlashObjectID_TargetSetsDifferAsInputsDiffer(t *testing.T) {
	w := newPCRWorld(t)
	in := slashInputs()
	legit, deeper := in[0].id, in[1].id
	role := w.seedRole("slash_repo_get_set",
		domain.Rules{{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get"}}})
	ctx := asUser(w.ctx, w.usrA)

	w.createDone(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(legit, deeper)),
		"выдача usr-D на два объекта")

	// Контроль: та же цель повторно — повтор действующей выдачи.
	op, err := w.ab.Create(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(deeper, legit)))
	if err == nil {
		done := awaitOp(t, w.ctx, w.ops, op.GetId())
		require.NotNil(t, done.Error, "контроль: повтор той же цели (в другом порядке) принят — сверка состава не работает")
	}

	// Предмет: один объект, чей идентификатор дословно равен записи состава из двух.
	glued := legit + "\nregistry.repositories:" + deeper
	op, err = w.ab.Create(ctx, w.grantRequest(userSubject(w.usrD), role, repoTarget(glued)))
	if err != nil {
		// Синхронный отказ входу вне грамматики объекта — тоже однозначный исход,
		// если он назван кодом формата.
		require.Equalf(t, codes.InvalidArgument, status.Code(err), "отказ цели %q не кодом формата: %v", glued, err)
		return
	}
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	assert.Nilf(t, done.Error,
		"цель из одного объекта %q отвергнута как повтор цели {%q, %q}: %v", glued, legit, deeper, done.Error)
}
