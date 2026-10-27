// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// public_container_read_multi_subject_integration_test.go — выдача ПЧ
// НЕСКОЛЬКИМ субъектам (PRO-Robotech/kaname#880).
//
// Одна выдача называет перечень субъектов (SC-04 приёмки
// anonymous-and-authenticated-are-subject-classes.md разрешает класс и людей в
// одной выдаче). Ворота класса судят ВЕСЬ перечень, ветвь выдач решения — тоже
// каждого субъекта; разворачивание на потомков контейнера обязано судить так
// же: `public_reader` на X получает КАЖДЫЙ класс выдачи, субъект-не-класс его
// не получает (ND-10), а исход не зависит от порядка субъектов.
//
// Мир — П6 (`public_container_read_world_integration_test.go`). Спрашивают трое:
// аноним, вошедший другого арендатора (usr-C, выдач в acc-A нет) и названный
// выдачей человек (usr-D). Каждый порядок — свой мир: выдачи одного мира
// складывались бы, и проба порядка не отличила бы.

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// pchSubjectsRequest — тело «выдача ПЧ» П6 с перечнем субъектов вместо одного.
func (p *pcrWorld) pchSubjectsRequest(subjects ...*iamv1.Subject) *iamv1.CreateAccessBindingRequest {
	req := p.pchRequest()
	req.Subjects = subjects
	return req
}

// publicReadersOn — субъекты кортежей `public_reader` на реестре id,
// отсортированно.
func (p *pcrWorld) publicReadersOn(id string) []string {
	p.t.Helper()
	rows, err := p.pool.Query(p.ctx,
		`SELECT subject FROM kaname.relation_fact
		  WHERE object_type = $1 AND object_id = $2 AND relation = 'public_reader'`, pcrRegType, id)
	require.NoError(p.t, err, "чтение public_reader")
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		require.NoError(p.t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(p.t, rows.Err())
	sort.Strings(out)
	return out
}

// readers — трое спрашивающих мира: аноним, вошедший другого арендатора,
// названный человек.
func (p *pcrWorld) readers() (anon, signedIn, alice string) {
	return pcrAnon, fmtSubject("user", string(p.usrC)), fmtSubject("user", string(p.usrD))
}

// fourPairs — v_get и v_list на X и на `…/app`.
func fourPairs() []pcrPair {
	return []pcrPair{
		{"v_get", pcrRegType, pcrX}, {"v_list", pcrRegType, pcrX},
		{"v_get", pcrRepoType, pcrXApp}, {"v_list", pcrRepoType, pcrXApp},
	}
}

// TestPublicContainerRead_MultiSubject_EveryClassOfTheGrantReadsTheChildrenInAnyOrder —
// kaname#880: выдача ПЧ нескольким субъектам открывает реестр X и его
// репозиторий одинаково при любом порядке субъектов; `public_reader` на X —
// ровно классы выдачи, человек его не получает.
func TestPublicContainerRead_MultiSubject_EveryClassOfTheGrantReadsTheChildrenInAnyOrder(t *testing.T) {
	cases := []struct {
		name     string
		subjects func(p *pcrWorld) []*iamv1.Subject
		readers  []string // ожидаемые субъекты public_reader на X
	}{
		{"anonymous,authenticated", func(*pcrWorld) []*iamv1.Subject {
			return []*iamv1.Subject{classSubject("anonymous"), classSubject("authenticated")}
		}, []string{"system_class:anonymous", "system_class:authenticated"}},
		{"authenticated,anonymous", func(*pcrWorld) []*iamv1.Subject {
			return []*iamv1.Subject{classSubject("authenticated"), classSubject("anonymous")}
		}, []string{"system_class:anonymous", "system_class:authenticated"}},
		{"user,anonymous", func(p *pcrWorld) []*iamv1.Subject {
			return []*iamv1.Subject{userSubject(p.usrD), classSubject("anonymous")}
		}, []string{"system_class:anonymous"}},
		{"anonymous,user", func(p *pcrWorld) []*iamv1.Subject {
			return []*iamv1.Subject{classSubject("anonymous"), userSubject(p.usrD)}
		}, []string{"system_class:anonymous"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newPCRWorld(t)
			p.deliverNewEdition("kaname#880 " + tc.name)
			anon, signedIn, alice := p.readers()
			// Контроль фикстуры: до выдачи ни один из троих X и `…/app` не читает.
			for _, who := range []string{anon, signedIn, alice} {
				for _, q := range fourPairs() {
					p.requireAsk(who, q.relation, q.modelType, q.id, false, "kaname#880 контроль: до выдачи "+q.String())
				}
			}

			p.createDone(asUser(p.ctx, p.usrA), p.pchSubjectsRequest(tc.subjects(p)...), "kaname#880: выдача ПЧ "+tc.name)
			// Положительный близнец раньше предмета: сам реестр открыт всем —
			// выдача развернулась (ветвь выдач судит каждого субъекта).
			for _, who := range []string{anon, signedIn, alice} {
				p.pollAsk(who, "v_get", pcrRegType, pcrX, true, "kaname#880 "+tc.name+": реестр X открыт")
			}
			// Предмет: репозиторий под X открыт тем же троим при любом порядке.
			for _, who := range []string{anon, signedIn, alice} {
				for _, q := range fourPairs() {
					p.pollAsk(who, q.relation, q.modelType, q.id, true, "kaname#880 "+tc.name+": "+q.String())
				}
			}
			require.Equalf(t, tc.readers, p.publicReadersOn(pcrX),
				"kaname#880 %s: public_reader на X — ровно классы выдачи, независимо от порядка", tc.name)
			require.Equalf(t, []string{}, p.publicReadersOn(pcrY),
				"kaname#880 %s: соседний реестр Y выдачей не охвачен", tc.name)
		})
	}
}

// TestPublicContainerRead_MultiSubject_UserOnlyTwinOpensNothingToTheAnonymous —
// близнец kaname#880: та же выдача ПЧ, но только человеку — анониму и
// вошедшему другого арендатора закрыто, `public_reader` на X нет; человек
// читает X и `…/app` своей ветвью выдач.
func TestPublicContainerRead_MultiSubject_UserOnlyTwinOpensNothingToTheAnonymous(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("kaname#880 близнец [user]")
	anon, signedIn, alice := p.readers()

	p.createDone(asUser(p.ctx, p.usrA), p.pchSubjectsRequest(userSubject(p.usrD)), "kaname#880 близнец: выдача ПЧ человеку")
	for _, q := range fourPairs() {
		p.pollAsk(alice, q.relation, q.modelType, q.id, true, "kaname#880 близнец: человек читает своей ветвью "+q.String())
	}
	for _, who := range []string{anon, signedIn} {
		for _, q := range fourPairs() {
			p.requireAsk(who, q.relation, q.modelType, q.id, false, "kaname#880 близнец: выдача человеку классу не открывает "+q.String())
		}
	}
	require.Equal(t, []string{}, p.publicReadersOn(pcrX), "kaname#880 близнец: человек public_reader не получает (ND-10)")
}

// TestPublicContainerRead_MultiSubject_RevokeClosesForEveryClass — kaname#880:
// снятие выдачи ПЧ [authenticated, anonymous] снимает `public_reader` у ОБОИХ
// классов и закрывает X и `…/app` анониму и вошедшему. Близнец — те же
// вопросы до снятия.
func TestPublicContainerRead_MultiSubject_RevokeClosesForEveryClass(t *testing.T) {
	p := newPCRWorld(t)
	p.deliverNewEdition("kaname#880 снятие")
	anon, signedIn, _ := p.readers()

	id := p.createDone(asUser(p.ctx, p.usrA),
		p.pchSubjectsRequest(classSubject("authenticated"), classSubject("anonymous")), "kaname#880 снятие: выдача ПЧ")
	for _, who := range []string{anon, signedIn} {
		for _, q := range fourPairs() {
			p.pollAsk(who, q.relation, q.modelType, q.id, true, "kaname#880 снятие, близнец до снятия: "+q.String())
		}
	}
	require.Equal(t, []string{"system_class:anonymous", "system_class:authenticated"}, p.publicReadersOn(pcrX),
		"kaname#880 снятие, близнец: public_reader у обоих классов до снятия")

	p.ownerMayRemove("kaname#880 снятие Дано", id)
	op, err := p.ab.Delete(asUser(p.ctx, p.usrA), &iamv1.DeleteAccessBindingRequest{AccessBindingId: id})
	require.NoError(t, err, "kaname#880 снятие: отзыв выдачи ПЧ")
	done := awaitOp(t, p.ctx, p.ops, op.GetId())
	require.Nilf(t, done.Error, "kaname#880 снятие: операция отзыва завершилась ошибкой %+v", done.Error)

	for _, who := range []string{anon, signedIn} {
		for _, q := range fourPairs() {
			p.pollAsk(who, q.relation, q.modelType, q.id, false, "kaname#880 снятие: после отзыва "+q.String())
		}
	}
	require.Equal(t, []string{}, p.publicReadersOn(pcrX), "kaname#880 снятие: public_reader снят у всех классов выдачи")
}
