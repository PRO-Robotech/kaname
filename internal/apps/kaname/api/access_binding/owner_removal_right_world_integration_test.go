// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// owner_removal_right_world_integration_test.go — право владельца снимать выдачи в
// мирах на основе П1 (`newSCWorld`).
//
// # Почему это понадобилось
//
// До PRO-Robotech/kaname#986 отзыв и удаление выдачи судила ДВЕРЬ слушателя
// (`v_delete` на объекте выдачи), а обработчик спрашивал только право выдавать на
// области. Пробы, зовущие use-case мимо двери, видели лишь вторую половину, и
// владелец снимал выдачи в мире, где у него НЕТ авто-выдачи владельца: посев
// кладёт аккаунт строкой, мимо `AccountService.Create`, которая её заводит.
//
// С задачи вопрос двери переехал в обработчик дословно (Р1а приёмки делегированных
// выдач), и мир обязан нести то, что несёт продукт: авто-выдачу роли `owner` на
// аккаунте (её пообъектные права и дают `v_delete` на объектах выдач) и указатель
// проекта на аккаунт строкой журнала — продукт со-коммитит его с проектом
// (`ProjectService.Create`), посев проекта мимо глагола его не кладёт, и без него
// пообъектные права аккаунта на объекты выдач проекта не выводятся. Это фикстура
// не снисходительнее продукта, а не послабление: проба по-прежнему требует, чтобы
// владелец ДЕРЖАЛ отношение удаления, — она лишь перестаёт судить мир, которого не
// бывает.

import (
	"time"

	"github.com/stretchr/testify/require"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ownerMayRemove — авто-выдача владельца usr-A (единожды на мир) и опрос, пока у
// usr-A не материализуется отношение удаления на каждой названной выдаче.
func (w *scWorld) ownerMayRemove(why string, bindingIDs ...string) {
	w.t.Helper()
	if !w.ownerSeeded {
		w.ownerSeeded = true
		_, err := w.pool.Exec(w.ctx, `
			INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
			VALUES ('fga.tuple.write', jsonb_build_object('user', $1::text, 'relation', 'account', 'object', $2::text), now())`,
			"account:"+string(w.accA), "project:"+string(w.prjA))
		require.NoErrorf(w.t, err, "%s: указатель проекта на аккаунт", why)
		w.createDone(asUser(w.ctx, w.usrA), &iamv1.CreateAccessBindingRequest{
			Subjects:  []*iamv1.Subject{userSubject(w.usrA)},
			RoleId:    domain.OwnerRoleID,
			ScopeType: "iam.account",
			ScopeId:   string(w.accA),
			Target:    allInScopeTarget(),
		}, why+": авто-выдача владельца")
	}
	subject := "user:" + string(w.usrA)
	for _, id := range bindingIDs {
		object := accessbindingapp.RemovalObjectType + ":" + id
		deadline := time.Now().Add(30 * time.Second)
		for {
			ok, err := w.door.Check(w.ctx, subject, accessbindingapp.RemovalRelation, object)
			require.NoErrorf(w.t, err, "%s: модель не ответила о %s", why, object)
			if ok {
				break
			}
			if time.Now().After(deadline) {
				w.t.Fatalf("%s: у владельца %s за 30 с не материализовалось %s на %s",
					why, w.usrA, accessbindingapp.RemovalRelation, object)
			}
			time.Sleep(200 * time.Millisecond)
		}
	}
}
