// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// role_preview_holding.go — ОДИН помощник признака превью роли на все четыре
// места провязки: `Get`/`List` (через целость роли), эхо создания, эхо правки и
// ответ резолвера осиротевших операций (kaname#76, приёмка
// `catalog-consequence-reaches-role-readers.md` §3.2).
//
// Признак — ответ проекции выдач о сегментах роли, тот же вопрос, которым
// считается её целость. Задаётся он в транзакции, описывающей роль: у чтений —
// в транзакции чтения, у эха мутации — в транзакции записи после записи
// проекций (писатель несёт читателя), у резолвера — там, где он читает роль.
// Второй помощник разошёлся бы с этим молча: превью читалось бы по-разному в
// ответах об одной роли.

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// RoleSegmentAnswer — ответ проекции выдач о ролях страницы: сколько
// адресуемых сегментов объявлено у каждой и какие из них не держатся.
type RoleSegmentAnswer struct {
	Declared   map[domain.RoleID]int
	Unresolved map[domain.RoleID][]domain.RoleSegment
}

// Holding — признак превью одной роли из ответа. Перечень ярусных классов
// берётся у владельца набора, а не выписывается здесь.
func (a RoleSegmentAnswer) Holding(id domain.RoleID) domain.PreviewHolding {
	return domain.PreviewHoldingOf(a.Unresolved[id], authzmap.TierOnlyVerbClasses())
}

// AskRoleSegments задаёт проекции выдач ОДИН вопрос о сегментах ролей страницы
// в транзакции `rd`.
//
// Контейнерное действие (kaname#1003) проекции «роль → тип × глагол» не даёт
// by construction: его право — отношение на родителе, и производит его каталог.
// Такой сегмент держится самим объявлением, и спрашивать его у `role_verb` не
// нужно — роль создателя читалась бы деградированной, давая ровно объявленное.
//
// Пустой странице вопрос не задаётся вовсе. Отказ проекции — отказ, а не
// «держится всё»: «не смог прочитать» не есть «отобранного нет».
func AskRoleSegments(ctx context.Context, rd kanamerepo.Reader, facts *catalog.Facts, roles []domain.Role) (RoleSegmentAnswer, error) {
	ans := RoleSegmentAnswer{
		Declared:   make(map[domain.RoleID]int, len(roles)),
		Unresolved: map[domain.RoleID][]domain.RoleSegment{},
	}
	segments := make([]domain.RoleSegment, 0, len(roles))
	for _, r := range roles {
		segs := domain.SegmentsOf(r.ID, r.Rules)
		ans.Declared[r.ID] = len(segs)
		for _, s := range segs {
			if _, ok := facts.ContainerVerb(s.ObjectType, s.Verb); ok {
				continue
			}
			segments = append(segments, s)
		}
	}
	if len(segments) == 0 {
		return ans, nil
	}
	got, err := rd.Roles().UnresolvedSegments(ctx, segments)
	if err != nil {
		return RoleSegmentAnswer{}, MapRepoErr(err)
	}
	ans.Unresolved = got
	return ans, nil
}

// WithPreviewHolding — роль с признаком превью, прочитанным в транзакции `rd`.
// Зовут эхо мутаций и резолвер; чтения получают признак вместе с целостью.
//
// Источник каталога НЕ провязан — отказ, а не роль без признака: перевод такую
// роль всё равно отвергнет, а отказ здесь называет предмет.
func WithPreviewHolding(ctx context.Context, rd kanamerepo.Reader, cat catalog.Source, r domain.Role) (domain.Role, error) {
	if cat == nil {
		return domain.Role{}, status.Error(codes.Internal, "internal error")
	}
	ans, err := AskRoleSegments(ctx, rd, cat.Facts(), []domain.Role{r})
	if err != nil {
		return domain.Role{}, err
	}
	r.Holding = ans.Holding(r.ID)
	return r, nil
}
