// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package membership

// get.go — GetMembershipUseCase: одно членство НАЗВАННОГО аккаунта.

import (
	"context"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

type GetMembershipUseCase struct{ repo Repo }

func NewGetMembershipUseCase(r Repo) *GetMembershipUseCase { return &GetMembershipUseCase{repo: r} }

// Execute — аккаунт и идентификатор членства оба уходят в УСЛОВИЕ ОТБОРА.
//
// Отсюда полоса ответа: членство ЧУЖОГО аккаунта отвечает тем же отсутствием и
// тем же текстом, что и несуществующее. Это не сокрытие поверх найденного —
// запрос такую строку не выбирает вовсе.
func (u *GetMembershipUseCase) Execute(
	ctx context.Context, accountID domain.AccountID, id domain.MembershipID,
) (domain.Membership, error) {
	// ФОРМА — ПЕРВЫМИ СТЕЙТМЕНТАМИ, до открытия чтения и до любого запроса.
	//
	// Аккаунт судится СВОИМ валидатором (он own-owned, форма его известна), а
	// членство — платформенным маршрутизатором, и это разные вещи:
	// `corevalidate.ResourceID` FAMILY-AGNOSTIC по контракту, поэтому чужой
	// ОБЪЯВЛЕННЫЙ префикс форму ПРОХОДИТ и уходит в полосу отсутствия. Так и
	// надо: терминальный отказ формы на строке, которая в этом дереве является
	// законным идентификатором, солгал бы вызывающему о его же ресурсе.
	if err := shared.ValidateResourceID(string(accountID), domain.PrefixAccount, "account"); err != nil {
		return domain.Membership{}, err
	}
	// Префикс берётся ИМЕНОВАННОЙ КОНСТАНТОЙ платформенного каталога, а не
	// литералом: каталог и есть единственное место, где эта форма объявлена, и
	// зеркалить её сюда значило бы завести второе.
	if err := corevalidate.ResourceID("membership", ids.PrefixMembershipHyphen, string(id)); err != nil {
		return domain.Membership{}, err
	}

	rd, closeFn, err := readerOf(ctx, u.repo)
	if err != nil {
		return domain.Membership{}, shared.MapRepoErr(err)
	}
	defer closeFn()

	m, err := rd.Get(ctx, accountID, id)
	if err != nil {
		return domain.Membership{}, shared.MapRepoErr(err)
	}
	return m, nil
}
