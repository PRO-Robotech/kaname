// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package ceremonyport

import (
	"context"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// FamilyRevoker — писатель отзыва семейства слоя доступа. Реализует
// `(*pg.OAuthCeremonyRepo).RevokeFamily`.
//
// Контракт, на котором стоит порт отзыва: ставится отметка отзыва семейства
// (один раз — первая причина остаётся), и она доезжает до каждой записи
// выпуска семейства, по которой о нём отвечают поверхности предъявления
// (`tokenrevocation`, kaname#319). Возвращается число строк семейства, которые
// затронула отметка: 1 — отозвано этим вызовом, 0 — уже было отозвано.
type FamilyRevoker interface {
	RevokeFamily(ctx context.Context, familyID string, reason domain.FamilyRevocationReason) (int64, error)
}

// Grants — адаптер порта отзыва гранта.
//
// # Отзыв гранта — это отзыв СЕМЕЙСТВА
//
// Оба метода порта снимают одно и то же: семейство гранта целиком. У службы это
// одно действие — отметка на семействе, от которой производна живость всего, что
// по нему выдано, включая записи выпуска, по которым судит место предъявления.
// Поэтому оба метода зовут один писатель; второй вызов той же операции —
// законные ноль строк отметки.
type Grants struct {
	families FamilyRevoker
}

var _ oauthceremony.GrantRevoker = (*Grants)(nil)

// NewGrants собирает адаптер над писателем отзыва семейства.
func NewGrants(families FamilyRevoker) (*Grants, error) {
	if families == nil {
		return nil, errors.New("ceremonyport: grant revoker needs the family revocation writer")
	}
	return &Grants{families: families}, nil
}

// RevokeGrantRefreshTokens снимает семейство гранта (и с ним все токены
// обновления) по причине церемонии.
func (g *Grants) RevokeGrantRefreshTokens(ctx context.Context, grantID string, reason oauthceremony.RevocationReason) (oauthceremony.StoreOutcome, error) {
	return g.revoke(ctx, grantID, reason)
}

// RevokeGrantAccessTokens снимает семейство гранта (и с ним все токены
// доступа — и в хранилище, и при предъявлении) по причине церемонии.
func (g *Grants) RevokeGrantAccessTokens(ctx context.Context, grantID string, reason oauthceremony.RevocationReason) (oauthceremony.StoreOutcome, error) {
	return g.revoke(ctx, grantID, reason)
}

// revoke — общая часть обоих методов. Вход, который отзывом не является,
// отвергается ДО записи: семейство без ключа и причина без слова службы не
// доходят до писателя.
func (g *Grants) revoke(ctx context.Context, grantID string, reason oauthceremony.RevocationReason) (oauthceremony.StoreOutcome, error) {
	if grantID == "" {
		return oauthceremony.StoreOutcome{}, errors.New("ceremonyport: revocation names no grant; " +
			"a family without a key cannot be revoked")
	}
	word, ok := FamilyReasonOf(reason)
	if !ok {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("ceremonyport: revocation reason %q has no word in the "+
			"closed family vocabulary %v; the family is left as it was", string(reason), domain.FamilyRevocationReasons())
	}
	rows, err := g.families.RevokeFamily(ctx, grantID, word)
	if err != nil {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("ceremonyport: revoke family %s: %w", grantID,
			iamerr.OnEndedCall(ctx, err))
	}
	return oauthceremony.RowsTouched(rows), nil
}

// FamilyReasonOf сопрягает причину церемонии со словом закрытого словаря
// семейств службы — ПО ЗНАЧЕНИЮ, как этого требует фундамент: написание причины
// есть контракт между ними.
//
// Ложь означает, что у причины слова службы нет: либо она вне словаря
// фундамента (в том числе нулевое значение — «причина не названа»), либо
// словарь службы её не знает. Отзыв по такой причине не исполняется — писатель
// отверг бы его ограничением схемы, а подставить другое слово значило бы
// записать в журнал семейства чужое событие.
func FamilyReasonOf(reason oauthceremony.RevocationReason) (domain.FamilyRevocationReason, bool) {
	if !reason.Declared() {
		return "", false
	}
	word := domain.FamilyRevocationReason(reason)
	if word.Validate() != nil {
		return "", false
	}
	return word, true
}

// NewGrantID — крючок чеканки идентификатора гранта
// (`oauthceremony.Config.NewGrantID`): ключ семейства чеканит служба формой,
// которую держит ограничение схемы семейств (`token_families_id_form_ck`,
// `tfm-` и 17 знаков). Форма через дефис — `ids.NewHyphenID`: слитная дала бы
// `tfm<17>`, и схема отвергла бы вставку на каждой выдаче кода.
func NewGrantID(context.Context) (string, error) {
	return ids.NewHyphenID(ids.PrefixTokenFamilyHyphen), nil
}
