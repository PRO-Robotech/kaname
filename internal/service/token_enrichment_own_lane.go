// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_enrichment_own_lane.go — вторая точка входа в ОДНО объявление состава
// утверждений (задача #898, приёмка F2 §2.11).
//
// # Почему второй ВХОД, а не второй состав
//
// С этой фазы токен принципалу выдают ДВА пути: обратный вызов прежнего
// провайдера, пока он жив, и наш собственный эндпоинт. Пока перечень утверждений
// и правила их вычисления живут у каждого свои, различие между ними НЕ ЯВЛЯЕТСЯ
// НИЧЬЕЙ НАХОДКОЙ: оно не выражено и потому не может покраснеть. Первая же
// правка одной стороны разойдётся с другой молча — и разойдётся у ПРИНЦИПАЛА,
// чей токен выдан не тем путём.
//
// Поэтому здесь заводится не вторая сборка утверждений, а второй СПОСОБ ДОЙТИ
// до той же: состав по-прежнему собирают `userTokenClaims` и `saClaims`, и
// правка любого из них доезжает до обеих сторон by construction.
//
// # Чем эта точка входа отличается от прежней
//
// Прежняя резолвит строку по имени клиента, которое прежний провайдер кладёт
// субъектом выпускаемого токена; наш путь — по НАШЕМУ идентификатору строки из
// реестра утверждений. С kaname#362 это одно и то же значение: второго имени у
// клиента нет, столбец, где его хранили, снят. Значением утверждения
// `kaname_external_id` на этом пути стоит поэтому идентификатор строки — тот
// же, что прежний путь получает субъектом.
package service

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TokenEnrichmentOwnClientPort — чтение строки реестра по НАШЕМУ идентификатору.
//
// Отдельный порт, а не расширение прежних: прежний резолвит ключ служебной
// учётки как КЛИЕНТА ОБМЕНА (только виды, обмениваемые клиентом), а этот читает
// строку реестра, уже разрешённую проверкой утверждения. Один порт с двумя
// вопросами рано или поздно задал бы не тот.
type TokenEnrichmentOwnClientPort interface {
	// GetUserToken читает клиента пользовательского токена по нашему id.
	GetUserToken(ctx context.Context, id domain.UserOAuthClientID) (domain.UserOAuthClient, error)
	// GetSAKey читает клиента ключа служебной учётки по нашему id.
	GetSAKey(ctx context.Context, id domain.SAOAuthClientID) (domain.ServiceAccountOAuthClient, error)
}

// WithOwnClientPort провязывает чтение по нашему идентификатору.
func (s *TokenEnrichmentService) WithOwnClientPort(p TokenEnrichmentOwnClientPort) *TokenEnrichmentService {
	s.ownClients = p
	return s
}

// ClaimsForAssertionClient собирает утверждения для клиента, аутентифицировавшего
// себя подписанным утверждением.
//
// Состав собирают ТЕ ЖЕ функции, что и на пути обратного вызова, поэтому
// множества имён и значений у обоих путей совпадают для одного и того же
// принципала. Проба сверяет именно МНОЖЕСТВА: проверка «есть поле X» зелена на
// токене, потерявшем поле Y.
func (s *TokenEnrichmentService) ClaimsForAssertionClient(
	ctx context.Context, client domain.AssertionClient, hookCtx TokenHookContext,
) (map[string]any, ResolvedPrincipal, error) {
	if s.ownClients == nil {
		// Ненастроенный порт — ОТКАЗ, а не пустой состав. Токен с пустым
		// составом утверждений выглядит выданным и не несёт принципала: край
		// принял бы его и не нашёл, за кого он говорит.
		return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: own-client port is not wired")
	}

	switch client.Kind {
	case domain.AssertionClientUser:
		row, err := s.ownClients.GetUserToken(ctx, domain.UserOAuthClientID(client.ID))
		if err != nil {
			return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: user-token client: %w", err)
		}
		user, err := s.userTokens.GetUser(ctx, row.UserID)
		if err != nil {
			return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: owner of user-token client: %w", err)
		}
		if !user.InviteStatus.MayAuthenticate() {
			// Состояние владельца читается ЗДЕСЬ так же, как на прежнем пути:
			// иначе один и тот же принципал получал бы токен одним путём и не
			// получал другим.
			return nil, ResolvedPrincipal{}, ErrSubjectNotActive
		}
		// Принципал — тот же, что разрешает прежний путь по той же строке,
		// ЦЕЛИКОМ, включая момент выдачи ключа: ключ человека сессии не несёт,
		// и его полномочие считается от собственной выдачи. По этому моменту
		// вызывающий судит отсечку отзыва-всех владельца — принципал без него
		// оставил бы правило без входа на одной из полос.
		issued := row.CreatedAt
		return s.userTokenClaims(row, user, string(row.ID), hookCtx),
			ResolvedPrincipal{
				Kind:                       PrincipalUser,
				UserID:                     string(row.UserID),
				StandingCredentialIssuedAt: &issued,
			}, nil

	case domain.AssertionClientServiceAccount:
		row, err := s.ownClients.GetSAKey(ctx, domain.SAOAuthClientID(client.ID))
		if err != nil {
			return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: sa-key client: %w", err)
		}
		sa, err := s.sas.GetServiceAccount(ctx, row.SvaID)
		if err != nil {
			return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: owner of sa-key client: %w", err)
		}
		if !sa.MayAuthenticate() {
			return nil, ResolvedPrincipal{}, ErrServiceAccountDisabled
		}
		return s.saClaims(row, sa, string(row.ID), hookCtx),
			ResolvedPrincipal{Kind: PrincipalServiceAccount}, nil

	default:
		// Словарь видов клиента ЗАКРЫТ: «прочее» не является корзиной приёма.
		// Вид, заведённый и не разобранный здесь, обязан дать отказ, а не
		// молчаливо пустой состав.
		return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: unknown assertion client kind %q", client.Kind)
	}
}
