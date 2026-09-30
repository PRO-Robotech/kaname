// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_enrichment_own_lane.go — вторая точка входа в ОДНО объявление состава
// утверждений (задача #898, приёмка F2 §2.11).
//
// # Почему ВХОД, а не свой состав
//
// Токен принципалу выдавали ДВА пути: обратный вызов прежнего провайдера и наш
// собственный эндпоинт. Пока перечень утверждений и правила их вычисления живут
// у каждого свои, различие между ними НЕ ЯВЛЯЕТСЯ НИЧЬЕЙ НАХОДКОЙ: оно не
// выражено и потому не может покраснеть. Поэтому здесь заведена не вторая
// сборка утверждений, а СПОСОБ ДОЙТИ до единственной: состав собирают
// `userTokenClaims` и `saClaims`.
//
// Обратного вызова провайдера больше нет (kaname#363), и этот вход — один; все
// полосы собственной выдачи идут через него.
//
// # По какому имени читается строка
//
// По НАШЕМУ идентификатору строки из реестра утверждений. С kaname#362 второго
// имени у клиента нет, столбец, где его хранили, снят. Значением утверждения
// `kaname_external_id` на этом пути стоит поэтому идентификатор строки.
package service

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TokenEnrichmentOwnClientPort — чтение строки реестра по НАШЕМУ идентификатору.
//
// Отдельный порт, а не расширение прежних: прежние читают ВЛАДЕЛЬЦА строки
// (служебную учётку, пользователя), а этот — саму строку реестра, уже
// разрешённую проверкой утверждения. Один порт с двумя вопросами рано или
// поздно задал бы не тот.
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
// Состав собирают ОДНИ функции для всех полос собственной выдачи, поэтому
// множества имён и значений у них совпадают для одного и того же принципала.
// Проба сверяет именно МНОЖЕСТВА: проверка «есть поле X» зелена на токене,
// потерявшем поле Y.
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
		if s.userTokens == nil {
			// Владельца нечем прочитать — ОТКАЗ, а не состав без владельца и не
			// паника: чьё состояние не прочитано, того и не судили.
			return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: user-token owner port is not wired")
		}
		row, err := s.ownClients.GetUserToken(ctx, domain.UserOAuthClientID(client.ID))
		if err != nil {
			return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: user-token client: %w", err)
		}
		user, err := s.userTokens.GetUser(ctx, row.UserID)
		if err != nil {
			return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: owner of user-token client: %w", err)
		}
		if !user.InviteStatus.MayAuthenticate() {
			// Состояние владельца читается ЗДЕСЬ, до выпуска: чьё состояние не
			// судили, тому и не выдаём.
			return nil, ResolvedPrincipal{}, ErrSubjectNotActive
		}
		// Принципал — ЦЕЛИКОМ, включая момент выдачи ключа: ключ человека сессии не несёт,
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
