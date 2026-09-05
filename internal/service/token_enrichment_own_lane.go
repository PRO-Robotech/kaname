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
// Прежняя резолвит строку по ЗЕРКАЛЬНОМУ значению — идентификатору клиента во
// внешнем сервере, потому что именно его прежний провайдер кладёт субъектом
// выпускаемого токена. Наш путь резолвит по НАШЕМУ идентификатору: зеркальное
// значение на пути разрешения клиента не участвует вовсе.
//
// Значением утверждения зеркало при этом остаётся — и это не противоречие, а
// разные роли одного поля. «По чему мы НАХОДИМ строку» и «что мы КЛАДЁМ в
// токен» — разные вопросы: первый решает, кого мы аутентифицировали, второй
// обязан дать тот же состав, что и прежний путь, иначе сверка составов
// невозможна. Роль зеркала как значения истекает вместе с самим внешним
// сервером.
package service

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// TokenEnrichmentOwnClientPort — чтение строки реестра по НАШЕМУ идентификатору.
//
// Отдельный порт, а не расширение прежних: те резолвят по зеркальному значению,
// и добавить сюда метод «по нашему» значило бы дать одному порту два разных
// вопроса — после чего вызывающий рано или поздно задаст не тот.
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
		return s.userTokenClaims(row, user, string(row.OAuthClientID), hookCtx),
			ResolvedPrincipal{Kind: PrincipalUser, UserID: string(row.UserID)}, nil

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
		return s.saClaims(row, sa, string(row.OAuthClientID), hookCtx),
			ResolvedPrincipal{Kind: PrincipalServiceAccount}, nil

	default:
		// Словарь видов клиента ЗАКРЫТ: «прочее» не является корзиной приёма.
		// Вид, заведённый и не разобранный здесь, обязан дать отказ, а не
		// молчаливо пустой состав.
		return nil, ResolvedPrincipal{}, fmt.Errorf("token enrichment: unknown assertion client kind %q", client.Kind)
	}
}
