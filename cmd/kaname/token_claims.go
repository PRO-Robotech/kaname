// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claims.go — ОДНА сборка состава утверждений для всех полос выдачи,
// чеканящих своим подписантом (задача #1119).
//
// # Почему это отдельная функция, а не по копии у каждой полосы
//
// Полос, выпускающих токен НАШИМ подписантом, стало больше одной: токен-эндпоинт
// платформы и бутстрап-удостоверение. Пока сборка состава стоит по копии у
// каждой, различие между ними НЕ ЯВЛЯЕТСЯ НИЧЬЕЙ НАХОДКОЙ: оно не выражено и
// потому не может покраснеть, а разойдутся копии у ПРИНЦИПАЛА — чей токен выдан
// не той полосой.
package main

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// newAssertionClaimsComposer собирает состав утверждений ОДНИМИ функциями для
// всех полос выдачи: перечень и правила объявлены один раз, и правка любого из
// них доезжает до всех полос by construction.
func newAssertionClaimsComposer(pool *pgxpool.Pool, cfg config.Config) *service.TokenEnrichmentService {
	users := kanamepg.NewUserPoolRepo(pool)
	saClients := kanamepg.NewSAOAuthClientRepo(pool)
	userClients := kanamepg.NewUserOAuthClientRepo(pool)

	return service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: cfg.AuthN.ResolveDomain()},
	).
		WithSAPort(&tokenEnrichSAAdapter{saClients: saClients}).
		WithUserTokenPort(&tokenEnrichUserTokenAdapter{users: users}).
		// Резолв по НАШЕМУ идентификатору строки — единственному имени клиента
		// (kaname#362).
		WithOwnClientPort(&ownClientAdapter{userClients: userClients, saClients: saClients})
}

// tokenEnrichSAAdapter — pool-scoped read adapter for
// service.TokenEnrichmentSAPort: the owning ServiceAccount of a key row, read by
// the SAOAuthClient pool repo.
//
// The ServiceAccount read used to be a query written out in the composition
// root instead. Living there, it was reachable by no test, and it selected only
// the identity fields — so `enabled` arrived false for every account and the
// mint path could not have judged the state even if it had tried to.
//
// The adapter lived next to the hooks of the external identity provider, its
// first reader, and also resolved a key by its client id and by an external
// subject for them; the hooks are gone (kaname#363), and so are both lookups.
type tokenEnrichSAAdapter struct {
	saClients *kanamepg.SAOAuthClientRepo
}

func (a *tokenEnrichSAAdapter) GetServiceAccount(ctx context.Context, id domain.ServiceAccountID) (domain.ServiceAccount, error) {
	return a.saClients.GetServiceAccount(ctx, id)
}

// tokenEnrichUserTokenAdapter — pool-scoped read adapter for
// service.TokenEnrichmentUserTokenPort: чтение владельца личного access-токена,
// чьё состояние полоса судит до выпуска.
type tokenEnrichUserTokenAdapter struct {
	users *kanamepg.UserPoolRepo
}

func (a *tokenEnrichUserTokenAdapter) GetUser(ctx context.Context, id domain.UserID) (domain.User, error) {
	return a.users.GetByID(ctx, id)
}
