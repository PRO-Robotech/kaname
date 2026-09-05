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
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// newAssertionClaimsComposer собирает состав утверждений ТЕМИ ЖЕ функциями, что
// и путь обратного вызова прежнего провайдера: перечень и правила объявлены один
// раз, и правка любого из них доезжает до всех полос by construction.
func newAssertionClaimsComposer(pool *pgxpool.Pool, cfg config.Config) *service.TokenEnrichmentService {
	users := kachopg.NewUserPoolRepo(pool)
	saClients := kachopg.NewSAOAuthClientRepo(pool)
	userClients := kachopg.NewUserOAuthClientRepo(pool)

	return service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{
			Domain:      cfg.AuthN.ResolveDomain(),
			HydraIssuer: cfg.AuthN.ResolveHydraIssuer(),
		},
		users,
	).
		WithSAPort(&tokenEnrichSAAdapter{saClients: saClients}).
		WithUserTokenPort(&tokenEnrichUserTokenAdapter{userClients: userClients, users: users}).
		// Резолв по НАШЕМУ идентификатору. Зеркальное значение на пути
		// разрешения клиента не участвует вовсе — оно остаётся значением
		// утверждения и истекает вместе с внешним сервером.
		WithOwnClientPort(&ownClientAdapter{userClients: userClients, saClients: saClients})
}
