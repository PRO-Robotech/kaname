// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// bootstrap_token.go — сборка контура бутстрап-удостоверения (задача #1119,
// Ф4б эпика #896).
//
// # Почему отдельный файл композиционного корня
//
// Контур собирает три части, и у каждой свой отказ: строка соответствия
// бутстрап-клиента, состав утверждений и НАШ подписант. Собранные в теле общего
// пуска, они растворяются среди двух десятков соседних провязок, и первая же
// неполная из них проходит обзор незамеченной.
//
// # Что здесь ГЛАВНОЕ
//
// Ни одного поля, называющего внешнего поставщика. Бутстрап — единственное
// удостоверение, которым кластер поднимают с нуля, и после этой сборки свежий
// клон получает его, не дожидаясь, пока чужая сторона поднимется и узнает наш
// ключ.
package main

import (
	"log/slog"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/bootstrap_token"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/bootstraptokenwire"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// buildBootstrapTokenHandler собирает чеканку бутстрап-удостоверения.
//
// Возвращает ошибку, когда контур ВКЛЮЧЁН (ключ задан), а выпускать нечем:
// «включено, но не работает» здесь не выражается — узналось бы это на первом
// запросе, то есть в момент, когда кластер поднимают и чинить уже поздно.
func buildBootstrapTokenHandler(
	pool *pgxpool.Pool,
	cfg config.Config,
	signer *tokensigner.Signer,
	logger *slog.Logger,
) (*bootstrap_token.Handler, error) {
	// Адресат выпускаемого удостоверения — адресат КРАЯ (https://{API_DOMAIN}).
	// Это решение iam, а не поле запроса: caller-supplied адресат можно задать,
	// но нельзя задать верно, а неверный отвергается краем много позже выдачи.
	audience := os.Getenv("KANAME_BOOTSTRAP_TOKEN_AUDIENCE")
	if audience == "" {
		audience = "https://" + cfg.AuthN.ResolveDomain()
	}

	// Подписант передаётся ИНТЕРФЕЙСОМ, но невключённая чеканка приходит сюда
	// нетипизированным nil: непереданный указатель в интерфейсном поле остался
	// бы «не-nil интерфейсом с nil внутри», и страж полноты в сборке пропустил
	// бы полусобранный контур.
	var ts bootstraptokenwire.TokenSigner
	if signer != nil {
		ts = signer
	}
	var claims bootstraptokenwire.ClaimsComposer
	if signer != nil {
		claims = newAssertionClaimsComposer(pool, cfg)
	}

	// SigningKeyPEM приходит из authn.bootstrap-mint.signing-key-env (умолчание
	// KANAME_BOOTSTRAP_SA_PRIVATE_KEY_PEM) — ТОТ ЖЕ аксессор, которым
	// Config.Validate решает, включён ли контур, поэтому страж старта и рантайм
	// не могут разойтись во мнении о нём. Пусто → чеканка выключена
	// (fail-closed).
	return bootstraptokenwire.Build(pool, bootstraptokenwire.BuildConfig{
		SigningKeyPEM:   cfg.AuthN.BootstrapMint.ResolveSigningKeyPEM(),
		Signer:          ts,
		Claims:          claims,
		GatewayAudience: audience,
		TokenTTL:        bootstrap_token.MaxTTL,
		Logger:          logger,
	})
}
