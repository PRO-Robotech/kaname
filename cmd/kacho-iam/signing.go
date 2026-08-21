// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// signing.go — сборка своей чеканки токенов в композиционном корне
// (задача #897).
//
// Здесь и только здесь ключница, обёртка и подписант соединяются с
// конфигурацией: use-case знает порты, адаптеры знают базу, а кто с чем связан
// — решается один раз, в единственном месте сборки.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/signingkeys"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/keywrap"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
	"github.com/PRO-Robotech/kacho/services/iam/internal/tokensigner"
)

// buildTokenSigning собирает ключницу и подписанта.
//
// Возвращает (nil, nil, nil), когда своя чеканка выключена: у выключенной
// подсистемы не бывает наполовину собранных частей, и «есть, но не работает»
// здесь не выражается.
//
// Неполная настройка при ВКЛЮЧЁННОЙ чеканке — ОТКАЗ, а не деградация:
// подписант, собранный наполовину, выпускал бы токены, которые приёмная
// сторона обязана отвергнуть, и узналось бы это на первом запросе.
func buildTokenSigning(
	ctx context.Context,
	pool *pgxpool.Pool,
	cfg config.Config,
	logger *slog.Logger,
) (*signingkeys.Keystore, *tokensigner.Signer, error) {
	ts := cfg.AuthN.TokenSigning
	if !ts.Enabled {
		return nil, nil, nil
	}

	// Ключ обёртки приватной половины — та же ручка, что требует страж старта.
	// Второй ручки об этом предмете в дереве нет.
	wrapKey, err := cfg.AuthN.ResolveJWKSEncryptionKey()
	if err != nil {
		return nil, nil, fmt.Errorf("ключ обёртки приватной половины: %w", err)
	}
	wrapper, err := keywrap.New(wrapKey)
	if err != nil {
		return nil, nil, fmt.Errorf("обёртка приватной половины: %w", err)
	}

	alg, err := domain.ParseSigningAlgorithm(ts.Algorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("алгоритм подписи: %w", err)
	}

	repo := kachopg.NewSigningKeyRepo(pool)
	keystore, err := signingkeys.New(signingkeys.Config{
		Algorithm:   alg,
		KeyLifetime: ts.ResolveKeyLifetime(),
		// Отсрочка снятия ВЫЧИСЛЕНА из объявленных слагаемых, а не выбрана
		// здесь: смена любого из них без пересмотра отсрочки роняет гейт.
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		Clock:        time.Now,
		Logger:       logger.With(slog.String("component", "signing_keystore")),
	}, repo, repo, wrapper)
	if err != nil {
		return nil, nil, fmt.Errorf("ключница: %w", err)
	}

	// Подписывающий ключ обеспечивается ПРИ СТАРТЕ. Порядок «в наборе →
	// подписывает» верен по построению: ключ рождается опубликованным, и лишь
	// потом вступает в подпись.
	if err := keystore.EnsureSigningKey(ctx); err != nil {
		return nil, nil, fmt.Errorf("подписывающий ключ: %w", err)
	}

	signer, err := tokensigner.New(tokensigner.Config{
		Issuer: ts.Issuer,
		// Часы — ВХОД, а не окружение: без этого сценарии расхождения часов
		// недетерминированы, а детерминизм входа есть условие того, чтобы
		// проба вообще могла упасть предсказуемо.
		Clock:       time.Now,
		MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, keystore)
	if err != nil {
		return nil, nil, fmt.Errorf("подписант: %w", err)
	}

	logger.Info("own token signing is on",
		slog.String("issuer", ts.Issuer),
		slog.String("algorithm", string(alg)),
		slog.String("key_set_path", ts.ResolveKeySetPath()),
		slog.String("max_token_ttl", tokenpolicy.MaxTokenTTL.String()),
		slog.String("key_removal_grace", tokenpolicy.KeyRemovalGrace.String()))
	return keystore, signer, nil
}

// startSigningKeySweeper снимает из набора выведенные ключи, чья отсрочка
// истекла.
//
// Почему отдельным ходом, а не при ротации: отсрочка истекает ПОЗЖЕ действия,
// её вызвавшего, и снятие, привязанное к ротации, случалось бы либо слишком
// рано (живые токены отвергаются), либо не случалось бы вовсе.
//
// РЕПЛИКИ: на-реплику — петля идёт в каждой реплике, и дубль безвреден не по
// намерению, а по СВОЙСТВУ ОПЕРАТОРА: снятие выражено переходом из
// определённого состояния (`WHERE state = 'RETIRED'`), поэтому второй
// исполнитель получает ноль строк, а не отменяет работу первого. Ноль строк
// сметатель читает как «уже снято» и продолжает обход — иначе он работал бы
// тем хуже, чем больше реплик.
func startSigningKeySweeper(ctx context.Context, ks *signingkeys.Keystore, logger *slog.Logger) {
	if ks == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(signingKeySweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := ks.SweepRemovable(ctx)
				if err != nil {
					// Отставший сметатель НЕ фатален: ключ постоит в наборе
					// дольше нужного, а предел продолжает действовать. Ронять
					// сервис из-за него значило бы менять ограниченное
					// отставание на полный отказ.
					logger.Warn("signing key sweep failed", slog.String("err", err.Error()))
					continue
				}
				if n > 0 {
					logger.Info("signing keys removed from the key set", slog.Int("count", n))
				}
			}
		}
	}()
}

// signingKeySweepInterval — как часто проверяется, не истекла ли отсрочка.
// Величина мала относительно самой отсрочки: сметатель, ходящий реже, чем
// истекает отсрочка, оставлял бы снятые ключи в наборе на целый свой период.
const signingKeySweepInterval = 15 * time.Minute
