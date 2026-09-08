// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// signing.go — сборка своей чеканки токенов в композиционном корне
// (задача #897).
//
// Здесь и только здесь ключница, обёртка и подписант соединяются с
// конфигурацией: use-case знает порты, адаптеры знают базу, а кто с чем связан
// — решается один раз, в единственном месте сборки.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
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
	// Второй ручки об этом предмете в дереве нет; ручка принимает ПЕРЕЧЕНЬ —
	// первый ключ оборачивает, все открывают (задача #1065), поэтому смена
	// ключа не требует ни простоя, ни переписывания хранилища.
	wrapKeys, err := cfg.AuthN.ResolveJWKSEncryptionKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("ключ обёртки приватной половины: %w", err)
	}
	wrapper, err := keywrap.New(wrapKeys...)
	if err != nil {
		return nil, nil, fmt.Errorf("обёртка приватной половины: %w", err)
	}
	// Число названных ключей печатается ВСЕГДА, включая единицу: перечень
	// растёт с каждой сменой и сам не убывает, а «названо шесть ключей» иначе
	// невидимо ниоткуда — то есть работу по выводу прежних некому начать. Оно
	// же и первое, что нужно оператору, если старт откажет на нечитаемом
	// наборе: перечень мог приехать без прежнего ключа.
	logger.Info("private-half wrapping keys declared",
		slog.Int("keys", wrapper.KeyCount()),
		slog.String("knob", "authn.jwks-encryption-key-hex"),
		slog.String("env", cfg.AuthN.JWKSEncryptionKeyEnvName()))

	alg, err := domain.ParseSigningAlgorithm(ts.Algorithm)
	if err != nil {
		return nil, nil, fmt.Errorf("алгоритм подписи: %w", err)
	}

	repo := kanamepg.NewSigningKeyRepo(pool)
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
	//
	// Ключница проверяет здесь же, что предъявленный ключ обёртки открывает
	// уже записанное, и на несовпадении ОТКАЗЫВАЕТ В СТАРТЕ (задача #1062).
	// Имя ручки приписывается тут, а не в ключнице: use-case конфигурации не
	// знает, а оператору без имени ручки чинить нечего.
	if err := keystore.EnsureSigningKey(ctx); err != nil {
		return nil, nil, signingKeyStartupRefusal(cfg.AuthN, err)
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

// signingKeyStartupRefusal облекает отказ обеспечения подписывающего ключа в
// текст, который видит ОПЕРАТОР, поднимающий стенд.
//
// Отдельная функция, а не строка на месте: текст отказа при старте — часть
// рантайм-диагностики, без которой стенд не поднять, поэтому он обязан быть
// проверяем пробой, а не читаться глазами на ревью.
//
// Имя ручки приписывается ЗДЕСЬ, а не в ключнице: use-case конфигурации не
// знает, а оператору без имени ручки чинить нечего. Имя переменной берётся из
// самой настройки — профиль, переназвавший её, обязан увидеть в отказе своё имя.
//
// Посторонний отказ (недоступное хранилище, негодный алгоритм) НЕ выдаётся за
// смену ключа обёртки: отказ, называющийся одинаково при любой беде, не
// сообщает ничего.
func signingKeyStartupRefusal(authn config.AuthNConfig, err error) error {
	if errors.Is(err, signingkeys.ErrWrappingKeyMismatch) {
		return fmt.Errorf(
			"подписывающий ключ: ручка authn.jwks-encryption-key-hex (ENV %s) не открывает уже записанные "+
				"подписные ключи. Служба ОТКАЗЫВАЕТСЯ стартовать: завести новый ключ поверх нечитаемых значило "+
				"бы молча обесценить все ранее выданные токены — «пересоздали стенд» и «потеряли все подписи» "+
				"стали бы неотличимы. Верните прежнее значение ручки: %w",
			authn.JWKSEncryptionKeyEnvName(), err)
	}
	return fmt.Errorf("подписывающий ключ: %w", err)
}
