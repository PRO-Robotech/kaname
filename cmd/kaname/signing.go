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

	"github.com/PRO-Robotech/corelib/tokenpolicy"
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
	return buildTokenSigningAt(ctx, pool, cfg, time.Now, logger)
}

// buildTokenSigningAt — то же построение с часами на ВХОДЕ.
//
// Часы вынесены в вызов, а не подставлены в теле: момент ротации есть функция
// времени, и проба, поднимающая ключницу ТЕМ ЖЕ построением, что `serve`, без
// управляемых часов не различила бы «рано» и «пора». Производственный вызов
// один — buildTokenSigning, и он подаёт системные часы.
func buildTokenSigningAt(
	ctx context.Context,
	pool *pgxpool.Pool,
	cfg config.Config,
	clock signingkeys.Clock,
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
		RotationLead: signingKeyRotationLead,
		Clock:        clock,
		Logger:       logger.With(slog.String("component", "signing_keystore")),
	}, repo, repo, wrapper)
	if err != nil {
		// Срок ключа, не превышающий запаса ротации, отвергается здесь, а не
		// стражем настройки: запас — величина этого корня. Имя ручки
		// приписывается, чтобы оператору было что править.
		return nil, nil, fmt.Errorf("ключница (authn.token-signing.key-lifetime=%s, запас ротации %s): %w",
			ts.KeyLifetime, signingKeyRotationLead, err)
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
		Clock:       tokensigner.Clock(clock),
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

// startSigningKeyMaintenance поднимает обслуживание ключницы: ротацию до
// объявленного срока подписывающего и снятие выведенных ключей, чья отсрочка
// истекла.
//
// Почему снятие отдельным ходом, а не при ротации: отсрочка истекает ПОЗЖЕ
// действия, её вызвавшего, и снятие, привязанное к ротации, случалось бы либо
// слишком рано (живые токены отвергаются), либо не случалось бы вовсе.
//
// ПЕРВЫЙ ПРОХОД — ПРИ СТАРТЕ и синхронно (#314): ноль проходов у живого
// процесса иначе читался бы как норма целый интервал, а ротация, чей срок
// наступил, пока служба стояла, ждала бы его же.
//
// РЕПЛИКИ: на-реплику — петля идёт в каждой реплике, и дубль безвреден не по
// намерению, а по СВОЙСТВУ ОПЕРАТОРОВ: снятие выражено переходом из
// определённого состояния (`WHERE state = 'RETIRED'`), а передача подписи —
// условно на ожидаемого подписывающего, поэтому второй исполнитель получает
// ноль строк, а не отменяет работу первого. Проигравший ротацию выводит свой
// порождённый ключ сам (signingkeys.RotateIfDue).
func startSigningKeyMaintenance(ctx context.Context, ks *signingkeys.Keystore, logger *slog.Logger) {
	if ks == nil {
		return
	}
	signingKeyMaintenancePass(ctx, ks, logger)
	go func() {
		ticker := time.NewTicker(signingKeySweepInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				signingKeyMaintenancePass(ctx, ks, logger)
			}
		}
	}()
}

// signingKeyMaintenancePass — ОДИН проход обслуживания: ротация, если срок
// подошёл, затем снятие.
//
// Порядок несущий: ротация первой, потому что ключ, выведенный ею, снимается
// не этим проходом, а через отсрочку, — обратный порядок ничего не выиграл бы,
// а отказ ротации не должен останавливать снятие. Отставшее обслуживание НЕ
// фатально: ключ постоит в наборе дольше нужного либо подпишет дольше запаса,
// и ронять сервис из-за него значило бы менять ограниченное отставание на
// полный отказ. Оба отказа звучат журналом и счётчиком отказов ключницы, а
// сорванный проход сметателя проходом не считается — правило тревоги на ноль
// проходов его увидит.
//
// Проход ограничен своим сроком: зависшее хранилище не держит петлю вечно.
func signingKeyMaintenancePass(ctx context.Context, ks *signingkeys.Keystore, logger *slog.Logger) {
	passCtx, cancel := context.WithTimeout(ctx, signingKeyPassTimeout)
	defer cancel()
	rotated, err := ks.RotateIfDue(passCtx)
	switch {
	case err != nil:
		logger.Warn("signing key rotation failed", slog.String("err", err.Error()))
	case rotated:
		logger.Info("signing key rotated ahead of its declared term",
			slog.String("rotation_lead", signingKeyRotationLead.String()))
	}
	n, err := ks.SweepRemovable(passCtx)
	if err != nil {
		logger.Warn("signing key sweep failed", slog.String("err", err.Error()))
		return
	}
	if n > 0 {
		logger.Info("signing keys removed from the key set", slog.Int("count", n))
	}
}

// signingKeySweepInterval — как часто идёт проход обслуживания. Величина мала
// относительно отсрочки: сметатель, ходящий реже, чем истекает отсрочка,
// оставлял бы снятые ключи в наборе на целый свой период.
const signingKeySweepInterval = 15 * time.Minute

// signingKeyRotationLead — за сколько до объявленного срока подписывающего
// подпись переходит к новому ключу.
//
// Четыре интервала прохода, а не один: ротация обязана случиться ДО срока и
// тогда, когда несколько проходов подряд сорвались (хранилище недоступно), — с
// одним интервалом запаса первый же пропуск переносил бы её за срок. Срок ключа
// обязан быть длиннее запаса; иначе ключница отказывает в построении.
const signingKeyRotationLead = 4 * signingKeySweepInterval

// signingKeyPassTimeout — срок ОДНОГО прохода обслуживания: порождение ключа,
// передача подписи и обход набора. Много больше их обычной длительности и
// меньше интервала, чтобы зависший проход не наложился на следующий.
const signingKeyPassTimeout = 2 * time.Minute

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
