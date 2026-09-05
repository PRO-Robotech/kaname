// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/anypb"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/secretsweep"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// secretSweepStore adapts the Postgres redactor to the use-case port. The port's
// types are declared by the caller, so the conversion lives here rather than
// letting the adapter's shape leak upwards.
type secretSweepStore struct{ inner *kachopg.OpsResponseRedactor }

func (s secretSweepStore) SweepStrandedSecrets(ctx context.Context, spec secretsweep.Spec) (secretsweep.Result, error) {
	targets := make([]kachopg.SecretSweepTarget, 0, len(spec.Targets))
	for _, t := range spec.Targets {
		targets = append(targets, kachopg.SecretSweepTarget{ResponseType: t.ResponseType, Fields: t.Fields})
	}
	res, err := s.inner.SweepStrandedSecrets(ctx, kachopg.SecretSweepSpec{
		Targets: targets, Settled: spec.Settled, Window: spec.Window, Limit: spec.Limit,
	})
	return secretsweep.Result{Scanned: res.Scanned, Redacted: res.Redacted}, err
}

// secretSweepWindow — how far back a sweep looks. The backstop covers a process
// restart, which is minutes; the bound is what keeps the cost of a sweep
// independent of the size of the operations table.
const secretSweepWindow = 24 * time.Hour

// secretSweepMargin — added to the longest configured grace window before a
// response is considered settled. The client is still polling for its credential
// during the grace window, and a key handed over as "" cannot be reissued, so the
// backstop must never be the one that wins that race.
const secretSweepMargin = 2 * time.Minute

// secretSweepBatch — rows per response type per sweep.
const secretSweepBatch = 200

// startSecretBackstop wires the durable clean-up of one-shot credentials staged in
// finished operation responses.
//
// The in-process clean-up is a goroutine detached from the issuing request; it is
// registered in no shutdown group, and the default termination grace is shorter
// than the credential grace window — so an ordinary rollout ends it mid-window.
// The row it was going to clean is done=true, which puts it outside the orphan
// reconciler's claim (done = false) by construction, and nothing ages operations
// out. Without this loop the plaintext stayed for the life of the cluster, silently:
// every branch that logs "key material may remain" runs inside the goroutine that
// no longer exists.
func startSecretBackstop(ctx context.Context, pool *pgxpool.Pool, cfg config.Config, logger *slog.Logger) error {
	// The response types are derived from the messages themselves, never written
	// out as strings: a renamed message would otherwise leave a sweeper that
	// matches nothing and reports a clean table for ever.
	saKey, err := anypb.New(&iamv1.IssueSAKeyResponse{})
	if err != nil {
		return fmt.Errorf("secret backstop: sa-key response type: %w", err)
	}
	userToken, err := anypb.New(&iamv1.IssueUserTokenResponse{})
	if err != nil {
		return fmt.Errorf("secret backstop: user-token response type: %w", err)
	}

	settled := cfg.AuthN.SAKeyRedactGrace
	if cfg.AuthN.UserTokenRedactGrace > settled {
		settled = cfg.AuthN.UserTokenRedactGrace
	}
	settled += secretSweepMargin

	sw := secretsweep.New(
		secretSweepStore{inner: kachopg.NewOpsResponseRedactor(pool, "kacho_iam")},
		secretsweep.Spec{
			Targets: secretSweepTargets(saKey.TypeUrl, userToken.TypeUrl),
			Settled: settled,
			Window:  secretSweepWindow,
			Limit:   secretSweepBatch,
		},
		0, // default interval
		logger.With(slog.String("component", "secret_backstop")),
	)
	go sw.Run(ctx)
	logger.Info("one-shot credential backstop started",
		"settled_after", settled.String(), "window", secretSweepWindow.String())
	return nil
}

// secretSweepTargets — ПЕРЕЧЕНЬ ПОДМЕТАЛЬЩИКА: тип ответа → поля-носители.
//
// Вынесен из тела построителя намеренно: перечень, который ВЫПИСЫВАЮТ,
// расходится с контрактом молча — и расходится в сторону «не называем», потому
// что не назвать проще. Поле, которого перечень не называет, подметальщик
// ПРОПУСКАЕТ, и таблица читается чистой навсегда; отсутствие записи при этом
// неотличимо от «поле проверено и чисто».
//
// Поэтому перечень обязан быть ЧИТАЕМ ГЕЙТОМ (`secret_bearing_ledger_test.go`):
// гейт берёт помеченные опцией контракта поля из ДЕСКРИПТОРОВ и требует, чтобы
// каждое, чьё сообщение названо ответом операции, стояло здесь.
//
// Обе меры держат РАЗНЫЕ свойства и держатся вместе: секрет не кладётся в тело
// при записи (конструкция того пути, который заводит фаза), а перечень
// подметальщика страхует ЛЮБОЙ путь, включая тот, что заведут завтра и который
// о конструкции знать не будет.
func secretSweepTargets(saKeyType, userTokenType string) []secretsweep.Target {
	return []secretsweep.Target{
		// У ответа машинного ключа названы ОБА написания: нынешний одноразовый
		// ключ и легаси-секрет, оставленный ради совместимости провода. Поле,
		// которого сообщение не несёт, пропускается.
		//
		// `secret` — базовый секрет (#1142). В тело, записываемое в строку
		// операции, он не кладётся ВОВСЕ, поэтому подметать здесь нечего; запись
		// стоит как БЭКСТОП против будущего второго пути записи.
		{ResponseType: saKeyType, Fields: []string{"private_key_pem", "client_secret", "secret"}},
		{ResponseType: userTokenType, Fields: []string{"private_key_pem", "secret"}},
	}
}
