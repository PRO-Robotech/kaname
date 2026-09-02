// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// invite_mail_wiring.go — дренаж очереди писем приглашения, возврат отравленных
// строк и наблюдаемость этой очереди.
//
// Основание: приёмка sub-phase-ID-MAIL-1-mail-delivery-acceptance.md, Р23 и Р25;
// объём §10 пп. 20–21, порядок §11 шаг 8а.
//
// # ДВЕ ВЕЛИЧИНЫ ЖИВУТ В РАЗНЫХ МЕСТАХ, И ЭТО НЕ СЛУЧАЙНОСТЬ
//
// Предел времени на ПОПЫТКУ принадлежит ОТПРАВИТЕЛЮ: он ограничивает один
// разговор с почтовым узлом и наблюдаем только на узле, который соединение
// принял и молчит. Число ПОВТОРОВ принадлежит ДРЕНАЖУ: оно ограничивает, сколько
// раз строка будет предъявлена отправителю. Величины разные, предметы разные, и
// подменять одну другой нельзя ни в какую сторону — «ограниченный повтор» без
// предела попытки ограничивает число попыток, каждая из которых вправе висеть
// вечно (`architecture.md` §«Per-call deadline на КАЖДОМ внешнем вызове»).
//
// # ТЕРПЕНИЕ ДРЕНАЖА БОЛЬШЕ ПРЕДЕЛА ПОПЫТКИ, И ЭТО ТРЕБОВАНИЕ
//
// Если бы `ApplyTimeout` был меньше предела попытки, разговор обрывал бы ВСЕГДА
// дренаж, и предел отправителя не фигурировал бы ни в одном исходе — то есть
// величина была бы объявлена и не исполнялась бы никогда. Поэтому терпение
// выводится ИЗ предела попытки, а не назначается рядом с ним: два независимо
// выбранных числа разошлись бы молча.
package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/outbox"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"
	outboxmetrics "github.com/PRO-Robotech/kacho/pkg/outbox/metrics"
	"github.com/PRO-Robotech/kacho/pkg/outbox/reconciler"
	"github.com/PRO-Robotech/kacho/pkg/retention"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// inviteMailPartitionColumn — КЛЮЧ ПАРТИЦИИ порядка очереди писем.
//
// Он объявлен ОДНАЖДЫ и приезжает значением и в дренаж, и в возврат отравленных,
// и в уборку доставленных. Второе написание того же ключа разошлось бы с
// остальными молча, а расхождение здесь означает, что одна половина правила
// сторожит партицию, которой другая не видит.
const inviteMailPartitionColumn = "resource_id"

// applyTimeoutHeadroom — насколько терпение дренажа превышает предел попытки
// отправителя.
//
// Величина названа решением: она покрывает установление соединения из пула и
// разбор ответа сверх самого разговора, оставаясь заведомо меньше, чем пауза
// между повторами. Если бы запаса не было, разговор обрывал бы дренаж, и предел
// отправителя не наблюдался бы ни в одном исходе.
const applyTimeoutHeadroom = 5 * time.Second

// buildInviteMailDrainer собирает дренаж очереди писем приглашения.
//
// Ошибка сборки ФАТАЛЬНА для старта: очередь без исполнителя означает, что
// намерения копятся, а письма не уходят — при этом всё выглядит работающим,
// потому что приглашение-то создаётся. Молчаливо поднятый сервис с мёртвым
// дренажом — ровно тот класс, который мы ловим в чужом коде.
func buildInviteMailDrainer(
	pool *pgxpool.Pool, cfg config.Config, obs clients.InviteMailObserver, logger *slog.Logger,
) (func() error, error) {
	relay, err := buildMailRelay(cfg.InviteMail)
	if err != nil {
		return nil, err
	}

	drainerLogger := logger.With(slog.String("component", "invite_mail_drainer"))
	d, derr := drainer.New[clients.InviteMailEvent](
		pool,
		inviteMailDrainerConfig(cfg.InviteMail),
		clients.DecodeInviteMail,
		clients.NewInviteMailApplier(clients.NewInviteMailSender(relay), obs, drainerLogger),
		drainerLogger,
	)
	if derr != nil {
		return nil, fmt.Errorf("init invite mail drainer: %w", derr)
	}

	return func() error {
		logger.Info("kacho-iam invite mail drainer starting",
			"table", clients.InviteMailTable,
			"channel", clients.InviteMailChannel,
			// Величины печатаются ОБЕ и порознь: слитые в одну строку, они
			// читались бы как одна настройка.
			"attempt_timeout", relay.AttemptTimeout,
			"max_attempts", cfg.InviteMail.MaxAttemptsOrDefault(),
			"relay_configured", cfg.InviteMail.RelayConfigured())
		return d.Run(context.Background())
	}, nil
}

// inviteMailDrainerConfig собирает проводку дренажа из объявленных величин.
//
// ВЫНЕСЕНО ОТДЕЛЬНОЙ ФУНКЦИЕЙ РАДИ ПРОВЕРЯЕМОСТИ. Связь двух величин —
// «терпение дренажа строго больше предела попытки отправителя» — есть
// ТРЕБОВАНИЕ, а не пожелание: при обратном соотношении разговор обрывал бы
// ВСЕГДА дренаж, и предел отправителя не фигурировал бы ни в одном исходе, то
// есть величина была бы объявлена и не исполнялась бы никогда. Требование,
// живущее только в комментарии, проверить нечем; здесь его проверяет
// `Test_InviteMailDrainerConfig_PatienceOutlastsTheAttempt`.
func inviteMailDrainerConfig(cfg config.InviteMailConfig) drainer.Config {
	return drainer.Config{
		Table:        clients.InviteMailTable,
		Channel:      clients.InviteMailChannel,
		BatchSize:    32,
		PollFallback: 30 * time.Second,
		// ЧИСЛО ПОВТОРОВ — величина объявления, не константа корня (MAIL-53).
		// Отдельная от предела времени на попытку.
		MaxAttempts: cfg.MaxAttemptsOrDefault(),
		BackoffMin:  time.Second,
		BackoffMax:  30 * time.Second,
		// ТЕРПЕНИЕ ДРЕНАЖА ВЫВОДИТСЯ из предела попытки отправителя, а не
		// назначается рядом: два независимо выбранных числа разошлись бы молча.
		ApplyTimeout: cfg.AttemptTimeoutOrDefault() + applyTimeoutHeadroom,
		// КЛЮЧ ПАРТИЦИИ ЕСТЬ, поэтому записи в commutativeDrainExempt не
		// требуется. Он покупает три вещи, и каждая — свойство: порядок писем
		// ОДНОМУ человеку (повторное письмо видно адресату, и порядок в его
		// ящике — часть того, что он видит); радиус застрявшей строки в один
		// адресат; выразимость уборки доставленных — общий уборщик платформы
		// ОТКАЗЫВАЕТ на сборке без ключа.
		PartitionColumn: inviteMailPartitionColumn,
		// Отравление ПОСТОЯННОГО отказа — исход по умолчанию, и здесь он верен:
		// постоянный отказ у этой очереди означает настройку (MAIL-33 требует
		// «без бесконечных повторов»). Строка не теряется — её поднимает обратно
		// возврат отравленных, когда настройку починят.
		PermanentPolicy: drainer.PoisonPermanent,
	}
}

// buildMailRelay собирает величины исходящего соединения.
//
// Удостоверение читается ИЗ ОКРУЖЕНИЯ по объявленному ИМЕНИ, а не из карты
// настроек (Р6): карта читается шире секрета. Значение здесь не печатается и не
// возвращается наружу ни одним путём.
//
// НЕОБЪЯВЛЕННАЯ ПОЛОСА ЗДЕСЬ НЕ ОТКАЗ, и это решение, а не послабление. Отказ
// старта по факту необъявленной полосы — предмет стража рендера профиля и шага
// подстановки (Р4а, места С1 и С2), у которых есть доступ к объявлениям профиля;
// здесь его нет by construction. Что происходит вместо: отправитель на каждой
// попытке даёт исход `misconfigured` — громко, в журнал уровнем ошибки и в свою
// клетку счётчика, — а строка отравляется вместо вечного повтора. То есть
// ненастроенная полоса НАБЛЮДАЕМА, а не тиха; тихой она была бы, если бы дренаж
// не поднимался вовсе.
func buildMailRelay(cfg config.InviteMailConfig) (clients.MailRelay, error) {
	mode, err := clients.ParseMailTLSMode(cfg.TLSModeName())
	if err != nil {
		return clients.MailRelay{}, fmt.Errorf("invite mail relay: %w", err)
	}

	var roots *x509.CertPool
	if cfg.CABundleFile != "" {
		pem, rerr := os.ReadFile(cfg.CABundleFile)
		if rerr != nil {
			return clients.MailRelay{}, fmt.Errorf(
				"invite mail relay: read trust anchor %s: %w", cfg.CABundleFile, rerr)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return clients.MailRelay{}, fmt.Errorf(
				"invite mail relay: trust anchor %s carries no certificate — a bundle that "+
					"parses to nothing reads as configured and verifies nothing", cfg.CABundleFile)
		}
	}

	return clients.MailRelay{
		Addr:     cfg.Relay,
		From:     cfg.From,
		FromName: cfg.FromName,
		Username: valueFromEnvName(cfg.UsernameEnv),
		Password: valueFromEnvName(cfg.PasswordEnv),
		// ПРЕДЕЛ ВРЕМЕНИ НА ПОПЫТКУ — величина объявления (MAIL-32), отдельная
		// от числа повторов.
		AttemptTimeout: cfg.AttemptTimeoutOrDefault(),
		TLSMode:        mode,
		RootCAs:        roots,
		LoginURL:       cfg.LoginURL,
	}, nil
}

// valueFromEnvName читает значение по ОБЪЯВЛЕННОМУ имени переменной окружения.
// Пустое имя означает «удостоверение не объявлено», а не «пустое удостоверение»:
// половину пары ловит страж старта и сам отправитель ОДНИМ предикатом.
func valueFromEnvName(name string) string {
	if name == "" {
		return ""
	}
	return os.Getenv(name)
}

// startInviteMailBackstop поднимает возврат отравленных строк и наблюдаемость
// очереди писем.
//
// ВОЗВРАТ НУЖЕН ИМЕННО ЗДЕСЬ, а не «для симметрии»: отравляется у этой очереди
// то, что отказало ПО НАСТРОЙКЕ, — а настройку чинят. Без возврата письмо,
// отравленное неверным адресом ретранслятора, не ушло бы уже никогда, и починка
// настройки не имела бы никакого наблюдаемого следствия для тех, кого пригласили
// в это окно.
func startInviteMailBackstop(
	ctx context.Context, pool *pgxpool.Pool, cfg config.Config,
	rec outboxmetrics.Recorder, logger *slog.Logger,
) error {
	rc, err := reconciler.NewRedriveOnly(pool, reconciler.Config{
		Table:   clients.InviteMailTable,
		Channel: clients.InviteMailChannel,
		// Ключ — ТОТ ЖЕ, что у клейма дренажа, и приезжает из ОДНОГО
		// объявления: на разных ключах каждая половина правила сторожила бы
		// партицию, которой не видит другая.
		PartitionColumn: inviteMailPartitionColumn,
		MaxAttempts:     cfg.InviteMail.MaxAttemptsOrDefault(),
	}, logger.With(slog.String("component", "invite_mail_reconciler")))
	if err != nil {
		return fmt.Errorf("invite mail redrive: %w", err)
	}
	go runInviteMailRedrive(ctx, rc, logger)

	// РАЗЛОЖЕНИЯ ПО НАПРАВЛЕНИЮ ЗДЕСЬ НЕТ И БЫТЬ НЕ МОЖЕТ: у потока одно
	// направление — отправка. Обратной половины («разотправить письмо») не
	// существует by construction, поэтому разложение разложило бы очередь на неё
	// саму и на пустоту. Предмет вынесен записью в ведомости
	// `outboxDirectionSplitExempt`, где перечень видов события машинно сверяется
	// со словарём, закрытым миграцией, — и тот же гейт покраснеет, если очередь
	// получит второе направление.
	col := outboxmetrics.NewCollector(pool, rec, outboxmetrics.CollectorConfig{
		Table:       clients.InviteMailTable,
		MaxAttempts: cfg.InviteMail.MaxAttemptsOrDefault(),
		Interval:    15 * time.Second,
	})
	go col.Run(ctx, func(serr error) {
		logger.Warn("invite mail outbox metrics scan failed", "err", serr)
	})

	// УБОРКА ДОСТАВЛЕННЫХ. Строка пишется на каждое приглашение, то есть темп
	// задаёт арендатор, а снятия строк не было бы ни на одном пути: рост был бы
	// монотонным и вечным. Общий уборщик платформы применим ровно потому, что у
	// очереди есть ключ партиции; недоставленную строку он не снимает НИ ПРИ
	// КАКОМ возрасте — у отравленной отметки доставки нет by construction.
	if _, err := outbox.StartQueueRetentionSweep(
		ctx, pool,
		outbox.QueueRetentionConfig{
			Table:           clients.InviteMailTable,
			PartitionColumn: inviteMailPartitionColumn,
		},
		retention.DefaultConfig(),
		logger.With(slog.String("component", "invite_mail_retention_sweep")),
	); err != nil {
		return fmt.Errorf("invite mail delivered-row sweep: %w", err)
	}

	logger.Info("invite mail backstop started (redrive + metrics + sweep)",
		"table", clients.InviteMailTable)
	return nil
}

// runInviteMailRedrive гоняет проход возврата отравленных строк на периодическом
// тикере.
//
// РЕПЛИКИ: на-реплику — проход есть один условный оператор возврата отравленных
// строк. Строки заперты самим оператором, повтор идемпотентен, к соседям проход
// не ходит; вторая реплика приводит к тому же состоянию. Вид тот же, что у
// одноимённого прохода vpc, и это не совпадение: механизм у них общий
// (`reconciler.RedrivePoisoned`), а два одинаковых прохода, названные разными
// видами, и есть то расхождение, ради которого словарь закрыт.
func runInviteMailRedrive(ctx context.Context, rc *reconciler.Reconciler, logger *slog.Logger) {
	const interval = 5 * time.Minute
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			if n, err := rc.RedrivePoisoned(ctx); err != nil {
				logger.Warn("invite mail redrive-poisoned failed", "err", err)
			} else if n > 0 {
				logger.Info("invite mail redrive re-queued poisoned letters", "count", n)
			}
		}
	}
}
