// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// orphan_scope_sweep.go — разовая идемпотентная уборка выдач, чья область УЖЕ
// УДАЛЕНА (задача #810, продолжение #792).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// #792 закрыл ИСТОЧНИК: `Project.Delete` дренирует выдачи своей области в той же
// транзакции, что и снятие строки. Правка действует ВПЕРЁД и накопленного не
// убирает: у `access_bindings` нет внешнего ключа на `projects` (ссылка мягкая,
// межресурсная), поэтому каждое снятие проекта до #792 оставляло свои выдачи
// живыми в состоянии ACTIVE, их кортежи — в движке, а реконсайлер продолжал их
// материализовать. Доступ живёт на объект, которого нет, и штатным путём не
// снимается: область, через которую привязку нашли бы, удалена.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ МИГРАЦИЯ — установлено, а не предпочтено
//
// Строка очереди в движок группируется по паре (субъект, объект) и несёт ВЕСЬ
// набор отношений субъекта на этом объекте, причём отзыв — намеренно БЕЗ
// совместимостного эха, которое несёт выдача (`fga_outbox/emitter.go`, emitTx).
// Ключ партиции дренажа выводится триггером и писателем не рендерится никогда.
// SQL, воспроизводящий эту форму, стал бы ВТОРЫМ КОДЕКОМ рядом с эмиттером и
// разошёлся бы с ним молча — именно там, где расхождение не видно, потому что на
// валидном входе оба отвечают одинаково.
//
// Плюс общая норма: применённую миграцию не правят (запрет #5), а ошибка в
// разовом ремонте данных становится неисправимой на месте.
//
// Поэтому уборка живёт на стороне Go и зовёт ТОТ ЖЕ путь, что и `Project.Delete`:
// `shared.RevokeBindingsInScope` → `Writer.EmitFGARelationDelete`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УБОРКА СУДИТ, А ЧТО НЕ БЕРЁТСЯ СУДИТЬ
//
// Только те области, чья строка лежит в СОБСТВЕННОЙ базе iam: `project` и
// `account`. Всё остальное (`cluster` — у него таблицы-владельца нет вовсе; любой
// межсервисный вид) уборка не трогает: она не вправе объявить отсутствующим то,
// чего не умеет прочитать. Отсутствие строки у чужого владельца — не её вопрос.
//
// `account` включён не «на всякий случай»: предикат для него тот же и решается
// так же локально, а замер на стенде даёт по нему НОЛЬ висячих выдач из 239 —
// потому что `Account.Delete` свои выдачи дренирует давно. То есть включение
// аккаунта превращает измеренный контроль в живое утверждение вместо допущения,
// которое держится чужим кодом и молча протухнет, если тот регрессирует.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
	"github.com/PRO-Robotech/kacho-iam/internal/outboxtypes"
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
)

// AuditEventOrphanScopeRevoked — тип события аудита разовой уборки. Словарь
// `audit_outbox.event_type` — регулярное выражение `iam.<часть>.<часть>`, а не
// закрытый перечень, поэтому новый литерал миграции НЕ требует (проверено по
// `audit_outbox_event_type_check`, миграция 0001).
const AuditEventOrphanScopeRevoked = "iam.access_binding.orphan_scope_revoked"

// OrphanScopeDefaultMaxScopes — сколько областей уборка берёт за один прогон.
// Прогон ОГРАНИЧЕН намеренно: он идёт на старте процесса и не вправе занимать его
// неограниченно. Остаток берёт следующий прогон, и о нём говорится вслух.
const OrphanScopeDefaultMaxScopes = 1000

// OrphanScope — область, чьей строки-владельца в базе iam больше нет.
type OrphanScope struct {
	ResourceType domain.ResourceType
	ResourceID   string
}

// OrphanScopeStore — узкий порт уборки: общий на кластер try-lock + перепись
// висячих областей. Реализуется pg-адаптером.
type OrphanScopeStore interface {
	// TryAcquireSingletonOrphanScopeLock берёт СЕССИОННЫЙ pg_advisory_lock по
	// известному ключу неблокирующим вариантом. ok=false ⇒ уборку уже ведёт другой
	// процесс ⇒ этот прогон пропускается. Замыкание освобождения обязано быть
	// вызвано.
	TryAcquireSingletonOrphanScopeLock(ctx context.Context) (ok bool, release func(context.Context), err error)

	// ListOrphanBindingScopes возвращает до `limit` РАЗЛИЧНЫХ областей, на которые
	// есть выдачи, но чьей строки-владельца в базе iam нет. Только виды, чьего
	// владельца iam читает у себя (project, account).
	ListOrphanBindingScopes(ctx context.Context, limit int) ([]OrphanScope, error)
}

// OrphanScopeConfig — настройки уборки.
type OrphanScopeConfig struct {
	// MaxScopesPerRun ограничивает прогон. ≤0 → OrphanScopeDefaultMaxScopes.
	MaxScopesPerRun int
	// Logger — необязателен; nil → slog.Default().
	Logger *slog.Logger
}

// OrphanScopeResult — исход прогона.
//
// ScopesInspected печатается ВСЕГДА и отдельно от ScopesRevoked: без него «ноль
// убранного» неотличимо от «ноль осмотренного», а это разные ответы.
type OrphanScopeResult struct {
	// Executed — этот ли прогон взял общий замок и вёл уборку.
	Executed bool
	// ScopesInspected — сколько областей прогон рассмотрел.
	ScopesInspected int
	// ScopesRevoked — по скольким областям выдачи сняты.
	ScopesRevoked int
	// ScopesSkipped — сколько областей на момент транзакции ОКАЗАЛИСЬ ЖИВЫ и
	// потому не тронуты (перепроверка внутри транзакции).
	ScopesSkipped int
	// BindingsRevoked / TuplesRetracted — снятые строки выдач и эмитированные
	// снятия кортежей.
	BindingsRevoked int
	TuplesRetracted int
	// Truncated — упёрлись в потолок прогона, остаток берёт следующий.
	Truncated bool
}

// OrphanScopeSweeper — разовая уборка висячих областей.
type OrphanScopeSweeper struct {
	repo      kachorepo.Repository
	store     OrphanScopeStore
	maxScopes int
	logger    *slog.Logger
}

// NewOrphanScopeSweeper собирает уборщик.
func NewOrphanScopeSweeper(repo kachorepo.Repository, store OrphanScopeStore, cfg OrphanScopeConfig) *OrphanScopeSweeper {
	maxScopes := cfg.MaxScopesPerRun
	if maxScopes <= 0 {
		maxScopes = OrphanScopeDefaultMaxScopes
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &OrphanScopeSweeper{repo: repo, store: store, maxScopes: maxScopes, logger: logger}
}

// RunOnce исполняет уборку ровно один раз на кластер.
//
// Сначала берётся общий неблокирующий замок: держит другой процесс — прогон
// возвращает Executed=false и НИЧЕГО не делает. Затем берётся снимок висячих
// областей (не более maxScopes) и каждая убирается в СВОЕЙ транзакции — не
// десятки тысяч удалений одной.
//
// Отказ по одной области НЕ роняет остальные: он считается, называется и
// возвращается ошибкой в конце. Иначе одна неубираемая область блокировала бы
// все последующие на каждом прогоне (голова очереди), а тихий пропуск сделал бы
// невидимым как раз то, ради чего уборка заведена.
//
// Повтор безопасен: убранная область в следующую перепись не попадает, а
// сохранившаяся отсеивается перепроверкой внутри транзакции.
func (s *OrphanScopeSweeper) RunOnce(ctx context.Context) (OrphanScopeResult, error) {
	ok, release, err := s.store.TryAcquireSingletonOrphanScopeLock(ctx)
	if err != nil {
		return OrphanScopeResult{}, fmt.Errorf("orphan-scope sweep: acquire singleton lock: %w", err)
	}
	if !ok {
		s.logger.InfoContext(ctx, "orphan-scope sweep: singleton lock held by another process — skipping")
		return OrphanScopeResult{Executed: false}, nil
	}
	defer release(ctx)

	scopes, err := s.store.ListOrphanBindingScopes(ctx, s.maxScopes)
	if err != nil {
		return OrphanScopeResult{Executed: true}, fmt.Errorf("orphan-scope sweep: list orphan scopes: %w", err)
	}

	res := OrphanScopeResult{Executed: true, ScopesInspected: len(scopes), Truncated: len(scopes) >= s.maxScopes}

	var failures int
	var firstErr error
	for _, sc := range scopes {
		bindings, tuples, skipped, rerr := s.revokeScope(ctx, sc)
		switch {
		case rerr != nil:
			failures++
			if firstErr == nil {
				firstErr = rerr
			}
			s.logger.ErrorContext(ctx, "orphan-scope sweep: scope revoke failed",
				slog.String("resource_type", string(sc.ResourceType)),
				slog.String("resource_id", sc.ResourceID),
				slog.Any("err", rerr))
		case skipped:
			res.ScopesSkipped++
		default:
			res.ScopesRevoked++
			res.BindingsRevoked += bindings
			res.TuplesRetracted += tuples
		}
	}

	s.logger.InfoContext(ctx, "orphan-scope sweep complete",
		slog.Int("scopes_inspected", res.ScopesInspected),
		slog.Int("scopes_revoked", res.ScopesRevoked),
		slog.Int("scopes_skipped", res.ScopesSkipped),
		slog.Int("bindings_revoked", res.BindingsRevoked),
		slog.Int("tuples_retracted", res.TuplesRetracted),
		slog.Int("scopes_failed", failures),
		slog.Bool("truncated", res.Truncated))
	if res.Truncated {
		s.logger.WarnContext(ctx, "orphan-scope sweep: hit the per-run scope ceiling — the remainder is left to the next run",
			slog.Int("max_scopes_per_run", s.maxScopes))
	}
	if failures > 0 {
		return res, fmt.Errorf("orphan-scope sweep: %d scope(s) failed, first: %w", failures, firstErr)
	}
	return res, nil
}

// revokeScope снимает выдачи ОДНОЙ висячей области в одной транзакции.
//
// Перепроверка отсутствия строки-владельца идёт ВНУТРИ той же транзакции, что и
// дренаж, а не по результату переписи снаружи: перепись читает другой снимок, и
// решение, принятое по нему, было бы проверкой-до-действия. Сегодня разойтись им
// нечем (идентификаторы не переиспользуются, поэтому «была висячей» — свойство
// монотонное), но правильность здесь держится оператором базы, а не рассуждением
// о том, чего не бывает.
func (s *OrphanScopeSweeper) revokeScope(ctx context.Context, sc OrphanScope) (bindings, tuples int, skipped bool, err error) {
	noun, ok := orphanScopeNoun(sc.ResourceType)
	if !ok {
		// Вид, чьего владельца iam не читает, до переписи дойти не может; если
		// дошёл — это расхождение переписи с уборкой, и молчать о нём нельзя.
		return 0, 0, false, fmt.Errorf("orphan-scope sweep: refusing to judge scope type %q — iam does not own its rows",
			sc.ResourceType)
	}
	terr := shared.DoWithWriteTxVoid(ctx, s.repo, func(ctx context.Context, w kachorepo.Writer) error {
		alive, aerr := orphanScopeStillAlive(ctx, w, sc)
		if aerr != nil {
			return aerr
		}
		if alive {
			skipped = true
			return nil
		}
		fgaDeletes, revoked, rerr := shared.RevokeBindingsInScope(ctx, w, sc.ResourceType, sc.ResourceID, noun)
		if rerr != nil {
			return rerr
		}
		// Признак «нечего было убирать» — НОЛЬ СНЯТЫХ СТРОК, а не пустой набор
		// кортежей. Выдача вправе не иметь ни одного материализованного кортежа
		// (реконсайлер до неё не дошёл, роль ничего не материализует), и судить о
		// проделанной работе по ведомости значило бы объявить такую уборку
		// несостоявшейся — ровно там, где она и нужна.
		if revoked == 0 {
			skipped = true
			return nil
		}
		bindings, tuples = revoked, len(fgaDeletes)
		if ferr := w.EmitFGARelationDelete(ctx, fgaDeletes); ferr != nil {
			return ferr
		}
		return w.EmitAuditEvent(ctx, outboxtypes.AuditEvent{
			EventType: AuditEventOrphanScopeRevoked,
			Payload: map[string]any{
				// Учётки-инициатора у уборки нет by construction: она идёт на старте
				// процесса, а не по чьему-то запросу. Пустая строка тут — факт, а не
				// потерянное значение; выдумывать актора нельзя.
				"actor":         "",
				"reason":        "scope row absent in iam database (orphan access bindings, issue #810)",
				"resource_type": string(sc.ResourceType),
				"resource_id":   sc.ResourceID,
				"tuples":        tuples,
			},
		})
	})
	if terr != nil {
		return 0, 0, false, terr
	}
	if skipped {
		return 0, 0, true, nil
	}
	return bindings, tuples, false, nil
}

// orphanScopeNoun — отображаемое существительное области для контрактного текста
// отказа дренажа. Оно же — перечень видов, которые уборка вправе судить.
func orphanScopeNoun(rt domain.ResourceType) (string, bool) {
	switch rt {
	case domain.ResourceType("project"):
		return "Project", true
	case domain.ResourceType("account"):
		return "Account", true
	default:
		return "", false
	}
}

// orphanScopeStillAlive — жива ли строка-владелец области в ЭТОЙ транзакции.
func orphanScopeStillAlive(ctx context.Context, w kachorepo.Writer, sc OrphanScope) (bool, error) {
	var err error
	switch sc.ResourceType {
	case domain.ResourceType("project"):
		_, err = w.Projects().Get(ctx, domain.ProjectID(sc.ResourceID))
	case domain.ResourceType("account"):
		_, err = w.Accounts().Get(ctx, domain.AccountID(sc.ResourceID))
	default:
		return false, fmt.Errorf("orphan-scope sweep: unsupported scope type %q", sc.ResourceType)
	}
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, iamerr.ErrNotFound):
		return false, nil
	default:
		return false, err
	}
}
