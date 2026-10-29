// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// verify_gate.go — непрерывный страж сверки перед фазой контракта. Фаза
// контракта (она снимает каскад вывода FGA и scope_grant) допустима ТОЛЬКО
// тогда, когда страж сообщает 100% отсутствия потери доступа.
//
// Утверждений два, оба — ЧТЕНИЕ, страж ничего не пишет:
//
//   Verify — у каждой ACTIVE-выдачи, которую СВЕДЕНИЕ решило материализовать
//     (у неё ≥1 ACTIVE-строка access_binding_target_members — вердикт самого
//     сведения, а не эвристика), ведомость access_binding_emitted_tuples обязана
//     быть непустой. ACTIVE-член при пустой ведомости — ПОТЕРЯ ДОСТУПА: после
//     снятия каскада оператор получил бы отказ, и страж сообщает
//     NoAccessLoss=false с названной выдачей. Выдача, которой сведение не
//     оставило ACTIVE-членов (кластерный `*.*.*`, обслуживаемый коротким путём
//     администратора кластера, роль только с правами, селектор без совпадений),
//     ведомости не ждёт и находкой не является.
//
//   VerifyRelationSatisfiesAction — настоящий Check по каждой тройке v_*
//     активной выдачи: материализованный кортеж обязан РАЗРЕШАТЬ отношение,
//     которым каталог гейтит чтение, а не просто лежать в ведомости.
//
// Живость прямого пути (объект, заведённый после выдачи, получает кортеж)
// страж НЕ утверждает. Прежде это делала дымовая проба: она клала синтетику в
// боевое зеркало, сводила её и снимала. Прод-потребителя у неё не было с #119,
// и она снята вместе со своими методами порта (#148). Свойство утверждается
// интеграционно против настоящего сведения: селекторная полоса —
// TestP8_05_VerifyGate_NoAccessLoss_ForwardMaterializes и
// TestReconcileForward_04_Backstop_FullConverges_NoDuplicate, владельческая —
// Test224_OwnerWildcard_ForwardMaterializesContent.
//
// Чистая архитектура: зависит только от узкого порта VerifyStore (его
// реализует pg BackfillAdapter) и порта Check. pgx здесь нет.

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/admission"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// VerifyRelationChecker — порт НАСТОЯЩЕГО Check, которым пользуется страж
// «отношение удовлетворяет действию» (Design-B). Реализует его дверь решения
// (internal/authzcascade) над реляционной формой. nil → страж — нефатальный
// пропуск (утверждения нет), так что неподключённый вычислитель старт не роняет.
//
// SubjectAdmitted стоит в том же порте, а не отдельным необязательным: дверь
// судит допуск субъекта ПЕРЕД отношением (#456, Р4а), и её «нет» на Check
// неподтверждённому человеку не говорит ничего о материализации. Страж, у
// которого спросить о допуске нечем, засчитал бы такой отказ потерей доступа
// (#610) — поэтому порт без вопроса о допуске невыразим.
type VerifyRelationChecker interface {
	SubjectAdmitted(ctx context.Context, subject string) (bool, error)
	Check(ctx context.Context, subject, relation, object string) (bool, error)
}

// ReasonRelationUnresolved — причина находки «материализованное чтение не
// разрешает требуемое отношение». Отказ допуска называется своей причиной —
// `admission.DenyReason`, тем же значением, которым его называет дверь.
const ReasonRelationUnresolved = "relation_unresolved"

// BindingRelationCheck — тройка Check требуемого отношения одной живой выдачи:
// субъект, отношение исполнения, которым каталог судит действие чтения выдачи
// (при Design-B — отношение v_*), и объект модели прав. Страж выполняет по ней
// НАСТОЯЩИЙ Check («отношение удовлетворяет действию»), а НЕ пробу присутствия в
// ведомости.
type BindingRelationCheck struct {
	BindingID domain.AccessBindingID
	Subject   string // "user:<id>" / "service_account:<id>"
	Relation  string // отношение исполнения (v_get / v_list / …)
	Object    string // "<fga_type>:<id>"
}

// BindingMaterialization — факты сверки одной выдачи: её id и ОЖИДАЕТСЯ ли от её
// роли материализация явных кортежей (глаголы «сама область» либо
// материализующий селектор). LedgerCount — записанное число явных кортежей.
type BindingMaterialization struct {
	BindingID     domain.AccessBindingID
	ExpectsTuples bool
	LedgerCount   int
}

// VerifyStore — узкий порт, нужный стражу. Реализует его pg BackfillAdapter.
type VerifyStore interface {
	// ListActiveBindingMaterialization возвращает для каждой АКТИВНОЙ выдачи,
	// ожидает ли она явной материализации, и текущее число её кортежей в ведомости
	// (одно чтение своей базы, без обращения на каждую выдачу).
	//
	// ОГРАНИЧЕНИЕ: ExpectsTuples выводится из СОБСТВЕННОГО вердикта сверщика
	// (active_members > 0). Поэтому оно ловит «АКТИВНЫЙ член есть, а ведомость
	// пуста» (член без кортежа), а НЕ «выдача ДОЛЖНА была материализовать ≥1 члена,
	// а дала 0» (потерянное членство, полный провал сведения). Эта слепая зона
	// закрыта для единственного класса, вычислимого БЕЗ ложных находок, — АКТИВНЫХ
	// выдач владельца уровня счёта, всегда материализующих ≥1 члена, — методом
	// ListOwnerBindingsMissingMembers ниже.
	ListActiveBindingMaterialization(ctx context.Context) ([]BindingMaterialization, error)

	// ListOwnerBindingsMissingMembers возвращает id АКТИВНЫХ выдач ВЛАДЕЛЬЦА уровня
	// счёта, у которых АКТИВНЫХ целевых членов НОЛЬ. Роль владельца (`*.*`),
	// выданная на уровне СЧЁТА, ВСЕГДА материализует ≥1 члена — своего члена «сама
	// область» на account:<A> (ScopeSelfVerbs роли владельца непусты, а счёт всегда
	// содержится в собственной области). Поэтому выдача владельца с 0 АКТИВНЫХ
	// членов — однозначно полный провал сведения (оператор молча потерял выдачу):
	// примета, которую Verify, выведенный из active_members, иначе не видит, и
	// вычислимая без ложных находок (законно пустые выдачи не отмечаются).
	ListOwnerBindingsMissingMembers(ctx context.Context) ([]domain.AccessBindingID, error)

	// ListActiveBindingRelationChecks возвращает для каждой АКТИВНОЙ выдачи,
	// материализовавшей ≥1 кортеж на объект, тройки (субъект, отношение исполнения,
	// объект), которые страж «отношение удовлетворяет действию» обязан проверить
	// настоящим Check. Отношение — v_*, которым каталог судит действие чтения
	// выдачи, поэтому страж доказывает, что материализованный кортеж действительно
	// СВОДИТСЯ к отношению, которое исполнит переключение, а не только что
	// ведомость непуста (слепая зона класса дефекта Design-A). Одно чтение своей
	// базы, без обращения на каждую выдачу.
	ListActiveBindingRelationChecks(ctx context.Context) ([]BindingRelationCheck, error)
}

// VerifyFailure — находка стража: выдача, ожидавшая явных кортежей при пустой
// ведомости, либо тройка, чьё отношение не разрешилось.
//
// Relation / Object / Subject НЕ дублируют Reason, а вынимают из него то, по чему
// разбирают журнал. Прежде отказ печатал одно число, а эти три величины жили
// внутри прозы и не выводились никогда — назвать несошедшуюся пару по журналу
// было невозможно (задача kacho#1865). Поля пусты у находок, у которых пары нет по
// построению (пустая ведомость привязки): пустое значение здесь означает
// «пары нет», а не «пара не названа».
type VerifyFailure struct {
	BindingID domain.AccessBindingID
	Reason    string
	Relation  string
	Object    string
	Subject   string
}

// verifyFailureLogCap — сколько пар называется поимённо, прежде чем остаток
// сворачивается в число.
//
// Предел, а не «печатать всё»: страж идёт на старте, и отказ по каждой привязке
// арендатора вылился бы в журнал, который никто не прочтёт. Предел, а не
// «печатать одно число»: остаток называется числом ЯВНО, поэтому усечение видно
// и не выдаёт себя за полный перечень.
const verifyFailureLogCap = 50

// logFailures называет КАЖДУЮ находку отдельной записью с полями.
//
// Поля, а не проза: разбирающий журнал отбирает по полю. Проза остаётся в
// reason — она объясняет, а не адресует.
//
// summary — поля сводки сверх общих двух (у сверки отношений — счёт по причинам).
func (g *VerifyGate) logFailures(ctx context.Context, msg string, report VerifyReport, summary ...any) {
	g.logger.WarnContext(ctx, msg,
		append([]any{
			slog.Int("failures", len(report.Failures)),
			slog.Int("bindings_checked", report.BindingsChecked),
		}, summary...)...)
	for i, f := range report.Failures {
		if i == verifyFailureLogCap {
			g.logger.WarnContext(ctx, "verify-gate: остаток находок не назван поимённо",
				slog.Int("named", verifyFailureLogCap),
				slog.Int("unnamed", len(report.Failures)-verifyFailureLogCap))
			break
		}
		attrs := []any{
			slog.String("binding_id", string(f.BindingID)),
			slog.String("reason", f.Reason),
		}
		if f.Relation != "" || f.Object != "" || f.Subject != "" {
			attrs = append(attrs,
				slog.String("relation", f.Relation),
				slog.String("object", f.Object),
				slog.String("subject", f.Subject))
		}
		g.logger.WarnContext(ctx, "verify-gate: находка", attrs...)
	}
}

// VerifyReport — вердикт стража.
type VerifyReport struct {
	// NoAccessLoss — true ⇒ каждая выдача, обязанная материализоваться, это
	// сделала (фаза контракта допустима).
	NoAccessLoss bool
	// BindingsChecked — сколько осмотрено живых выдач (у сверки отношений — троек).
	BindingsChecked int
	// Failures — находки: выдачи, ожидавшие явных кортежей и не получившие их, и
	// тройки, чьё отношение не разрешилось.
	Failures []VerifyFailure
	// Refusals — тройки, по которым отношение НЕ спрашивалось: субъект не допущен
	// к решению (адрес не подтверждён, #456 Р4а). Это не потеря материализации —
	// запись о выдаче есть и подействует после подтверждения, — и в NoAccessLoss
	// они не входят. Отдельным полем, а не находкой с другой прозой: потребитель
	// отчёта различает причины по полю, а не разбором текста.
	Refusals []VerifyRefusal
}

// VerifyRefusal — тройка, отвеченная отказом допуска субъекта, а не отношением.
type VerifyRefusal struct {
	BindingID domain.AccessBindingID
	Subject   string
	Relation  string
	Object    string
	// Reason — причина отказа; сейчас одна: admission.DenyReason.
	Reason string
}

// ByReason — счёт сверки отношений по каждой причине, включая ноль: «отказов
// допуска 0» обязано читаться так же явно, как «находок 0». Находки сверки
// ведомости (Verify) пары не несут и сюда не входят: у них своя сводка.
func (r VerifyReport) ByReason() map[string]int {
	out := map[string]int{
		ReasonRelationUnresolved: 0,
		admission.DenyReason:     0,
	}
	for _, f := range r.Failures {
		if f.Relation != "" || f.Object != "" || f.Subject != "" {
			out[ReasonRelationUnresolved]++
		}
	}
	for _, rf := range r.Refusals {
		out[rf.Reason]++
	}
	return out
}

// reasonAttrs — счёт по причинам полями записи журнала.
func (r VerifyReport) reasonAttrs() []any {
	by := r.ByReason()
	return []any{
		slog.Int(ReasonRelationUnresolved, by[ReasonRelationUnresolved]),
		slog.Int(admission.DenyReason, by[admission.DenyReason]),
	}
}

// VerifyGate — страж сверки перед фазой контракта.
type VerifyGate struct {
	store   VerifyStore
	logger  *slog.Logger
	checker VerifyRelationChecker // отношение разрешает действие; nil — пропуск
}

// NewVerifyGate собирает стража. Сведения он не зовёт и ничего не пишет: оба
// утверждения — чтение ведомости и настоящий Check (#148).
func NewVerifyGate(store VerifyStore, logger *slog.Logger) *VerifyGate {
	if logger == nil {
		logger = slog.Default()
	}
	return &VerifyGate{store: store, logger: logger}
}

// WithRelationChecker подключает порт настоящего Check, которым пользуется страж
// «отношение удовлетворяет действию». nil допустим: неподключённый проверяющий
// делает VerifyRelationSatisfiesAction нефатальным пропуском (старт не обязан
// падать, когда проверяющий отношения недоступен).
func (g *VerifyGate) WithRelationChecker(c VerifyRelationChecker) *VerifyGate {
	g.checker = c
	return g
}

// VerifyRelationSatisfiesAction — страж переключения Design-B: для КАЖДОЙ тройки
// требуемого отношения живой выдачи допущенного субъекта он выполняет НАСТОЯЩИЙ
// Check(субъект, отношение исполнения, объект) и сообщает NoAccessLoss=true
// ТОЛЬКО когда разрешены все 100 %; тройки недопущенного субъекта уходят в
// Refusals и вердикта не меняют. Это закрывает слепую зону, через которую прошёл
// класс дефекта Design-A: страж до Design-B доказывал лишь «материализация
// состоялась» (ведомость непуста), а НЕ «материализованный кортеж СВОДИТСЯ к
// отношению, которое исполняет каталог». Историческая ведомость только ярусов
// (без v_get) → Check(v_get) ОТКАЗЫВАЕТ → страж ПАДАЕТ, и переворот каталога
// закрыт, пока сверщик не дозаполнит v_*.
//
// nil вместо проверяющего → нефатальный пропуск: BindingsChecked=0,
// NoAccessLoss=true (утверждения нет); вызывающий пишет в журнал и продолжает
// (как и у прочих методов стража, работающих по мере возможности).
func (g *VerifyGate) VerifyRelationSatisfiesAction(ctx context.Context) (VerifyReport, error) {
	if g.checker == nil {
		g.logger.InfoContext(ctx, "verify-gate: relation-satisfies-action skipped (no FGA checker wired)")
		return VerifyReport{NoAccessLoss: true}, nil
	}
	checks, err := g.store.ListActiveBindingRelationChecks(ctx)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("verify-gate: list active binding relation checks: %w", err)
	}
	report := VerifyReport{NoAccessLoss: true, BindingsChecked: len(checks)}
	// Допуск спрашивается ОДИН раз на субъекта: он не зависит ни от отношения, ни
	// от объекта, а троек у одного человека — по числу его выдач.
	admitted := map[string]bool{}
	for _, c := range checks {
		ok, seen := admitted[c.Subject]
		if !seen {
			var aerr error
			ok, aerr = g.checker.SubjectAdmitted(ctx, c.Subject)
			if aerr != nil {
				// Третий исход — «спросить не смогли»: он не сливается ни с
				// допуском, ни с отказом.
				return VerifyReport{}, fmt.Errorf("verify-gate: допуск субъекта %s: %w", c.Subject, aerr)
			}
			admitted[c.Subject] = ok
		}
		if !ok {
			// Дверь ответила бы «нет», не вычисляя отношения: ответ про допуск, а
			// не про материализацию. Спрашивать отношение незачем.
			report.Refusals = append(report.Refusals, VerifyRefusal{
				BindingID: c.BindingID,
				Subject:   c.Subject,
				Relation:  c.Relation,
				Object:    c.Object,
				Reason:    admission.DenyReason,
			})
			continue
		}
		allowed, cerr := g.checker.Check(ctx, c.Subject, c.Relation, c.Object)
		if cerr != nil {
			return VerifyReport{}, fmt.Errorf("verify-gate: fga check %s#%s@%s: %w",
				c.Object, c.Relation, c.Subject, cerr)
		}
		if !allowed {
			report.NoAccessLoss = false
			report.Failures = append(report.Failures, VerifyFailure{
				BindingID: c.BindingID,
				Relation:  c.Relation,
				Object:    c.Object,
				Subject:   c.Subject,
				Reason: fmt.Sprintf("required relation %q on %s does NOT resolve for %s "+
					"(materialized read tuple does not resolve the enforced relation)",
					c.Relation, c.Object, c.Subject),
			})
		}
	}
	if !report.NoAccessLoss {
		g.logFailures(ctx, "verify-gate: materialized read tuples that do NOT resolve", report, report.reasonAttrs()...)
	} else {
		g.logger.InfoContext(ctx, "verify-gate: every materialized read tuple of an admitted subject resolves",
			append([]any{slog.Int("bindings_checked", report.BindingsChecked)}, report.reasonAttrs()...)...)
	}
	return report, nil
}

// Verify утверждает отсутствие потери доступа: у каждой живой выдачи, обязанной
// материализовать явные кортежи, ведомость непуста. Возвращает вердикт.
//
// Две взаимодополняющие проверки:
//   - член без кортежа: АКТИВНЫЙ член, чья ведомость выдачи пуста (сверщик его
//     активировал, но кортежа не выпустил).
//   - членов быть должно, а нет (примета): АКТИВНАЯ выдача ВЛАДЕЛЬЦА уровня счёта
//     с 0 АКТИВНЫХ членов — полный провал сведения, к которому слепа проверка,
//     выведенная из active_members. Сужено до выдач владельца, потому что они
//     ВСЕГДА материализуют ≥1 члена, и законно пустая выдача ложно не отмечается.
func (g *VerifyGate) Verify(ctx context.Context) (VerifyReport, error) {
	rows, err := g.store.ListActiveBindingMaterialization(ctx)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("verify-gate: list active binding materialization: %w", err)
	}
	report := VerifyReport{NoAccessLoss: true, BindingsChecked: len(rows)}
	for _, m := range rows {
		if m.ExpectsTuples && m.LedgerCount == 0 {
			report.NoAccessLoss = false
			report.Failures = append(report.Failures, VerifyFailure{
				BindingID: m.BindingID,
				Reason:    "binding expects explicit materialization but its ledger is empty (no-access-loss risk before contract)",
			})
		}
	}
	// Перекрёстная примета: выдача владельца, у которой должен быть ≥1 член, а нет
	// ни одного → регресс потерянного членства, невидимый выводу из active_members.
	missing, err := g.store.ListOwnerBindingsMissingMembers(ctx)
	if err != nil {
		return VerifyReport{}, fmt.Errorf("verify-gate: list owner bindings missing members: %w", err)
	}
	for _, bid := range missing {
		report.NoAccessLoss = false
		report.Failures = append(report.Failures, VerifyFailure{
			BindingID: bid,
			Reason:    "owner-binding materialized 0 members but must have ≥1 (scope-self) — wholesale reconcile failure (no-access-loss)",
		})
	}
	if !report.NoAccessLoss {
		g.logFailures(ctx, "verify-gate: no-access-loss FAILED — contract phase BLOCKED", report)
	} else {
		g.logger.InfoContext(ctx, "verify-gate: 100% no-access-loss — contract phase permitted",
			slog.Int("bindings_checked", report.BindingsChecked))
	}
	return report, nil
}
