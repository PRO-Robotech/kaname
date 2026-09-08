// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package retention — уборка таблиц iam, чей рост задаёт внешний.
//
// Предмет — приёмка `services/iam/docs/engineering/acceptance/
// retention-sweep-has-a-caller.md` (задача #1292). Три таблицы росли без
// ограничения: у двух уборщик был ОБЪЯВЛЕН и не имел ни одного прод-вызывающего,
// у третьей уборщика не было вовсе. Восемь мест дерева при этом утверждали в
// настоящем времени, что сборщик работает.
//
// # Почему ОДНА петля, а не три
//
// Три петли — три расписания об одном предмете, и они расходятся молча. Петля
// владеет РЕЕСТРОМ: каждая запись называет предмет, порог и уборщика. Добавление
// уборщика — одна запись, а не новая петля.
//
// # Порог — функция предиката ЧИТАТЕЛЯ, а не свойство колонки срока
//
// Строку позволено снять не раньше момента, после которого НИ ОДИН читатель не
// изменил бы из-за неё своего исхода. Порог есть ПАРА «величина + источник
// часов»: уборщик и читатель обязаны судить одними часами, а разница источников
// входит в порог отдельным слагаемым и берётся из объявленной величины, а не
// выписывается числом (§2.2 приёмки).
//
// Часы уборки — БАЗЫ у КАЖДОГО предмета: момент времени не входит в сигнатуру
// уборщика, предикат целиком в SQL. Это идиома дерева, а не изобретение — все
// уборщики, у которых вызывающий есть, приняли ровно эту форму. Входом момент
// принимали ровно два, и это были те самые два, у которых вызывающего не было.
package retention

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kacho/pkg/outbox"
	"github.com/PRO-Robotech/kacho/pkg/subjectchange"
	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/reconcile_outbox"
)

// Имена предметов уборки. Совпадают с именами таблиц: имя предмета попадает в
// отчёт прохода и в метку метрики, и оператор обязан узнавать в нём таблицу.
const (
	// SubjectClientAssertionReplay — однократность предъявленных утверждений
	// клиента. Темп задаёт предъявитель.
	SubjectClientAssertionReplay = "client_assertion_replay"
	// SubjectSessionRevocations — отзыв по идентификатору токена. Темп задают
	// пользователь (выход) и администратор (принудительный выход).
	SubjectSessionRevocations = "session_revocations"
	// SubjectMintedTokenCutoffs — отсечки по субъекту. Темп задаёт арендатор:
	// строку пишет триггер на удалении ключа клиента, а каждый отозванный ключ
	// даёт НОВЫЙ субъект — слияние по первичному ключу здесь не помогает.
	// #nosec G101 -- это ИМЯ ТАБЛИЦЫ, а не удостоверение: слово `revocations`
	// в строке ловит образец инструмента, но значение здесь — предмет уборки,
	// он же ключ реестра, и наружу не уезжает ничем, кроме журнала прохода.
	SubjectMintedTokenCutoffs = "minted_token_revocations"
	// SubjectIdentityAdmissionWindows — окна темпа заведения аккаунтов. Темп
	// задаёт внешний: строку заводит первое же заведение аккаунта носителем
	// внешней личности, а окно, ради счётчика которого строка живёт, двигается
	// ВНУТРИ неё — значит строк ровно столько, сколько личностей побывало на
	// установке за всю её жизнь.
	SubjectIdentityAdmissionWindows = "identity_admission_windows"
	// SubjectSubjectChangeJournal — журнал смены субъекта. Темп задаёт арендатор:
	// строка пишется в той же транзакции, что снятие привязки и смена состава
	// группы. Читает её КРАЙ курсором по позиции, поэтому порог выводится из
	// наибольшего допустимого отставания читателя, а не из свойства колонки
	// срока.
	SubjectSubjectChangeJournal = "subject_change_outbox"
	// SubjectReconcileOutbox — очередь сверки прав. Темп задаёт арендатор:
	// строка пишется в той же транзакции, что смена состояния зеркала ресурса,
	// то есть на каждую регистрацию и снятие регистрации.
	//
	// До #2050 дренированные строки не снимались НИКОГДА: таблица росла
	// неограниченно под штатным потоком регистраций, при том что приём уборки в
	// дереве уже был и применён к соседней очереди.
	SubjectReconcileOutbox = "resource_reconcile_outbox"
	// SubjectProviderCompensationOutbox — очередь компенсаций у внешнего
	// провайдера. Темп задаёт арендатор: строка пишется в writer-транзакции
	// мутации, снимающей клиента либо доверенную выдачу у провайдера.
	//
	// До #2069 доставленные строки не снимались НИКОГДА, и реестр роста таблиц
	// объявлял таблицу ДОЛГОМ, назвав условие легализации: предикат ей нужен
	// СВОЙ и более простой, чем у общего уборщика платформы, а послабление
	// обязано нести гейт, который покраснеет с появлением оживителя.
	SubjectProviderCompensationOutbox = "provider_compensation_outbox"
)

// SweepFunc — один проход уборщика по одному предмету.
//
// `grace` — слагаемое порога: уборщик снимает строки, чей срок истёк РАНЬШЕ чем
// `now() − grace` часами БАЗЫ. Момент времени параметром не приходит намеренно.
//
// Возвращает число снятых строк и признак «партия ушла полной». Признак — не
// удобство: без него проход не отличает «убрал всё, что было» от «упёрся в
// партию», и уборка со скоростью одна партия за тик не догоняла бы внешний темп
// НИКОГДА, оставаясь зелёной по всякой проверке «вызвался ли».
type SweepFunc func(ctx context.Context, grace time.Duration, batch int) (removed int64, full bool, err error)

// Subject — запись реестра: предмет, порог и уборщик.
type Subject struct {
	// Name — имя предмета из констант выше.
	Name string
	// Grace — слагаемое порога. ВЫЧИСЛЯЕТСЯ из `pkg/tokenpolicy`, а не
	// выписывается длительностью: копия разошлась бы с политикой молча и в
	// ОПАСНУЮ сторону — политика удлиняет допуск, копия остаётся прежней и
	// снимает строку, которая ещё держит однократность. Держит это гейт
	// `TestRegistryThresholdsFollowPolicyRatherThanACopy`.
	Grace time.Duration
	// Sweep — сам уборщик.
	Sweep SweepFunc
}

// AssertionReaper — порт уборщика однократности предъявленных утверждений.
type AssertionReaper interface {
	Reap(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// RevocationReaper — порт уборщика отзывов по идентификатору токена.
type RevocationReaper interface {
	DeleteExpired(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// CutoffReaper — порт уборщика отсечек по субъекту.
type CutoffReaper interface {
	SweepStaleCutoffs(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// AdmissionWindowReaper — порт уборщика окон темпа заведения.
type AdmissionWindowReaper interface {
	SweepElapsedAdmissionWindows(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// SubjectChangeJournalReaper — порт уборщика журнала смены субъекта.
type SubjectChangeJournalReaper interface {
	SweepAgedRows(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// CompensationOutboxReaper — порт уборщика очереди компенсаций у провайдера.
type CompensationOutboxReaper interface {
	SweepDeliveredCompensations(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// ReconcileOutboxReaper — порт уборщика очереди сверки прав.
type ReconcileOutboxReaper interface {
	SweepDrainedReconcileEvents(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// Subjects — реестр уборки iam.
//
// Пороги — §2.2 приёмки, и повторять их вторым местом нельзя: два места об одном
// числе разошлись бы молча.
//
//	уборка утверждений:  expires_at     <= now() − (ClockSkew + RemovalSlack)
//	уборка отзывов:      ttl_expires_at <= now()
//	уборка отсечек:      revoke_before  <  now() − (MaxTokenTTL + ClockSkew + RemovalSlack)
//	уборка окон темпа:   window_started_at < now() − window_seconds − 0
//	уборка журнала:      created_at     <  now() − subjectchange.JournalRetention
//	уборка очереди сверки: sent_at      <  now() − reconcile_outbox.DrainedRetention
//	уборка компенсаций:    sent_at      <  now() − outbox.DeliveredRetention
//
// У отзывов слагаемых НЕТ, и это не пропуск: часы уборки и всех четырёх её
// читателей уже одни — база, — поэтому запасу взяться неоткуда. Ноль здесь
// объявлен явно, чтобы «слагаемое забыли» было отличимо от «слагаемого не
// бывает»; держит это RET-SWP-04, где третья запись стоит контролем.
//
// У окон темпа слагаемых нет по той же мерке, а несущая часть их порога —
// `window_seconds` — в реестр НЕ ПОПАДАЕТ намеренно: это величина, которую
// владелец облака меняет строкой без выката, и уборщик читает её из той же
// действующей строки, что и читатель-триггер. Копия здесь разошлась бы с
// авторитетом молча и в опасную сторону — уборщик снимал бы строку, чьё окно
// ещё идёт. Разбор — шапка `SweepElapsedAdmissionWindows`; здесь он не
// пересказывается.
// У журнала смены субъекта слагаемых тоже нет, и по той же мерке: `created_at`
// ставится умолчанием колонки, то есть часами БАЗЫ, и уборка судит теми же
// часами. Несущая часть его порога — [subjectchange.JournalRetention] — берётся
// у ЧИТАТЕЛЯ, а не выписывается здесь: копия разошлась бы с ним молча и в
// опасную сторону, снимая строки, которые читатель ещё вправе получить.
func Subjects(
	assertions AssertionReaper,
	revocations RevocationReaper,
	cutoffs CutoffReaper,
	admissionWindows AdmissionWindowReaper,
	subjectChangeJournal SubjectChangeJournalReaper,
	reconcileOutbox ReconcileOutboxReaper,
	compensationOutbox CompensationOutboxReaper,
) []Subject {
	return []Subject{
		{
			Name:  SubjectClientAssertionReplay,
			Grace: tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack,
			Sweep: assertions.Reap,
		},
		{
			Name:  SubjectSessionRevocations,
			Grace: 0,
			Sweep: revocations.DeleteExpired,
		},
		{
			Name:  SubjectMintedTokenCutoffs,
			Grace: tokenpolicy.MaxTokenTTL + tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack,
			Sweep: cutoffs.SweepStaleCutoffs,
		},
		{
			Name:  SubjectIdentityAdmissionWindows,
			Grace: 0,
			Sweep: admissionWindows.SweepElapsedAdmissionWindows,
		},
		{
			Name:  SubjectSubjectChangeJournal,
			Grace: subjectchange.JournalRetention,
			Sweep: subjectChangeJournal.SweepAgedRows,
		},
		{
			Name:  SubjectReconcileOutbox,
			Grace: reconcile_outbox.DrainedRetention,
			Sweep: reconcileOutbox.SweepDrainedReconcileEvents,
		},
		{
			// Порог берётся у СЕМЬИ, а не объявляется здесь седьмым числом:
			// [outbox.DeliveredRetention] выведен из читателя доставленной
			// строки очереди дренажа — оператора, разбирающего «доехало ли
			// снятие», — и эта очередь ровно того же рода. Своя копия величины
			// разошлась бы с семьёй молча.
			Name:  SubjectProviderCompensationOutbox,
			Grace: outbox.DeliveredRetention,
			Sweep: compensationOutbox.SweepDeliveredCompensations,
		},
	}
}
