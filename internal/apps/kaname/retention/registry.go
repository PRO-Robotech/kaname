// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package retention — уборка таблиц iam, чей рост задаёт внешний.
//
// Предмет — приёмка `docs/engineering/acceptance/
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

	"github.com/PRO-Robotech/corelib/outbox"
	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/pkg/subjectchange"

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
	// SubjectAccessTokens — записи выпуска токена доступа собственной церемонии
	// (kaname#319): идентификатор выпуска → семейство. Писать строку ОБЯЗАН
	// выпуск токена доступа церемонии (провязка — kaname#396); на этой ревизии
	// писателя на пути выдачи нет, и предмет пуст. Когда выпуск провязан, темп
	// задаёт арендатор: строка на каждый токен доступа, выданный обменом кода
	// или ротацией. Читают её поверхности предъявления, и каждая отвергает
	// истёкший токен по его сроку, поэтому строка за сроком токена ни одного
	// исхода не меняет.
	// #nosec G101 -- это ИМЯ ТАБЛИЦЫ, а не удостоверение: предмет уборки, он же
	// ключ реестра, наружу не уезжает ничем, кроме журнала прохода.
	SubjectAccessTokens = "access_tokens"
	// SubjectHumanSessions — записи нашей сессии человека, которые `Resolve`
	// уже не обслужит ни при каком носителе: истёкшие и снятые (Ф3-49).
	SubjectHumanSessions = "human_sessions"
	// SubjectLoginFailures — следы неверных предъявлений пароля старше самого
	// длинного окна счёта (Ф3 Р10).
	SubjectLoginFailures = "login_failures"
	// SubjectRecoveryCodes — коды восстановления, которые оператор применения
	// уже не обслужит: применённые и истёкшие (Ф5 Р1). Темп задаёт внешний:
	// строку заводит запрос восстановления по любому подтверждённому адресу,
	// а также по неподтверждённому адресу личности `ACTIVE` без способа входа
	// (Ф5 Р9).
	SubjectRecoveryCodes = "recovery_codes"
	// SubjectSecondFactorEnrollments — неподтверждённые заведения второго
	// фактора (Ф12-44, kacho#1281): строки `pending` старше окна свежести —
	// `confirm` их уже не примет ни при каком коде (Ф12-04). Темп задаёт сам
	// человек: строку заводит `enroll` под живой сессией.
	SubjectSecondFactorEnrollments = "second_factor_enrollments"
	// SubjectAccessKeyChallenges — испытания ключей доступа (Ф7, kacho#1273;
	// Р5, врезка Ф7-34): истёкшие и снятые — ни приём результата церемонии, ни
	// проверка утверждения их уже не обслужат. Темп задаёт сам человек: строку
	// заводит начало церемонии либо предъявления под живой сессией.
	SubjectAccessKeyChallenges = "access_key_challenges"
	// SubjectAccessKeyLoginChallenges — испытания ПОЛОСЫ ВХОДА ключом (Ф13,
	// kaname#613): своя таблица, привязанная к контексту формы.
	SubjectAccessKeyLoginChallenges = "access_key_login_challenges"
	// SubjectVerificationCodes — коды подтверждения адреса (kaname#456, Р7,
	// Р9): строки старше окна писем, которые ни предъявление, ни предел писем
	// уже не прочтут. Темп задаёт человек: строку заводит письмо подтверждения.
	SubjectVerificationCodes = "email_verification_codes"
	// SubjectEmailChangeCodes — отложенные смены адреса и их коды (kaname#635,
	// Р5, Р6): строки старше окна темпа, которые ни предъявление, ни темп уже
	// не прочтут. Темп задаёт человек: строку заводит принятый запрос смены.
	SubjectEmailChangeCodes = "email_change_codes"
	// SubjectSourceRequestWindows — окна обращений без удостоверения по
	// источнику (регистрация, запрос восстановления): строка на источник, темп
	// задаёт внешний.
	SubjectSourceRequestWindows = "source_request_windows"
	// SubjectBearerLetters — строки очереди писем с истёкшим кодом
	// (восстановление, подтверждение): открытое значение кода без предмета
	// снимается и у недоставленного письма.
	SubjectBearerLetters = "bearer_letters"
)

// HumanSessionReapers — ПЯТЬ уборщиков полосы входа (Ф3, Ф5, Ф12, Ф7): порог
// у второго — самое длинное окно счёта, у четвёртого — окно свежести правки
// своих данных, у пятого — срок испытания ключа; величины приходят
// параметром вместе с уборщиком, а не выписываются длительностью.
type HumanSessionReapers struct {
	Sessions         HumanSessionReaper
	Failures         LoginFailureReaper
	Codes            RecoveryCodeReaper
	Enrollments      EnrollmentReaper
	Challenges       AccessKeyChallengeReaper
	LongestWindow    time.Duration
	EnrollmentWindow time.Duration
	// ChallengeTTL — срок испытания ключа доступа, величина КОНТРАКТА (врезка
	// Ф7-34); порог уборки испытаний. Нулевой порог снимал бы предъявленное
	// испытание первым же проходом, и повтор читался бы «не выдавалось».
	ChallengeTTL time.Duration
	// LoginChallenges — уборщик испытаний ПОЛОСЫ ВХОДА ключом (Ф13,
	// kaname#613); nil — полоса входа ключом не провязана, и предмета уборки
	// у реестра нет (таблица пустует by construction).
	LoginChallenges AccessKeyLoginChallengeReaper
	// Подтверждение адреса (kaname#456): коды, окна источника, письма с
	// истёкшим кодом; LetterWindow — окно писем подтверждения, SourceWindow —
	// окно обращений источника.
	VerificationCodes VerificationCodeReaper
	SourceWindows     SourceWindowReaper
	BearerLetters     BearerLetterReaper
	LetterWindow      time.Duration
	SourceWindow      time.Duration
	// EmailChangeCodes — уборщик отложенных смен адреса (kaname#635); порог —
	// LetterWindow: смена считает темп теми же величинами. nil — глагол смены
	// не провязан, и предмета уборки у реестра нет.
	EmailChangeCodes EmailChangeCodeReaper
}

// EmailChangeCodeReaper — порт уборщика отложенных смен адреса.
type EmailChangeCodeReaper interface {
	SweepUnservableEmailChangeCodes(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// VerificationCodeReaper — порт уборщика кодов подтверждения адреса.
type VerificationCodeReaper interface {
	SweepUnservableVerificationCodes(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// SourceWindowReaper — порт уборщика окон обращений источника.
type SourceWindowReaper interface {
	SweepAgedSourceWindows(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// BearerLetterReaper — порт уборщика писем с истёкшим кодом.
type BearerLetterReaper interface {
	SweepExpiredBearerLetters(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// HumanSessionReaper — порт уборщика истёкших и снятых записей сессии.
type HumanSessionReaper interface {
	SweepUnservableSessions(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// LoginFailureReaper — порт уборщика следов неверных предъявлений.
type LoginFailureReaper interface {
	SweepAgedFailures(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// RecoveryCodeReaper — порт уборщика применённых и истёкших кодов восстановления.
type RecoveryCodeReaper interface {
	SweepUnservableRecoveryCodes(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// EnrollmentReaper — порт уборщика неподтверждённых заведений второго фактора:
// `window` — окно свежести; строка `pending` старше него снимается.
type EnrollmentReaper interface {
	SweepExpiredEnrollments(ctx context.Context, window time.Duration, batch int) (int64, bool, error)
}

// AccessKeyChallengeReaper — порт уборщика истёкших и снятых испытаний ключей.
type AccessKeyChallengeReaper interface {
	SweepUnservableChallenges(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// AccessKeyLoginChallengeReaper — порт уборщика истёкших и предъявленных
// испытаний полосы входа ключом.
type AccessKeyLoginChallengeReaper interface {
	SweepUnservableLoginChallenges(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

// WithHumanSessions — записи реестра полосы входа поверх базовых. Отдельной
// функцией, а не параметрами `Subjects`: уборщики приходят от собранной полосы,
// и неполный их набор — отказ, а не уборщик без предмета, который выглядел бы
// исправным.
func WithHumanSessions(base []Subject, r HumanSessionReapers) []Subject {
	if r.Sessions == nil || r.Failures == nil || r.Codes == nil || r.Enrollments == nil || r.Challenges == nil || r.EnrollmentWindow <= 0 || r.ChallengeTTL <= 0 ||
		r.VerificationCodes == nil || r.SourceWindows == nil || r.BearerLetters == nil || r.LetterWindow <= 0 || r.SourceWindow <= 0 {
		return base
	}
	subjects := append(base,
		Subject{
			Name: SubjectHumanSessions,
			// Порог — функция предиката читателя: запись годна к снятию, как
			// только `Resolve` её не обслужит, и не раньше; запаса сверх срока
			// не нужно — момент истечения ВКЛЮЧАЮЩИЙ и у читателя, и у уборки.
			Grace: 0,
			Sweep: r.Sessions.SweepUnservableSessions,
		},
		Subject{
			Name:  SubjectLoginFailures,
			Grace: r.LongestWindow,
			Sweep: r.Failures.SweepAgedFailures,
		},
		Subject{
			Name: SubjectRecoveryCodes,
			// Порог — предикат читателя: оператор применения не обслужит ни
			// истёкшую, ни применённую строку, и запаса сверх срока не нужно —
			// граница срока включающая и у оператора, и у уборки.
			Grace: 0,
			Sweep: r.Codes.SweepUnservableRecoveryCodes,
		},
		Subject{
			Name: SubjectSecondFactorEnrollments,
			// Порог — предикат читателя: `confirm` не примет `pending` старше
			// окна свежести (Р8 — срок заведения равен окну), и уборщик снимает
			// ровно то, что читатель уже отверг; запаса сверх окна не нужно.
			Grace: r.EnrollmentWindow,
			Sweep: r.Enrollments.SweepExpiredEnrollments,
		},
		Subject{
			Name: SubjectAccessKeyChallenges,
			// Порог — срок испытания, а не ноль. Истёкшее и предъявленное
			// испытание не ПРИМЕТ ни приём результата церемонии, ни проверка
			// утверждения, но приём результата его ЧИТАЕТ: три состояния
			// (просрочено · не выдавалось · уже предъявлено) вызывающему
			// различимы (Ф7-34), повтор отвергается как однократное (Ф7-03), и
			// различимость держит только хранение строки — снятая читается
			// как «не выдавалось». Порог в срок испытания хранит предъявленную
			// строку не меньше, чем она прожила бы непредъявленной
			// (consumed_at ≥ issued_at), а истёкшую — ещё один срок (kaname#590).
			Grace: r.ChallengeTTL,
			Sweep: r.Challenges.SweepUnservableChallenges,
		},
		Subject{
			Name: SubjectVerificationCodes,
			// Порог — окно писем: строки кодов считают предел писем за окно, и
			// снятая раньше строка удлинила бы предел.
			Grace: r.LetterWindow,
			Sweep: r.VerificationCodes.SweepUnservableVerificationCodes,
		},
		Subject{
			Name: SubjectSourceRequestWindows,
			// Порог — окно источника: вышедшее окно начинается заново.
			Grace: r.SourceWindow,
			Sweep: r.SourceWindows.SweepAgedSourceWindows,
		},
		Subject{
			Name: SubjectBearerLetters,
			// Порог — срок кода, записанный в строке: запаса сверх него не нужно.
			Grace: 0,
			Sweep: r.BearerLetters.SweepExpiredBearerLetters,
		},
	)
	if r.EmailChangeCodes != nil {
		subjects = append(subjects, Subject{
			Name: SubjectEmailChangeCodes,
			// Порог — окно темпа: строки принятых запросов считают предел за
			// окно, и снятая раньше строка удлинила бы предел.
			Grace: r.LetterWindow,
			Sweep: r.EmailChangeCodes.SweepUnservableEmailChangeCodes,
		})
	}
	if r.LoginChallenges != nil {
		subjects = append(subjects, Subject{
			Name: SubjectAccessKeyLoginChallenges,
			// Порог — ноль: оператор однократности полосы входа не обслужит ни
			// истёкшую, ни предъявленную строку, а три состояния испытания
			// наружу НЕ различаются (Ф13 Р7 — один отказ), и хранить строку
			// ради различимости незачем.
			Grace: 0,
			Sweep: r.LoginChallenges.SweepUnservableLoginChallenges,
		})
	}
	return subjects
}

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

// AccessTokenReaper — порт уборщика записей выпуска токена доступа.
type AccessTokenReaper interface {
	SweepExpiredAccessTokens(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
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
//	уборка выпусков:     expires_at     <  now() − (ClockSkew + RemovalSlack)
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
	accessTokens AccessTokenReaper,
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
		{
			// Порог — предикат ЧИТАТЕЛЕЙ: каждая поверхность предъявления
			// отвергает истёкший токен по его сроку с допуском ClockSkew, а
			// RemovalSlack — запас на расхождение часов уборки (база) и часов
			// поверхности (процесс). Того же вида, что порог утверждений клиента:
			// предмет обоих — «после срока с допуском строка ничего не решает».
			Name:  SubjectAccessTokens,
			Grace: tokenpolicy.ClockSkew + tokenpolicy.RemovalSlack,
			Sweep: accessTokens.SweepExpiredAccessTokens,
		},
	}
}
