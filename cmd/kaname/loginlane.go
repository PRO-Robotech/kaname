// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// loginlane.go — КОМПОЗИЦИЯ полосы входа паролем и нашей сессии (фаза Ф3,
// задача PRO-Robotech/kacho#1269; приёмка
// `docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`,
// Р15, Ф3-44, Ф3-45), регистрации той же полосой (фаза Ф4, kacho#1270) и
// восстановления доступа на ней же (фаза Ф5, задача PRO-Robotech/kacho#1271).
// Глагол регистрации собирается здесь же, для полосы из объявления
// `registration.Lanes`, с тем же правилом пароля, хешером, сроком сессии и
// наблюдателем; восстановление берёт те же хранилища, хешер и правило пароля,
// те же величины частоты, а своё у него — срок кода и диспетчер постановки
// письма вне пути ответа (Ф5 Р2).
//
// # Поднимается ПОСАДКОЙ
//
// Под `own` полоса — условие старта: хранилища провязаны, слушатель формы
// поднят в режиме `mutual` на объявленном адресе, `Resolve` зарегистрирован на
// внутреннем слушателе. Под `external` полосы нет вовсе: вход человека
// проверяет поставщик, и наша полоса рядом с ним была бы вторым входом об одном
// предмете. «Нет» здесь — nil-объект, и наблюдатель провязки сообщает о нём
// честно (`HumanSessionsWired: false`), а не литералом.
//
// # Порт стража памяти — чтение cgroup
//
// Предел памяти среды берётся у контейнера (cgroup v2 `memory.max`, v1
// `memory.limit_in_bytes`), а не у настройки: величину, которую страж сверяет с
// собственной арифметикой, оператор не должен иметь возможности «подставить»
// в обход среды. Не наложен — отказ старта с числами (Ф3-42 г).

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/servicecontract"
	reconcileapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/retention"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/clients/breachcheck"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// knobLoginLane — ручка адреса слушателя полосы формы.
const knobLoginLane = "KANAME_API_SERVER__LOGIN_LANE_ENDPOINT"

// breachCheckTimeout — потолок одного обращения к авторитету утечек.
const breachCheckTimeout = 5 * time.Second

// recoveryDispatchTimeout — предел одной постановки письма восстановления вне
// пути ответа: запись двух строк одной транзакцией, а не разговор с узлом.
const recoveryDispatchTimeout = 30 * time.Second

// envelopeCensusTimeout — предел переписи классов стоимости при старте: один
// последовательный проход по таблице способов (индекса по материалу нет
// намеренно — шапка её миграции). Калибровка классов в этот срок не входит:
// у неё свой предел ниже.
const envelopeCensusTimeout = 60 * time.Second

// envelopeCalibrationTimeout — предел калибровки ОДНОГО класса: пять прогонов
// плюс построение значения; класс на потолке наследуемого формата (bcrypt 14)
// стоит около секунды на прогон на машине разработки, на слабом поде — больше.
const envelopeCalibrationTimeout = 2 * time.Minute

// loginLane — всё, что корень собирает под полосу; nil — полосы нет.
type loginLane struct {
	handler    *loginlanehttp.Handler
	resolve    *humansession.Handler
	sessions   *kanamepg.HumanSessionRepo
	methods    *kanamepg.LoginMethodRepo
	limits     humansession.Limits
	dispatcher *humansession.GoDispatcher
	// freshness — окно свежести правки своих данных (Ф12 Р8): срок `pending`
	// и порог уборки заведений — та же величина.
	freshness time.Duration
	// keys — хранилище ключей доступа и их испытаний (Ф7, kacho#1273): служба
	// ключей поднимается вместе с полосой — окно свежести (Р5) и предъявление
	// судятся о сессии, которой под `external` нет.
	keys *kanamepg.AccessKeyRepo
	// keyFreshness — окно свежести вызывающего по его живым сессиям (Ф7 Р5):
	// читатель того же хранилища сессий, что и полоса.
	keyFreshness *kanamepg.HumanSessionFreshness
	// verifier — проверяющий пароля полосы; его ёмкость — бюджет памяти
	// процесса, и проверяющий секрета клиента церемонии делит её
	// (`passwordverify.Verifier.SharingCapacity`, LINE-A-1).
	verifier *passwordverify.Verifier
}

// secretVerifier — проверяющий секрета конфиденциального клиента церемонии:
// та же ёмкость, свой приёмник исходов. nil-полоса — nil: церемонии без
// своего входа нет.
func (l *loginLane) secretVerifier(observer passwordverify.Observer) (*passwordverify.Verifier, error) {
	if l == nil || l.verifier == nil {
		return nil, nil
	}
	return l.verifier.SharingCapacity(observer)
}

// drain — дождаться постановок письма, начатых до гашения (Ф5 Р2): ответ их не
// ждал, гашение — ждёт. nil-полоса — нечего ждать.
func (l *loginLane) drain() {
	if l == nil || l.dispatcher == nil {
		return
	}
	l.dispatcher.Wait()
}

// loginLaneWanted — поднимается ли полоса на этой посадке: ровно под `own`.
func loginLaneWanted(cfg config.Config) bool {
	return cfg.AuthN.IdentityProvider == config.IdentityProviderOwn
}

// wired — хранилища полосы провязаны (наблюдение для посадки, `kaname#21`).
func (l *loginLane) wired() bool { return l != nil && l.sessions != nil && l.methods != nil }

// signInMethods — способы входа человека, чьи проверяющие собраны ЭТИМ корнем:
// пароль, код по времени и запасной код (Ф12): проверяющие обоих кодов
// собираются вместе с полосой, поэтому пока полоса поднята — собраны все три.
func (l *loginLane) signInMethods() []assurance.Method {
	if !l.wired() {
		return nil
	}
	return []assurance.Method{assurance.MethodPassword, assurance.MethodTOTP, assurance.MethodLookupSecret}
}

// laneWiringOf — вклад полосы в наблюдение провязки.
func laneWiringOf(l *loginLane) config.LaneWiring {
	return config.LaneWiring{HumanCredentialsWired: l.wired(), HumanSessionsWired: l.wired()}
}

// resetSecondFactorUseCase — сброс второго фактора распорядителем (Ф12 Р10)
// теми же хранилищами, что полоса: чтение строки способа — хранилище способов,
// снятие/отсечка/событие — писатель хранилища сессий; nil — полосы нет.
func (l *loginLane) resetSecondFactorUseCase(repo kanamerepo.Repository, opsRepo operations.Repo) *userapp.ResetSecondFactorUseCase {
	if !l.wired() {
		return nil
	}
	return userapp.NewResetSecondFactorUseCase(repo, opsRepo, l.methods, secondFactorResetStore{sessions: l.sessions})
}

// secondFactorResetStore — адаптер хранилища сессий к порту сброса: писатель
// сессии несёт все четыре операции порта, соответствие закрепляется здесь.
type secondFactorResetStore struct{ sessions *kanamepg.HumanSessionRepo }

func (s secondFactorResetStore) ResetWriter(ctx context.Context) (userapp.SecondFactorResetWriter, error) {
	return s.sessions.Writer(ctx)
}

// resolveHandler — `Resolve` для внутреннего слушателя; nil — полосы нет.
func (l *loginLane) resolveHandler() *humansession.Handler {
	if l == nil {
		return nil
	}
	return l.resolve
}

// retentionReapers — уборщики полосы для реестра уборки (форма Ф-ж).
func (l *loginLane) retentionReapers() retention.HumanSessionReapers {
	if !l.wired() {
		return retention.HumanSessionReapers{}
	}
	return retention.HumanSessionReapers{
		Sessions: l.sessions, Failures: l.sessions, Codes: l.sessions, LongestWindow: l.limits.LongestWindow(),
		Enrollments: l.methods, EnrollmentWindow: l.freshness,
		Challenges: l.keys,
	}
}

// accessKeyHandler — шесть глаголов ключа доступа (Ф7, kacho#1273) теми же
// хранилищами, что полоса: свежесть — по сессиям, «последний способ» — по
// строкам способов; nil — полосы нет (под `external` служба не регистрируется
// и привязка фронта ведёт к `Unimplemented`).
//
// Привязка (имя доверяющей стороны, происхождения, алгоритмы) — из посадки,
// прошедшей стража старта (`AccessKeysConfig.Validate` в требованиях полосы);
// окно свежести — то же, что у правки своих данных (Р5).
func (l *loginLane) accessKeyHandler(cfg config.Config, opsRepo operations.Repo, reg *metrics.Registry, logger *slog.Logger) (*access_keys.Handler, error) {
	if !l.wired() || l.keys == nil || l.keyFreshness == nil {
		return nil, nil
	}
	deps := access_keys.Deps{
		Store:           l.keys,
		Freshness:       l.keyFreshness,
		Methods:         l.methods,
		Binding:         cfg.AuthN.AccessKeys.Binding(),
		FreshnessWindow: cfg.AuthN.SelfServiceFreshness,
		Observer:        reg.AccessKeyRecorder(),
		Now:             time.Now,
		Logger:          logger,
	}
	h, err := access_keys.NewHandler(deps, opsRepo)
	if err != nil {
		return nil, fmt.Errorf("access keys: %w", err)
	}
	logger.Info("access keys wired",
		"rp_id", deps.Binding.RPID, "origins", len(deps.Binding.Origins), "nobody", cfg.AuthN.AccessKeys.Nobody(),
		"algorithms", len(deps.Binding.Algorithms))
	return h, nil
}

// requireLoginLaneTLS — страж посадки `own` (Ф3-44 в): адрес объявлен, TLS
// включён, режим `mutual`. Под `external` и вне production — no-op.
func requireLoginLaneTLS(productionMode bool, cfg config.Config, mtlsCfg config.MTLSConfig) error {
	if !productionMode || !loginLaneWanted(cfg) {
		return nil
	}
	if strings.TrimSpace(cfg.APIServer.LoginLaneEndpoint) == "" {
		return fmt.Errorf("%s=%s requires the password sign-in lane listener, and its address is not declared "+
			"(set %s, e.g. tcp://0.0.0.0:9100 — a port of its own, distinct from the REST fronts): on this posture no other component lets a person sign in",
			config.IdentityProviderSetting, config.IdentityProviderOwn, knobLoginLane)
	}
	if !mtlsCfg.LoginLaneServerMTLS.Enable {
		return fmt.Errorf("%s=%s requires TLS on the sign-in lane listener %s "+
			"(set KANAME_LOGINLANE_SERVER_MTLS_ENABLE=true with its cert/key and client CA): the lane admits "+
			"exactly the edge by its verified client certificate, and without TLS there is no certificate to judge",
			config.IdentityProviderSetting, config.IdentityProviderOwn, cfg.APIServer.LoginLaneEndpoint)
	}
	if !mtlsCfg.LoginLaneRequiresClientCert() {
		return fmt.Errorf("%s=%s requires the sign-in lane listener in mode %q, got %q "+
			"(set KANAME_LOGINLANE_SERVER_MTLS_CLIENTAUTHMODE=%s): admission of exactly the edge is judged by the "+
			"SAN of a verified client certificate, and any other mode leaves the lane open to every peer",
			config.IdentityProviderSetting, config.IdentityProviderOwn, config.InternalRESTMutualModeName(),
			mtlsCfg.LoginLaneClientAuthModeValue(), config.InternalRESTMutualModeName())
	}
	return nil
}

// memoryLimitFiles — где среда объявляет предел памяти контейнера.
var memoryLimitFiles = []string{
	"/sys/fs/cgroup/memory.max",
	"/sys/fs/cgroup/memory/memory.limit_in_bytes",
}

// cgroupV1Unlimited — величина, которой cgroup v1 обозначает «без предела»
// (PAGE_COUNTER_MAX × страница на 64-битной системе).
const cgroupV1Unlimited = uint64(9223372036854771712)

// readMemoryLimit — предел памяти среды; ok=false — предел не наложен либо не
// прочитан. Первое читаемое объявление побеждает.
func readMemoryLimit(files []string) (uint64, bool) {
	for _, f := range files {
		raw, err := os.ReadFile(f) // #nosec G304 -- перечень путей объявлен в коде, не приходит с входа
		if err != nil {
			continue
		}
		s := strings.TrimSpace(string(raw))
		if s == "max" {
			return 0, false
		}
		v, perr := strconv.ParseUint(s, 10, 64)
		if perr != nil || v == 0 || v >= cgroupV1Unlimited {
			return 0, false
		}
		return v, true
	}
	return 0, false
}

// writeProbeFile — запись файла пробы стража памяти (только для проб).
func writeProbeFile(path, body string) error {
	return os.WriteFile(path, []byte(body), 0o600)
}

// envelopeReport — самоотчёт калибровки огибающей при старте (Ф3-31, решение
// kaname#188): что прочитано, что калибровано, что не читается.
type envelopeReport struct {
	// RowsCounted — строк способа «пароль» в хранилище, по переписи.
	RowsCounted int64
	// ClassesCalibrated — классов, калиброванных этим стартом (перепись ∪
	// ручка; класс ручки, лежащий и в хранилище, считается один раз).
	ClassesCalibrated int
	// UnreadableRows / UnreadablePrefixes — строк и префиксов переписи, чей
	// класс проверяющий не читает: признак вне перечня, негодная стоимость,
	// выше потолка записи. Находка о хранилище, не отказ старта: отказ входа
	// по таким строкам приходит без вычисления (ID-PW-1 Р4, PWV-04/05/14).
	UnreadableRows     int64
	UnreadablePrefixes int
	// Floor — потолок после калибровки; CeilingClass — класс-потолок.
	Floor        time.Duration
	CeilingClass string
}

// calibrateLoginEnvelope — огибающая по потолку ФАКТИЧЕСКОЙ популяции: каждый
// читаемый класс переписи хранилища и класс ручки «что писать» — калибровкой
// (повод `startup`). Класс ручки, который проверяющий не читает, — отказ:
// огибающей, не покрывающей то, что продукт сам пишет, не бывает.
func calibrateLoginEnvelope(ctx context.Context, envelope *passwordverify.Envelope,
	census []loginmethod.CostClassCount, declared domain.PasswordCostClass, logger *slog.Logger,
) (envelopeReport, error) {
	var report envelopeReport
	admit := func(class domain.PasswordCostClass) (passwordverify.Admission, error) {
		cctx, cancel := context.WithTimeout(ctx, envelopeCalibrationTimeout)
		defer cancel()
		return envelope.Admit(cctx, class, passwordverify.EnvelopeTriggerStartup)
	}
	for _, row := range census {
		report.RowsCounted += row.Rows
		class, err := passwordverify.ParseCostClassPrefix(row.Prefix)
		if err != nil {
			report.UnreadableRows += row.Rows
			report.UnreadablePrefixes++
			logger.Error("sign-in lane timing envelope: stored class is not readable by the verifier — a finding about the store, not a refusal to start",
				"rows", row.Rows, "err", err.Error())
			continue
		}
		adm, err := admit(class)
		var unreadable *passwordverify.ClassNotReadableError
		switch {
		case errors.As(err, &unreadable):
			report.UnreadableRows += row.Rows
			report.UnreadablePrefixes++
			logger.Error("sign-in lane timing envelope: stored class is not readable by the verifier — a finding about the store, not a refusal to start",
				"class", class.Key(), "rows", row.Rows, "outcome", string(unreadable.Outcome))
			continue
		case err != nil:
			return envelopeReport{}, fmt.Errorf("sign-in lane timing envelope: class %s from the store: %w", class.Key(), err)
		}
		if adm.Calibrated {
			report.ClassesCalibrated++
		}
		logger.Info("sign-in lane timing envelope: class calibrated", "class", class.Key(), "rows", row.Rows, "cost", adm.Cost)
	}
	adm, err := admit(declared)
	if err != nil {
		return envelopeReport{}, fmt.Errorf("sign-in lane timing envelope: the class the product writes (%s) could not be calibrated: %w", declared.Key(), err)
	}
	if adm.Calibrated {
		report.ClassesCalibrated++
		logger.Info("sign-in lane timing envelope: class calibrated", "class", declared.Key(), "rows", 0, "cost", adm.Cost)
	}
	ceiling, ok := envelope.Ceiling()
	if !ok {
		return envelopeReport{}, fmt.Errorf("sign-in lane timing envelope: no class calibrated — the lane would answer with the verification time")
	}
	report.Floor, report.CeilingClass = envelope.Floor(), ceiling.Class.Key()
	return report, nil
}

// buildLoginLane — полоса под `own`; под `external` — nil без ошибки.
// reconciler — материализация собственнической выдачи после регистрации: тот
// же экземпляр, что у пути запроса; nil-safe (уборка доберёт по намерениям).
func buildLoginLane(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, repo kanamerepo.Repository,
	reconciler *reconcileapp.Reconciler, reg *metrics.Registry, logger *slog.Logger,
) (*loginLane, error) {
	if !loginLaneWanted(cfg) {
		return nil, nil
	}
	login := cfg.AuthN.Login
	if err := login.ValidateAll(); err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	limit, limited := readMemoryLimit(memoryLimitFiles)
	if err := login.ValidateMemoryBudget(limit, limited); err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	logger.Info("sign-in lane memory budget",
		"verifier_capacity", login.VerifierCapacity,
		"memory_per_verification_at_ceiling_bytes", config.MemoryPerVerificationAtCeilingBytes(),
		"memory_reserve_bytes", login.MemoryReserveBytes,
		"environment_memory_limit_bytes", limit)

	rec := reg.LoginLaneRecorder()
	verifier, err := passwordverify.New(login.VerifierCapacity, rec)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	hasher, err := passwordverify.NewHasher(login.Declared())
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	// Выравнивание полосы «материала нет» (Ф3-31, PWV-06): значение объявленного
	// класса записи от случайного пароля, которого не знает никто, — проверка
	// против него стоит как проверка всякого значения этого класса.
	decoySecret := make([]byte, 32)
	if _, err := rand.Read(decoySecret); err != nil {
		return nil, fmt.Errorf("sign-in lane: decoy secret: %w", err)
	}
	decoy, err := hasher.Hash(hex.EncodeToString(decoySecret))
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: decoy: %w", err)
	}
	if err := verifier.SetDecoy(decoy); err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	sessions := kanamepg.NewHumanSessionRepo(pool)
	methods := kanamepg.NewLoginMethodRepo(pool)
	// Огибающая по потолку (Ф3-31, решение kaname#188): перепись классов
	// хранилища ∪ класс ручки, каждый — калибровкой прогоном проверяющего.
	// Перепись не удалась — отказ старта: огибающая только по классу ручки
	// оставила бы популяцию переноса отличимой по времени.
	envelope, err := passwordverify.NewEnvelope(verifier, rec)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	censusCtx, cancelCensus := context.WithTimeout(ctx, envelopeCensusTimeout)
	census, err := methods.PasswordCostClasses(censusCtx)
	cancelCensus()
	if err != nil {
		return nil, fmt.Errorf("sign-in lane timing envelope: cost-class census of the store: %w", err)
	}
	report, err := calibrateLoginEnvelope(ctx, envelope,
		census, domain.PasswordCostClass{Format: login.Declared().Format, Params: login.Declared().Params}, logger)
	if err != nil {
		return nil, err
	}
	logger.Info("sign-in lane timing envelope",
		"floor", report.Floor,
		"ceiling_class", report.CeilingClass,
		"classes_calibrated", report.ClassesCalibrated,
		"rows_counted", report.RowsCounted,
		"unreadable_rows", report.UnreadableRows,
		"unreadable_prefixes", report.UnreadablePrefixes)
	var breach humansession.BreachChecker
	if login.BreachCheckOn() {
		client, berr := breachcheck.New(login.BreachCheckURL, breachCheckTimeout)
		if berr != nil {
			return nil, fmt.Errorf("sign-in lane: %w", berr)
		}
		breach = client
	}
	logger.Info("password breach check", "state", strings.TrimSpace(login.BreachCheck), "authority_declared", login.BreachCheckOn())
	rule, err := humansession.NewPasswordRule(login.PasswordMinLength, breach, rec, logger)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	limits := humansession.Limits{
		AddressAttempts: login.AddressAttempts, AddressWindow: login.AddressWindow,
		SourceAttempts: login.SourceAttempts, SourceWindow: login.SourceWindow,
	}
	// Второй фактор (Ф12): своё кольцо ключей обёртки секретов (Р2) — первый
	// оборачивает, все открывают; число ключей печатается всегда, как у
	// приватной половины подписи (`signing.go`).
	sfKeys, err := cfg.AuthN.ResolveSecondFactorEncryptionKeys()
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: second factor wrapping keys: %w", err)
	}
	sfWrapper, err := keywrap.New(sfKeys...)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: second factor wrapper: %w", err)
	}
	logger.Info("second-factor wrapping keys declared",
		slog.Int("keys", sfWrapper.KeyCount()),
		slog.String("knob", "authn.second-factor-encryption-key-hex"),
		slog.String("env", cfg.AuthN.SecondFactorEncryptionKeyEnvName()))
	totp, err := totpverify.New(sfWrapper)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: totp verifier: %w", err)
	}
	loginUC, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: sessions, Users: kanamepg.NewUserDirectory(repo), Methods: methods, Verifier: verifier,
		Hasher: hasher, Limits: limits, TTL: login.SessionTTL, Observer: rec, Now: time.Now, Logger: logger,
		Envelope: envelope, TOTP: totp, Sets: verifier,
	})
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	logoutUC, err := humansession.NewLogoutUseCase(sessions, rec, time.Now, logger)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	changeUC, err := humansession.NewChangePasswordUseCase(humansession.ChangePasswordDeps{
		Store: sessions, Methods: methods, Verifier: verifier, Hasher: hasher, Rule: rule,
		Limits: limits, Observer: rec, Now: time.Now, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	resolveUC, err := humansession.NewResolveUseCase(sessions, rec, time.Now)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	// Регистрация (Ф4) — полоса из ЕДИНСТВЕННОГО объявления; глагол не
	// собирается для полосы, не объявившей всех трёх следствий.
	regLane, ok := registration.LaneByName(registration.LanePassword)
	if !ok {
		return nil, fmt.Errorf("sign-in lane: registration lane %q is not declared in registration.Lanes", registration.LanePassword)
	}
	registerUC, err := registration.NewRegisterUseCase(registration.Deps{
		Store: registrationStore{inner: kanamepg.NewRegistrationStore(pool)}, Rule: rule, Hasher: hasher, Lane: regLane,
		TTL: login.SessionTTL, Observer: rec, Reconciler: ownerReconcilerOrNone(reconciler), Now: time.Now, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	// Восстановление доступа (Ф5): постановка письма — вне пути ответа (Р2).
	dispatcher := humansession.NewGoDispatcher(recoveryDispatchTimeout)
	requestUC, err := humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{
		Store: sessions, CodeTTL: login.RecoveryCodeTTL, Dispatcher: dispatcher, Observer: rec, Now: time.Now, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	completeUC, err := humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{
		Store: sessions, Hasher: hasher, Rule: rule, Limits: limits, TTL: login.SessionTTL,
		Observer: rec, Now: time.Now, Logger: logger,
	})
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	// Второй фактор (Ф12): шесть глаголов одними зависимостями — те же
	// хранилища, тот же проверяющий пароля (он же проверяющий набора, Р6), тот
	// же хешер (он же чеканит набор), окно свежести Р8 и доменное имя посадки
	// как издатель `otpauth`-адреса (Р5).
	if err := cfg.AuthN.ValidateSelfServiceFreshness(); err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	sfDeps := humansession.SecondFactorDeps{
		Store: sessions, Methods: methods, TOTP: totp, Sets: verifier, SetHasher: hasher, Verifier: verifier,
		Limits: limits, Freshness: cfg.AuthN.SelfServiceFreshness, Domain: cfg.AuthN.ResolveDomain(),
		Observer: rec, Now: time.Now, Logger: logger,
	}
	enrollUC, err := humansession.NewEnrollSecondFactorUseCase(sfDeps)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	confirmUC, err := humansession.NewConfirmSecondFactorUseCase(sfDeps)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	statusUC, err := humansession.NewSecondFactorStatusUseCase(sfDeps)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	removeUC, err := humansession.NewRemoveSecondFactorUseCase(sfDeps)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	regenerateUC, err := humansession.NewRegenerateBackupCodesUseCase(sfDeps)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	stepUpUC, err := humansession.NewStepUpUseCase(sfDeps)
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	handler, err := loginlanehttp.New(loginlanehttp.Config{
		SessionTTL:    login.SessionTTL,
		CookieDomain:  login.ResolvedCookieDomain(),
		TrustDomain:   cfg.AuthN.TrustDomain(),
		RefusalDomain: refusaldomain.For(refusaldomain.ServiceIAM),
		Logger:        logger,
		Observer:      rec,
	}, laneVerbs{
		login: loginUC, logout: logoutUC, change: changeUC, register: registerUC, request: requestUC, complete: completeUC,
		enroll: enrollUC, confirm: confirmUC, status: statusUC, remove: removeUC, regenerate: regenerateUC, stepUp: stepUpUC,
	})
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	return &loginLane{
		handler: handler, resolve: humansession.NewHandler(resolveUC),
		sessions: sessions, methods: methods, limits: limits, dispatcher: dispatcher,
		freshness: cfg.AuthN.SelfServiceFreshness,
		keys:      kanamepg.NewAccessKeyRepo(pool), keyFreshness: kanamepg.NewHumanSessionFreshness(pool),
		verifier: verifier,
	}, nil
}

// registrationStore — адаптер хранилища регистрации к порту глагола. Адаптер
// `pg` порт не импортирует (иначе круг импортов в пробах пакета зеркала) и
// отдаёт писатель зеркала своей транзакции; композицию зеркала (Р6) над ним
// исполняет `user.RegisterMirrorTx` — здесь, в композиционном корне, где
// соответствие порту закрепляется присваиванием.
type registrationStore struct{ inner *kanamepg.RegistrationStore }

func (s registrationStore) Writer(ctx context.Context) (registration.Writer, error) {
	w, err := s.inner.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return registrationWriter{RegistrationWriter: w}, nil
}

type registrationWriter struct{ *kanamepg.RegistrationWriter }

func (w registrationWriter) Mirror(ctx context.Context, in registration.MirrorInput) (registration.MirrorResult, error) {
	return userapp.RegisterMirrorTx(ctx, w.MirrorWriter(), in)
}

// ownerReconcilerOrNone — nil указателя НЕ становится ненулевым интерфейсом:
// глагол читает «реконсайлера нет» по nil интерфейса и оставляет
// материализацию уборке по намерениям.
func ownerReconcilerOrNone(r *reconcileapp.Reconciler) registration.OwnerBindingReconciler {
	if r == nil {
		return nil
	}
	return r
}

// laneVerbs — порт глаголов слушателя над вариантами использования.
type laneVerbs struct {
	login    *humansession.LoginUseCase
	logout   *humansession.LogoutUseCase
	change   *humansession.ChangePasswordUseCase
	register *registration.RegisterUseCase
	request  *humansession.RequestRecoveryUseCase
	complete *humansession.CompleteRecoveryUseCase
	// Второй фактор (Ф12).
	enroll     *humansession.EnrollSecondFactorUseCase
	confirm    *humansession.ConfirmSecondFactorUseCase
	status     *humansession.SecondFactorStatusUseCase
	remove     *humansession.RemoveSecondFactorUseCase
	regenerate *humansession.RegenerateBackupCodesUseCase
	stepUp     *humansession.StepUpUseCase
}

func (v laneVerbs) Register(ctx context.Context, in registration.Input) (registration.Output, error) {
	return v.register.Execute(ctx, in)
}

func (v laneVerbs) Login(ctx context.Context, in humansession.LoginInput) (humansession.LoginOutput, error) {
	return v.login.Execute(ctx, in)
}

func (v laneVerbs) Logout(ctx context.Context, bearer domain.SessionBearer) (bool, error) {
	return v.logout.Execute(ctx, bearer)
}

func (v laneVerbs) ChangePassword(ctx context.Context, in humansession.ChangePasswordInput) (humansession.ChangePasswordOutput, error) {
	return v.change.Execute(ctx, in)
}

func (v laneVerbs) RequestRecovery(ctx context.Context, in humansession.RequestRecoveryInput) error {
	return v.request.Execute(ctx, in)
}

func (v laneVerbs) CompleteRecovery(ctx context.Context, in humansession.CompleteRecoveryInput) (humansession.CompleteRecoveryOutput, error) {
	return v.complete.Execute(ctx, in)
}

func (v laneVerbs) EnrollSecondFactor(ctx context.Context, in humansession.EnrollInput) (humansession.EnrollOutput, error) {
	return v.enroll.Execute(ctx, in)
}

func (v laneVerbs) ConfirmSecondFactor(ctx context.Context, in humansession.ConfirmInput) (humansession.ConfirmOutput, error) {
	return v.confirm.Execute(ctx, in)
}

func (v laneVerbs) SecondFactorStatus(ctx context.Context, in humansession.StatusInput) (humansession.StatusOutput, error) {
	return v.status.Execute(ctx, in)
}

func (v laneVerbs) RemoveSecondFactor(ctx context.Context, in humansession.RemoveSecondFactorInput) (humansession.RemoveSecondFactorOutput, error) {
	return v.remove.Execute(ctx, in)
}

func (v laneVerbs) RegenerateBackupCodes(ctx context.Context, in humansession.RegenerateBackupCodesInput) (humansession.RegenerateBackupCodesOutput, error) {
	return v.regenerate.Execute(ctx, in)
}

func (v laneVerbs) StepUp(ctx context.Context, in humansession.StepUpInput) (humansession.StepUpOutput, error) {
	return v.stepUp.Execute(ctx, in)
}

// loginLaneSurface — профиль поверхности слушателя формы. Досягаемость —
// внутри кластера: до слушателя доходит ровно край, и адрес консоли, на
// котором живут глаголы полосы, принадлежит краю.
func loginLaneSurface(cfg config.Config, mode servicecontract.Mode, logger *slog.Logger,
	lane *loginLane, mtlsCfg config.MTLSConfig,
) (servicecontract.SurfaceDescriptor, error) {
	addr := ""
	var handler http.Handler
	if lane != nil {
		// Адрес — НОРМАЛИЗОВАННЫЙ, тем же правилом, что у остальных
		// поверхностей. Здесь стояло сырое объявление профиля
		// (`tcp://0.0.0.0:9100`): под `own` процесс проходил всех стражей и
		// падал на привязке этой поверхности — «too many colons in address»
		// (задача kaname#21, живой старт 2026-09-17). Держит
		// `loginlane_addr_test.go`.
		addr = cfg.APIServer.LoginLaneListenAddress()
		handler = lane.handler
	}
	tlsCfg, err := mtlsCfg.LoginLaneServerTLSConfig()
	if err != nil {
		return servicecontract.SurfaceDescriptor{}, fmt.Errorf("sign-in lane TLS: %w", err)
	}
	if lane == nil {
		tlsCfg = nil
	}
	return iamHTTPSurface(servicecontract.Surface{
		Name: "полоса входа паролем, регистрации, восстановления доступа и второго фактора " +
			"(/iam/v1/auth/{login,logout,password,csrf,register,recovery,recovery/complete,second-factor,second-factor/{enroll,confirm,remove,backup-codes},step-up})",
		Mode:   mode,
		Logger: logger,
		Addr: addrAxis(addr, "полоса входа паролем поднимается только посадкой authn.identity-provider=own "+
			"по адресу "+knobLoginLane+"; на этой посадке вход человека, регистрацию, смену пароля, выход, "+
			"восстановление доступа и второй фактор (/iam/v1/auth/login, /register, /logout, /password, /csrf, /recovery, "+
			"/recovery/complete, /second-factor, /second-factor/{enroll,confirm,remove,backup-codes}, /step-up) "+
			"служба не обслуживает — их исполняет внешний поставщик"),
		Handler: handler,
		Reach:   servicecontract.ReachClusterInternal,
		Auth: servicecontract.Value[servicecontract.SurfaceAuthMech](
			"вызывающий — РОВНО край: короткое имя службы из SAN проверенного клиентского сертификата " +
				"равно имени края (та же константа, что у яруса gateway-only); личность человека на этой " +
				"поверхности производит ОДИН механизм — носитель kaname_session, судимый по записи; " +
				"переданная личность не читается"),
		TLS: tlsCfg,
	})
}
