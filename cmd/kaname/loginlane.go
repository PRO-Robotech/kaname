// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// loginlane.go — КОМПОЗИЦИЯ полосы входа паролем и нашей сессии (фаза Ф3,
// задача PRO-Robotech/kacho#1269; приёмка
// `docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`,
// Р15, Ф3-44, Ф3-45).
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
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/servicecontract"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/retention"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/clients/breachcheck"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// knobLoginLane — ручка адреса слушателя полосы формы.
const knobLoginLane = "KANAME_API_SERVER__LOGIN_LANE_ENDPOINT"

// breachCheckTimeout — потолок одного обращения к авторитету утечек.
const breachCheckTimeout = 5 * time.Second

// loginLane — всё, что корень собирает под полосу; nil — полосы нет.
type loginLane struct {
	handler  *loginlanehttp.Handler
	resolve  *humansession.Handler
	sessions *kanamepg.HumanSessionRepo
	methods  *kanamepg.LoginMethodRepo
	limits   humansession.Limits
}

// loginLaneWanted — поднимается ли полоса на этой посадке: ровно под `own`.
func loginLaneWanted(cfg config.Config) bool {
	return cfg.AuthN.IdentityProvider == config.IdentityProviderOwn
}

// wired — хранилища полосы провязаны (наблюдение для посадки, `kaname#21`).
func (l *loginLane) wired() bool { return l != nil && l.sessions != nil && l.methods != nil }

// signInMethods — способы входа человека, чьи проверяющие собраны ЭТИМ корнем:
// пароль, пока полоса поднята. Второй фактор — Ф12.
func (l *loginLane) signInMethods() []assurance.Method {
	if !l.wired() {
		return nil
	}
	return []assurance.Method{assurance.MethodPassword}
}

// laneWiringOf — вклад полосы в наблюдение провязки.
func laneWiringOf(l *loginLane) config.LaneWiring {
	return config.LaneWiring{HumanCredentialsWired: l.wired(), HumanSessionsWired: l.wired()}
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
	return retention.HumanSessionReapers{Sessions: l.sessions, Failures: l.sessions, LongestWindow: l.limits.LongestWindow()}
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

// buildLoginLane — полоса под `own`; под `external` — nil без ошибки.
func buildLoginLane(cfg config.Config, pool *pgxpool.Pool, repo kanamerepo.Repository,
	reg *metrics.Registry, logger *slog.Logger,
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
	sessions := kanamepg.NewHumanSessionRepo(pool)
	methods := kanamepg.NewLoginMethodRepo(pool)
	loginUC, err := humansession.NewLoginUseCase(humansession.LoginDeps{
		Store: sessions, Users: kanamepg.NewUserDirectory(repo), Methods: methods, Verifier: verifier,
		Hasher: hasher, Limits: limits, TTL: login.SessionTTL, Observer: rec, Now: time.Now, Logger: logger,
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
	handler, err := loginlanehttp.New(loginlanehttp.Config{
		SessionTTL:    login.SessionTTL,
		CookieDomain:  login.ResolvedCookieDomain(),
		TrustDomain:   cfg.AuthN.TrustDomain(),
		RefusalDomain: refusaldomain.For(refusaldomain.ServiceIAM),
		Logger:        logger,
		Observer:      rec,
	}, laneVerbs{login: loginUC, logout: logoutUC, change: changeUC})
	if err != nil {
		return nil, fmt.Errorf("sign-in lane: %w", err)
	}
	return &loginLane{
		handler: handler, resolve: humansession.NewHandler(resolveUC),
		sessions: sessions, methods: methods, limits: limits,
	}, nil
}

// laneVerbs — порт глаголов слушателя над вариантами использования.
type laneVerbs struct {
	login  *humansession.LoginUseCase
	logout *humansession.LogoutUseCase
	change *humansession.ChangePasswordUseCase
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

// loginLaneSurface — профиль поверхности слушателя формы. Досягаемость —
// внутри кластера: до слушателя доходит ровно край, и адрес консоли, на
// котором живут четыре глагола, принадлежит краю.
func loginLaneSurface(cfg config.Config, mode servicecontract.Mode, logger *slog.Logger,
	lane *loginLane, mtlsCfg config.MTLSConfig,
) (servicecontract.SurfaceDescriptor, error) {
	addr := ""
	var handler http.Handler
	if lane != nil {
		addr = cfg.APIServer.LoginLaneEndpoint
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
		Name:   "полоса входа паролем (/iam/v1/auth/{login,logout,password,csrf})",
		Mode:   mode,
		Logger: logger,
		Addr: addrAxis(addr, "полоса входа паролем поднимается только посадкой authn.identity-provider=own "+
			"по адресу "+knobLoginLane+"; на этой посадке вход человека, смену пароля и выход "+
			"(/iam/v1/auth/login, /logout, /password, /csrf) служба не обслуживает — их исполняет "+
			"внешний поставщик"),
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
