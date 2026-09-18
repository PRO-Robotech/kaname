// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recovery_session_integration_test.go — СЕССИЯ, ВЫДАННАЯ ВОССТАНОВЛЕНИЕМ,
// ПОЛНОПРАВНА: половина Ф5-24 на слушателе службы (задачи
// PRO-Robotech/kaname#201, PRO-Robotech/kacho#2707; приёмка
// `docs/engineering/acceptance/recovery-of-access.md` ред. 3, Ф5-24, Р5, §8
// строка «Ф5-24»).
//
// # Что утверждается
//
// Сессия `R` выдана завершением восстановления (Ф5-03: новый пароль записан тем
// же обращением); сессия `L` — входом тем же новым паролем (Ф5-18). Ответы
// службы краю о `R` и о `L` (`Resolve`, Ф3 Р7) несут ОДИН состав (Ф3-09) и ни
// один — ключа требования сменить пароль; различие двух сессий — одно,
// множество предъявленного ({`recovery_code`} против {`password`}), и
// наблюдается оно уровнем (правило Ф11 Р2 даёт обоим «1»), а не правом.
//
// Половина через край («кто я» и глагол платформы под `R` и под `L`) — связка
// службы с платформой; её дом — репозиторий платформы (`e2e-flow.md` §7а), здесь
// её нет.
//
// # Отрицательный контроль — после `kaname#201` это ИНЪЕКЦИЯ читателя
//
// Приёмка (Ф5-24, второе «И»): поле требования неконструируемо, и способность
// падать держит инъекция «читатель, судящий сессию по множеству предъявленного
// {`recovery_code`} иначе, чем по {`password`}» — красное с именем пути. Здесь
// она ЗАКОММИЧЕНА, а не только прогнана руками: тот же предикат состава
// применяется к ответам двух внесённых читателей (отказ сессии восстановления и
// иной её состав), и обязан назвать путь `InternalHumanSessionService.Resolve`.
// Без этой половины проба зеленела бы и на предикате, не умеющем различать.
//
// Run: `go test ./internal/handler/loginlanehttp/ -run F5_24 -count=1`
// (Docker). Skipped under -short.
package loginlanehttp_test

import (
	"context"
	"fmt"
	"net/http"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// resolvePath — имя пути, которое называет красное предиката: ответ службы
// краю о сессии.
const resolvePath = "InternalHumanSessionService.Resolve"

// passwordChangeKeys — ключ требования сменить пароль в двух написаниях провода
// (имя поля и имя JSON), снятый с контракта `kaname#201`.
var passwordChangeKeys = []string{"password_change_required", "passwordChangeRequired"}

// TestLaneIntegration_F5_24_RecoverySessionResolvesLikeTheLoginSession — Ф5-24,
// половина на слушателе службы.
//
// Инъекция в прод-код (resolve.go, `Execute`): читатель отвечает «сессии нет»
// на сессию, чьё множество предъявленного содержит `recovery_code` → красное с
// именем пути.
func TestLaneIntegration_F5_24_RecoverySessionResolvesLikeTheLoginSession(t *testing.T) {
	const newPassword = "recovered-and-full-rights-5-24"
	h := newSessionLane(t)
	// Дано: адрес подтверждён — посевом, писателем продукта (Ф6; приёмка §7:
	// признак подтверждённости ставится посевом).
	require.NoError(t, kanamepg.NewLoginMethodRepo(h.pool).MarkEmailVerified(h.ctx, h.user.ID, h.user.Email, time.Now().UTC()))

	r := h.recover(t, newPassword)
	l := h.login(t, newPassword)

	// Дано проверяется ДО предмета: R выдана восстановлением, L — входом, и
	// различие записей — множество предъявленного.
	rRow, ok := h.rowByBearer(t, r.bearer.Value)
	require.True(t, ok, "Дано: запись сессии восстановления найдена по носителю")
	lRow, ok := h.rowByBearer(t, l.bearer.Value)
	require.True(t, ok, "Дано: запись сессии входа найдена по носителю")
	require.Equal(t, []string{"recovery_code"}, rRow.methods, "Дано: R выдана восстановлением (Ф11 Р8)")
	require.Equal(t, []string{"password"}, lRow.methods, "Дано: L выдана входом паролем")

	rRes := h.resolve(t, r.bearer.Value)
	lRes := h.resolve(t, l.bearer.Value)
	findings := resolveCompositionFindings(rRes, lRes, rRow.methods, lRow.methods)
	require.Empty(t, findings, "ответ краю о сессии восстановления расходится с ответом о сессии входа:\n%s",
		strings.Join(findings, "\n"))
	t.Logf("перепись: состав R %v · состав L %v · уровень R %q · уровень L %q",
		populated(rRes.GetSession()), populated(lRes.GetSession()),
		rRes.GetSession().GetAssuranceLevel(), lRes.GetSession().GetAssuranceLevel())

	// Отрицательный контроль: читатели, судящие сессию по множеству
	// предъявленного. Каждый обязан дать красное с именем пути — иначе предикат
	// выше не различает того, ради чего написан.
	for _, reader := range []struct {
		name  string
		judge func(humansession.Resolved) (humansession.Resolved, humansession.NoSessionReason)
	}{
		{"refuses-the-recovery-session", func(humansession.Resolved) (humansession.Resolved, humansession.NoSessionReason) {
			return humansession.Resolved{}, humansession.NoSessionUnknown
		}},
		{"narrows-the-recovery-session", func(res humansession.Resolved) (humansession.Resolved, humansession.NoSessionReason) {
			res.EmailVerified = false
			return res, humansession.SessionFound
		}},
	} {
		uc, err := humansession.NewResolveUseCase(setJudgingStore{Store: h.sessions, judge: reader.judge}, humansession.NopObserver{}, time.Now)
		require.NoError(t, err)
		c := serveResolve(t, humansession.NewHandler(uc))
		got := resolveCompositionFindings(resolveOver(t, c, r.bearer.Value), resolveOver(t, c, l.bearer.Value), rRow.methods, lRow.methods)
		require.NotEmpty(t, got, "%s: внесённый читатель судит R иначе, чем L, а предикат молчит — он не различает", reader.name)
		require.Contains(t, strings.Join(got, "\n"), resolvePath, "%s: красное обязано называть путь", reader.name)
		t.Logf("отрицательный контроль %s — красное: %s", reader.name, strings.Join(got, " | "))
	}
}

// resolveCompositionFindings — предикат Ф5-24 над двумя ответами краю: пусто —
// состав один; иначе — каждое расхождение с именем пути.
func resolveCompositionFindings(r, l *iamv1.ResolveHumanSessionResponse, rSet, lSet []string) []string {
	var out []string
	add := func(format string, args ...any) {
		out = append(out, resolvePath+": "+fmt.Sprintf(format, args...))
	}
	if !r.GetFound() || !l.GetFound() {
		add("сессия восстановления найдена=%v, сессия входа найдена=%v — полноправная сессия обязана разрешаться, как сессия входа",
			r.GetFound(), l.GetFound())
		return out
	}
	rs, ls := r.GetSession(), l.GetSession()
	if a, b := populated(rs), populated(ls); !slices.Equal(a, b) {
		add("состав ответа о сессии восстановления %v, о сессии входа %v — состав один (Ф3-09)", a, b)
	}
	if rs.GetUserId() != ls.GetUserId() || rs.GetEmail() != ls.GetEmail() ||
		rs.GetDisplayName() != ls.GetDisplayName() || rs.GetEmailVerified() != ls.GetEmailVerified() {
		add("субъект различается: восстановление {%s %s %q %v}, вход {%s %s %q %v}",
			rs.GetUserId(), rs.GetEmail(), rs.GetDisplayName(), rs.GetEmailVerified(),
			ls.GetUserId(), ls.GetEmail(), ls.GetDisplayName(), ls.GetEmailVerified())
	}
	for _, side := range []struct {
		name  string
		level string
		set   []string
	}{{"восстановления", rs.GetAssuranceLevel(), rSet}, {"входа", ls.GetAssuranceLevel(), lSet}} {
		if want := ruleLevel(side.set); side.level != want {
			add("уровень сессии %s %q, правило Ф11 над %v даёт %q — различие обязано наблюдаться уровнем правила", side.name, side.level, side.set, want)
		}
	}
	if rs.GetAssuranceLevel() != ls.GetAssuranceLevel() {
		add("уровень сессии восстановления %q, сессии входа %q", rs.GetAssuranceLevel(), ls.GetAssuranceLevel())
	}
	rLife := rs.GetExpiresAt().AsTime().Sub(rs.GetAuthenticatedAt().AsTime())
	lLife := ls.GetExpiresAt().AsTime().Sub(ls.GetAuthenticatedAt().AsTime())
	if d := rLife - lLife; d > time.Second || d < -time.Second {
		add("срок жизни сессии восстановления %v, сессии входа %v — срок один", rLife, lLife)
	}
	for _, side := range []struct {
		name string
		res  *iamv1.ResolveHumanSessionResponse
	}{{"восстановления", r}, {"входа", l}} {
		if key := passwordChangeKeyOf(side.res); key != "" {
			add("ответ о сессии %s несёт ключ требования сменить пароль (%s) — снят с контракта kaname#201", side.name, key)
		}
	}
	return out
}

// populated — имена полей сессии, несущих значение на проводе.
func populated(s *iamv1.HumanSession) []string {
	var names []string
	s.ProtoReflect().Range(func(fd protoreflect.FieldDescriptor, _ protoreflect.Value) bool {
		names = append(names, string(fd.Name()))
		return true
	})
	sort.Strings(names)
	return names
}

// ruleLevel — уровень, который правило Ф11 даёт множеству предъявленного.
func ruleLevel(set []string) string {
	var ps []assurance.Presentation
	for _, m := range set {
		switch m {
		case assurance.MethodPassword.String():
			ps = append(ps, assurance.PasswordPresented())
		case assurance.MethodRecoveryCode.String():
			ps = append(ps, assurance.RecoveryCodePresented())
		case assurance.MethodTOTP.String():
			ps = append(ps, assurance.TOTPPresented())
		case assurance.MethodLookupSecret.String():
			ps = append(ps, assurance.LookupSecretPresented())
		}
	}
	lvl, ok := assurance.LevelOf(ps)
	if !ok {
		return ""
	}
	return lvl.String()
}

// passwordChangeKeyOf — ключ требования сменить пароль, если ответ его несёт в
// любом виде: объявленным полем, неизвестным полем разобранного сообщения
// (сервер пишет то, чего контракт уже не объявляет) или ключом JSON.
func passwordChangeKeyOf(res *iamv1.ResolveHumanSessionResponse) string {
	s := res.GetSession()
	fields := s.ProtoReflect().Descriptor().Fields()
	for _, k := range passwordChangeKeys {
		if fields.ByName(protoreflect.Name(k)) != nil {
			return "объявленное поле " + k
		}
	}
	if len(s.ProtoReflect().GetUnknown()) > 0 || len(res.ProtoReflect().GetUnknown()) > 0 {
		return "неизвестное поле на проводе"
	}
	b, err := protojson.Marshal(res)
	if err != nil {
		return "ответ не сериализуется: " + err.Error()
	}
	for _, k := range passwordChangeKeys {
		if strings.Contains(string(b), `"`+k+`"`) {
			return "ключ JSON " + k
		}
	}
	return ""
}

// setJudgingStore — ВНЕСЁННЫЙ читатель отрицательного контроля: судит сессию,
// чьё множество содержит `recovery_code`, функцией judge; прочие — как
// настоящее хранилище. Это инъекция, а не фикстура пробы: положительная
// половина идёт по настоящему хранилищу.
type setJudgingStore struct {
	humansession.Store
	judge func(humansession.Resolved) (humansession.Resolved, humansession.NoSessionReason)
}

func (s setJudgingStore) Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	res, reason, err := s.Store.Resolve(ctx, digest, now)
	if err != nil || reason != humansession.SessionFound {
		return res, reason, err
	}
	if slices.Contains(res.Session.PresentedMethods, assurance.MethodRecoveryCode.String()) {
		judged, why := s.judge(res)
		return judged, why, nil
	}
	return res, reason, nil
}

// recover — восстановление доступа через слушатель: запрос кода, код из
// намерения письма (постановка синхронна), завершение с новым паролем.
func (h *sessionLane) recover(t *testing.T, newPassword string) laneSession {
	t.Helper()
	tok, ctxCk := h.lane.csrf(t, h.c, string(domain.FormRecovery), nil)
	req := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecovery,
		map[string]any{"email": h.email, "csrfToken": tok}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, req.status, "Дано: запрос кода: %s", req.body)

	var letters int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM invite_mail_outbox WHERE resource_id = $1 AND event_type = 'mail.recovery.send'`,
		string(h.user.ID)).Scan(&letters))
	require.Equal(t, 1, letters, "Дано: запрос поставил ровно одно письмо с кодом")
	var code string
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT payload->>'code' FROM invite_mail_outbox WHERE resource_id = $1 AND event_type = 'mail.recovery.send'`,
		string(h.user.ID)).Scan(&code))
	require.NotEmpty(t, code, "Дано: письмо несёт код")

	done := h.lane.do(t, h.c, http.MethodPost, loginlanehttp.PathRecoveryComplete, map[string]any{
		"email": h.email, "code": code, "newPassword": newPassword,
		"csrfToken": h.csrfFor(t, domain.FormRecoveryComplete, ctxCk),
	}, fwd(), ctxCk)
	require.Equal(t, http.StatusOK, done.status, "Дано: завершение восстановления выдаёт сессию (Ф5-03): %s", done.body)
	s := laneSession{bearer: cookieNamed(done.cookies, loginlanehttp.CookieSession), form: cookieNamed(done.cookies, loginlanehttp.CookieForm)}
	require.NotNil(t, s.bearer, "Дано: восстановление пишет носитель")
	require.NotNil(t, s.form, "Дано: выдача сессии сменяет контекст формы")
	return s
}
