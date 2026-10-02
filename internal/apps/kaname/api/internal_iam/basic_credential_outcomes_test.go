// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_outcomes_test.go — отказ полосы базового секрета различим
// ВНУТРИ по причине и неразличим СНАРУЖИ (задача kaname#379).
//
// # Предмет
//
// Полоса отказывает одним кодом и одним текстом на любую причину: различимый
// отказ был бы оракулом. Но отказ, который и внутри неотличим от соседнего,
// делает новый контроль ненаблюдаемым: отсечка отзыва-всех, сработавшая тысячу
// раз, выглядит так же, как не сработавшая ни разу, — перебором секрета.
//
// # Что утверждается
//
//   - на каждую причину словаря и на каждом глаголе снаружи уходит ОДИН И ТОТ
//     ЖЕ статус, побайтно равный прежнему единому отказу (он записан здесь
//     литералом, а не взят у кода под пробой);
//   - перепись сдвигает РОВНО клетку этой причины на этом глаголе и никакую
//     другую — отсечка, «строки нет» и «неверный секрет» считаются каждая своим
//     исходом;
//   - журнал несёт структурную запись отказа с глаголом и исходом и не несёт
//     ни предъявленной строки, ни её секретной части;
//   - отказ, чью причину авторитет не назвал, — свой исход, а не чужая клетка.
package internal_iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// reasonedAuthority — авторитет, отвечающий заданным на оба вопроса.
type reasonedAuthority struct {
	err  error
	cred domain.BasicCredential
}

func (a reasonedAuthority) ResolveBasic(context.Context, string) (domain.BasicCredential, error) {
	return a.cred, a.err
}

func (a reasonedAuthority) TouchLastUsed(context.Context, string, time.Duration) error { return nil }

func (a reasonedAuthority) CheckBasicLive(context.Context, string) error { return a.err }

// basicWire — статус в том виде, в каком он уходит на провод.
func basicWire(t *testing.T, err error) []byte {
	t.Helper()
	b, merr := proto.MarshalOptions{Deterministic: true}.Marshal(status.Convert(err).Proto())
	require.NoError(t, merr)
	return b
}

// priorRefusalWire — единый отказ полосы в том виде, каким он уходил ДО
// различения причин. Код и текст записаны литералом: взятые у кода под пробой,
// они сдвинулись бы вместе с ним, и «побайтно прежний» проверял бы сам себя.
func priorRefusalWire(t *testing.T) []byte {
	t.Helper()
	return basicWire(t, status.Error(codes.Unauthenticated, "credential refused"))
}

// askBasic задаёт глаголу вопрос так, как его задаёт край.
func askBasic(h *Handler, verb BasicCredentialVerb, presented, credentialID string) error {
	switch verb {
	case BasicCredentialResolve:
		_, err := h.ResolveBasicCredential(context.Background(),
			&iamv1.ResolveBasicCredentialRequest{Presented: presented})
		return err
	case BasicCredentialLiveness:
		_, err := h.CheckBasicCredentialLive(context.Background(),
			&iamv1.CheckBasicCredentialLiveRequest{CredentialId: credentialID})
		return err
	default:
		return errors.New("проба: глагол вне словаря")
	}
}

// refusalRecords — записи журнала об отказе полосы.
func refusalRecords(t *testing.T, buf *bytes.Buffer) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		require.NoErrorf(t, json.Unmarshal([]byte(line), &rec), "запись журнала не разбирается: %s", line)
		if rec["msg"] == basicRefusalLogMessage {
			out = append(out, rec)
		}
	}
	return out
}

// basicRefusalLogMessage — сообщение записи об отказе. Записано литералом по
// той же причине, что и отказ снаружи: запись ищут по нему в журнале.
const basicRefusalLogMessage = "basic credential refused"

// TestBasicCredentialRefusal_EachReasonIsItsOwnOutcomeAndTheWireIsOne — каждая
// причина на каждом глаголе: снаружи прежний единый отказ, внутри — своя
// клетка переписи и своя запись журнала.
func TestBasicCredentialRefusal_EachReasonIsItsOwnOutcomeAndTheWireIsOne(t *testing.T) {
	presented := mintedPresentedForTest(t, "uoc_rsn00000000000001")
	parsed, err := credsecret.Parse(presented)
	require.NoError(t, err)
	prior := priorRefusalWire(t)

	type probe struct {
		name string
		err  error
		want BasicCredentialOutcome
	}
	var probes []probe
	for _, r := range domain.BasicCredentialRefusalReasons() {
		probes = append(probes, probe{string(r), domain.RefuseBasicCredential(r), BasicCredentialOutcome(r)})
	}
	// Отказ без названной причины — нарушение контракта авторитета. Он обязан
	// лечь в свою клетку, а не в клетку первой попавшейся причины.
	probes = append(probes, probe{"голый сторожевой", domain.ErrBasicCredentialRefused, BasicOutcomeReasonUnnamed})

	verbs := []BasicCredentialVerb{BasicCredentialResolve, BasicCredentialLiveness}
	var ran int
	for _, verb := range verbs {
		for _, p := range probes {
			var buf bytes.Buffer
			h := (&Handler{}).WithBasicCredentialResolver(reasonedAuthority{err: p.err}).
				WithLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
			before := h.BasicCredentialOutcomes()

			err := askBasic(h, verb, presented, parsed.CredentialID)
			require.Errorf(t, err, "%s/%s: отказ авторитета стал ответом", verb, p.name)
			require.Equalf(t, prior, basicWire(t, err),
				"%s/%s: отказ снаружи отличается от прежнего единого — по нему узнали бы причину", verb, p.name)

			after := h.BasicCredentialOutcomes()
			cell := BasicCredentialCell{Verb: verb, Outcome: p.want}
			_, declared := before[cell]
			require.Truef(t, declared, "%s/%s: клетка %v не объявлена в переписи", verb, p.name, cell)
			require.Equalf(t, before[cell]+1, after[cell],
				"%s/%s: отказ не лёг в свою клетку %v", verb, p.name, cell)
			for c, v := range after {
				if c != cell {
					require.Equalf(t, before[c], v, "%s/%s: сдвинулась чужая клетка %v", verb, p.name, c)
				}
			}

			records := refusalRecords(t, &buf)
			require.Lenf(t, records, 1, "%s/%s: записей об отказе в журнале %d, а не одна", verb, p.name, len(records))
			require.Equalf(t, string(verb), records[0]["verb"], "%s/%s: запись не называет глагол", verb, p.name)
			require.Equalf(t, string(p.want), records[0]["outcome"], "%s/%s: запись не называет исход", verb, p.name)
			require.NotContainsf(t, buf.String(), presented, "%s/%s: предъявленная строка в журнале", verb, p.name)
			require.NotContainsf(t, buf.String(), parsed.SecretPart, "%s/%s: секретная часть в журнале", verb, p.name)
			ran++
		}
	}
	t.Logf("перепись: глаголов %d · исходов отказа на глагол %d · исполнено %d", len(verbs), len(probes), ran)
	require.Equal(t, len(verbs)*len(probes), ran)
}

// TestBasicCredentialLane_AcceptedUnavailableAndHandlerRefusalsAreCounted —
// знаменатель и третий исход: принятое, «авторитет не ответил» и отказы,
// которые глагол выносит сам, не спрашивая авторитета, считаются тоже.
func TestBasicCredentialLane_AcceptedUnavailableAndHandlerRefusalsAreCounted(t *testing.T) {
	presented := mintedPresentedForTest(t, "uoc_rsn00000000000002")
	parsed, err := credsecret.Parse(presented)
	require.NoError(t, err)
	malformed := BasicCredentialOutcome(domain.BasicRefusalMalformed)

	cases := []struct {
		name      string
		authority basicCredentialResolver
		verb      BasicCredentialVerb
		presented string
		id        string
		want      BasicCredentialOutcome
	}{
		{"резолв принят", reasonedAuthority{cred: domain.BasicCredential{
			PrincipalType: "user", PrincipalID: "usr_x", CredentialID: parsed.CredentialID}},
			BasicCredentialResolve, presented, "", BasicOutcomeAccepted},
		{"живость подтверждена", reasonedAuthority{}, BasicCredentialLiveness, "", parsed.CredentialID, BasicOutcomeAccepted},
		{"резолв: авторитет не ответил", reasonedAuthority{err: errors.New("pool closed")},
			BasicCredentialResolve, presented, "", BasicOutcomeUnavailable},
		{"живость: авторитет не ответил", reasonedAuthority{err: errors.New("pool closed")},
			BasicCredentialLiveness, "", parsed.CredentialID, BasicOutcomeUnavailable},
		{"резолв: авторитет не провязан", nil, BasicCredentialResolve, presented, "", BasicOutcomeUnavailable},
		{"живость: авторитет не провязан", nil, BasicCredentialLiveness, "", parsed.CredentialID, BasicOutcomeUnavailable},
		{"резолв: пустое предъявление", reasonedAuthority{}, BasicCredentialResolve, "", "", malformed},
		{"живость: пустой идентификатор", reasonedAuthority{}, BasicCredentialLiveness, "", "", malformed},
		{"живость: вместо идентификатора прислана предъявленная строка", reasonedAuthority{},
			BasicCredentialLiveness, "", presented, malformed},
	}
	for _, c := range cases {
		var buf bytes.Buffer
		h := &Handler{}
		if c.authority != nil {
			h = h.WithBasicCredentialResolver(c.authority)
		}
		h = h.WithLogger(slog.New(slog.NewJSONHandler(&buf, nil)))
		before := h.BasicCredentialOutcomes()
		_ = askBasic(h, c.verb, c.presented, c.id)
		after := h.BasicCredentialOutcomes()

		cell := BasicCredentialCell{Verb: c.verb, Outcome: c.want}
		require.Equalf(t, before[cell]+1, after[cell], "%s: исход не лёг в свою клетку %v", c.name, cell)
		for k, v := range after {
			if k != cell {
				require.Equalf(t, before[k], v, "%s: сдвинулась чужая клетка %v", c.name, k)
			}
		}
		require.NotContainsf(t, buf.String(), presented, "%s: предъявленная строка в журнале", c.name)
	}
	t.Logf("перепись: исходов вне словаря причин проверено %d", len(cases))
}

// TestBasicCredentialCensus_EveryDeclaredCellIsPresentAtZero — перепись
// заведена целиком: клетка, появляющаяся при первом попадании, не отличает
// «ноль отказов по отсечке» от «исхода без счётчика».
func TestBasicCredentialCensus_EveryDeclaredCellIsPresentAtZero(t *testing.T) {
	declared := DeclaredBasicCredentialCells()
	unique := map[BasicCredentialCell]bool{}
	for _, c := range declared {
		require.Falsef(t, unique[c], "клетка %v объявлена дважды", c)
		unique[c] = true
	}
	for _, verb := range []BasicCredentialVerb{BasicCredentialResolve, BasicCredentialLiveness} {
		for _, r := range domain.BasicCredentialRefusalReasons() {
			require.Truef(t, unique[BasicCredentialCell{Verb: verb, Outcome: BasicCredentialOutcome(r)}],
				"причина %q на глаголе %q не объявлена клеткой переписи", r, verb)
		}
		for _, o := range []BasicCredentialOutcome{BasicOutcomeAccepted, BasicOutcomeReasonUnnamed, BasicOutcomeUnavailable} {
			require.Truef(t, unique[BasicCredentialCell{Verb: verb, Outcome: o}],
				"исход %q на глаголе %q не объявлен клеткой переписи", o, verb)
		}
	}

	census := (&Handler{}).BasicCredentialOutcomes()
	require.Lenf(t, census, len(declared), "перепись свежего обработчика несёт %d клеток, объявлено %d",
		len(census), len(declared))
	for _, c := range declared {
		v, ok := census[c]
		require.Truef(t, ok, "клетка %v объявлена и в переписи отсутствует", c)
		require.Zerof(t, v, "клетка %v свежего обработчика не нулевая", c)
	}
	t.Logf("перепись: клеток объявлено %d", len(declared))
}
