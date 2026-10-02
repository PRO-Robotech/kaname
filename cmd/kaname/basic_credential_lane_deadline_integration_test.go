// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// basic_credential_lane_deadline_integration_test.go — авторитет о базовом
// секрете, СОБРАННЫЙ корнем, обращается к базе под объявленным пределом на
// вызов — тем же, что у полос выдачи токена (задача kaname#379).
//
// # Почему через сборку и через базу
//
// Проба, зовущая оператор с пределом, выставленным самой пробой, утверждает,
// что оператор его ставит, и молчит о том, какой предел даёт корень. Здесь
// авторитет берётся у той же функции, которой его собирает корень, вопрос идёт
// в глагол внутреннего слушателя, а срок смотрится там, куда запрос приходит на
// живом пути, — у самого обращения к базе, трассировщиком пула.
//
// # Чем проба защищена от собственной снисходительности
//
// Вопрос, не дошедший до базы, — не «срок есть», а «не измерено»: проба
// называет его и падает. Контекст вопроса — без срока: будь предел у
// вызывающего, а не у авторитета, его здесь не было бы вовсе.

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/corelib/pgtest"

	internaliamapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// credentialQuery — одно обращение к строкам удостоверений глазами пула.
type credentialQuery struct {
	hadDeadline bool
	remaining   time.Duration
}

// credentialQueryTracer — трассировщик пула: запоминает срок контекста каждого
// обращения к таблицам удостоверений. Прочие запросы пула его не касаются.
type credentialQueryTracer struct {
	mu    sync.Mutex
	calls []credentialQuery
}

func (r *credentialQueryTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if !strings.Contains(data.SQL, "_oauth_clients") {
		return ctx
	}
	dl, had := ctx.Deadline()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, credentialQuery{hadDeadline: had, remaining: time.Until(dl)})
	return ctx
}

func (r *credentialQueryTracer) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

// take отдаёт накопленные обращения и начинает счёт заново.
func (r *credentialQueryTracer) take() []credentialQuery {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.calls
	r.calls = nil
	return out
}

// TestBasicCredentialLaneQueriesTheBaseUnderTheDeclaredLimit — каждый вопрос к
// авторитету, собранному корнем, доходит до базы со своим сроком, не большим
// объявленного.
func TestBasicCredentialLaneQueriesTheBaseUnderTheDeclaredLimit(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres: срок смотрится у обращения к базе")
	}
	if credentialLanePeerTimeout <= 0 {
		t.Fatalf("предпосылка: объявленный предел на вызов обязан быть положительным, объявлено %s",
			credentialLanePeerTimeout)
	}
	ctx := context.Background()
	cfg, err := pgxpool.ParseConfig(iampgtest.AppendIAMSearchPath(pgtest.NewDB(t)))
	require.NoError(t, err)
	tracer := &credentialQueryTracer{}
	cfg.ConnConfig.Tracer = tracer
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	authority, err := newBasicCredentialAuthority(pool)
	require.NoError(t, err, "корень не собрал авторитет с объявленным пределом")
	h := internaliamapp.NewHandler(internaliamapp.NewLookupSubjectUseCase(nil), nil).
		WithBasicCredentialResolver(authority)

	const (
		userID = "uoc_dlim0000000000001"
		saID   = "soc_dlim0000000000002"
	)
	userSecret, _, err := credsecret.Mint(userID)
	require.NoError(t, err)
	saSecret, _, err := credsecret.Mint(saID)
	require.NoError(t, err)

	// Вопросы — ровно те, что задаёт край, и отметка предъявления, которую
	// глагол ставит на принятом. Строк нет: срок смотрится у обращения, а не у
	// ответа, и отказ «строки нет» обращается к базе так же, как принятие.
	questions := []struct {
		name string
		ask  func(context.Context)
	}{
		{"резолв секрета человека", func(c context.Context) {
			_, _ = h.ResolveBasicCredential(c, &iamv1.ResolveBasicCredentialRequest{Presented: userSecret})
		}},
		{"резолв секрета машины", func(c context.Context) {
			_, _ = h.ResolveBasicCredential(c, &iamv1.ResolveBasicCredentialRequest{Presented: saSecret})
		}},
		{"живость удостоверения человека", func(c context.Context) {
			_, _ = h.CheckBasicCredentialLive(c, &iamv1.CheckBasicCredentialLiveRequest{CredentialId: userID})
		}},
		{"живость удостоверения машины", func(c context.Context) {
			_, _ = h.CheckBasicCredentialLive(c, &iamv1.CheckBasicCredentialLiveRequest{CredentialId: saID})
		}},
		{"отметка предъявления", func(c context.Context) {
			_ = authority.TouchLastUsed(c, saID, time.Second)
		}},
	}

	var reached, bounded int
	for _, q := range questions {
		if _, had := ctx.Deadline(); had {
			t.Fatalf("предпосылка: контекст вопроса не несёт срока, а у %q он есть", q.name)
		}
		q.ask(ctx)
		calls := tracer.take()
		if len(calls) == 0 {
			t.Fatalf("%s: вопрос не дошёл до базы — предел НЕ ИЗМЕРЕН, это не зелёное", q.name)
		}
		reached++
		ok := 0
		for i, c := range calls {
			if !c.hadDeadline {
				t.Errorf("%s: обращение #%d идёт без своего предела времени — неотвечающая база держит "+
					"глагол сколько угодно", q.name, i+1)
				continue
			}
			if c.remaining <= 0 || c.remaining > credentialLanePeerTimeout {
				t.Errorf("%s: обращение #%d несёт срок %s, а объявленный предел на вызов — %s",
					q.name, i+1, c.remaining, credentialLanePeerTimeout)
				continue
			}
			ok++
		}
		if ok == len(calls) {
			bounded++
		}
	}
	t.Logf("перепись: вопросов задано %d · дошли до базы %d · обращаются под пределом %s — %d",
		len(questions), reached, credentialLanePeerTimeout, bounded)
}
