// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// shadow_questions_test.go — КАЖДЫЙ вопрос решения о доступе задаётся ОБЕИМ
// формам, теневой вопрос уходит ПЕРВЫМ, и ответ вызывающему от этого не меняется.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТИХ УТВЕРЖДЕНИЙ НУЖНО ТРИ, А НЕ ОДНО
//
// «Спрашивает» без «не меняет» допускает провязку, которая однажды начнёт влиять
// на вердикт, — и это заметят по чужому доступу.
//
// «Не меняет» без «спрашивает» удовлетворяется провязкой, которой нет вовсе:
// ответ тот же потому, что сравнения не было.
//
// И оба без «спрашивает ПЕРВЫМ» удовлетворяются провязкой, которая сравнивает
// только там, где движок дошёл до ответа: путь, где ответ пришёл дёшево или не
// пришёл, сравнения не получает, а «расхождений нет» продолжает читаться как
// свойство всех решений.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authztypes"
	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// trace — общая лента событий: кто и в каком порядке был спрошен.
type trace struct {
	mu     sync.Mutex
	events []string
}

func (t *trace) add(ev string) {
	t.mu.Lock()
	t.events = append(t.events, ev)
	t.mu.Unlock()
}

func (t *trace) snapshot() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.events...)
}

// firstIndexOf — позиция первого события с этим именем, -1 если его нет.
func (t *trace) firstIndexOf(ev string) int {
	for i, e := range t.snapshot() {
		if e == ev {
			return i
		}
	}
	return -1
}

// tracingRelations — движок, отмечающий на ленте КАЖДОЕ обращение к себе.
type tracingRelations struct {
	tr *trace

	allow     bool
	checkErr  error
	objects   []string
	objectErr error
	subjects  []string
	subjErr   error
	tree      *clients.ExpandTree
	treeErr   error
}

func (m *tracingRelations) CheckWithContext(context.Context, string, string, string, map[string]any) (bool, error) {
	m.tr.add("движок")
	return m.allow, m.checkErr
}

func (m *tracingRelations) ListObjects(context.Context, string, string, string, map[string]any, int) ([]string, error) {
	m.tr.add("движок")
	return m.objects, m.objectErr
}

func (m *tracingRelations) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	m.tr.add("движок")
	return m.subjects, "", m.subjErr
}

func (m *tracingRelations) Expand(context.Context, string, string, string) (*clients.ExpandTree, error) {
	m.tr.add("движок")
	return m.tree, m.treeErr
}

func (m *tracingRelations) ReadTuples(context.Context, string, string, string, int, string) ([]clients.ConditionalTuple, string, error) {
	return nil, "", nil
}

// tracingShadow — теневое сравнение, отмечающее на ленте вопрос и сведение.
type tracingShadow struct {
	tr *trace

	mu             sync.Mutex
	asked          []string
	settled        []string
	unaskable      []string
	settledVerdict []bool
}

func (s *tracingShadow) record(kind string) func(...any) {
	s.tr.add("форма E")
	s.mu.Lock()
	s.asked = append(s.asked, kind)
	s.mu.Unlock()
	return func(...any) {
		s.mu.Lock()
		s.settled = append(s.settled, kind)
		s.mu.Unlock()
	}
}

func (s *tracingShadow) Ask(_ context.Context, _, _, _, _ string, _ map[string]any) func(bool, bool) {
	done := s.record("прямой вердикт")
	return func(allowed, answered bool) {
		s.mu.Lock()
		s.settledVerdict = append(s.settledVerdict, allowed && answered)
		s.mu.Unlock()
		done(allowed, answered)
	}
}

func (s *tracingShadow) AskObjects(_ context.Context, _, _ string, _ []string) func([]string, bool, bool) {
	done := s.record("перечисление объектов")
	return func(ids []string, complete, answered bool) { done(ids, complete, answered) }
}

func (s *tracingShadow) AskSubjects(_ context.Context, _, _, _ string) func([]string, bool, bool) {
	done := s.record("перечисление субъектов")
	return func(subs []string, complete, answered bool) { done(subs, complete, answered) }
}

func (s *tracingShadow) AskSources(_ context.Context, _, _, _ string) func([]string, bool, bool) {
	done := s.record("разворот отношений")
	return func(grounds []string, complete, answered bool) { done(grounds, complete, answered) }
}

func (s *tracingShadow) Unaskable(reason, _, _ string) {
	s.mu.Lock()
	s.unaskable = append(s.unaskable, reason)
	s.mu.Unlock()
}

func (s *tracingShadow) askedKinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.asked...)
}

func (s *tracingShadow) settledKinds() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.settled...)
}

func newTracedService(rel *tracingRelations, sh *tracingShadow) *AuthorizeService {
	return NewAuthorizeService(AuthorizeServiceConfig{
		Relations: rel,
		ModelID:   "model-shadow-1",
		Shadow:    sh,
	})
}

// Каждый из вопросов, которые сервис отвечает движком, обязан быть задан и форме E —
// ПЕРВЫМ, и сведён ровно один раз.
func TestEveryDecisionQuestionAsksTheShadowFormBeforeTheEngine(t *testing.T) {
	cases := []struct {
		name string
		kind string
		call func(*AuthorizeService) error
	}{
		{
			name: "прямой вердикт по действию",
			kind: "прямой вердикт",
			call: func(s *AuthorizeService) error {
				_, err := s.Check(context.Background(), CheckRequest{
					Subject:  "user:usr_alice",
					Resource: ResourceRef{Type: "vpc_network", ID: "net-1"},
					Action:   "vpc.networks.get",
				})
				return err
			},
		},
		{
			name: "прямой вердикт по отношению",
			kind: "прямой вердикт",
			call: func(s *AuthorizeService) error {
				_, err := s.CheckRelation(context.Background(), CheckRelationRequest{
					Subject: "user:usr_alice", Relation: "v_get", Object: "vpc_network:net-1",
				})
				return err
			},
		},
		{
			name: "перечисление объектов",
			kind: "перечисление объектов",
			call: func(s *AuthorizeService) error {
				_, err := s.ListObjects(context.Background(), ListObjectsRequest{
					Subject: "user:usr_alice", ResourceType: "vpc_network", Action: "vpc.networks.list",
				})
				return err
			},
		},
		{
			name: "перечисление субъектов",
			kind: "перечисление субъектов",
			call: func(s *AuthorizeService) error {
				_, err := s.ListSubjects(context.Background(), ListSubjectsRequest{
					ResourceType: "vpc_network", ResourceID: "net-1", Action: "vpc.networks.get",
				})
				return err
			},
		},
		{
			name: "разворот отношений",
			kind: "разворот отношений",
			call: func(s *AuthorizeService) error {
				_, err := s.ExpandRelations(context.Background(), ExpandRequest{
					ResourceType: "vpc_network", ResourceID: "net-1", Relation: "viewer",
				})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := &trace{}
			rel := &tracingRelations{
				tr: tr, allow: true,
				objects:  []string{"net-1"},
				subjects: []string{"user:usr_alice"},
				tree:     &authztypes.ExpandTree{Leaves: []string{"user:usr_alice"}},
			}
			sh := &tracingShadow{tr: tr}

			if err := tc.call(newTracedService(rel, sh)); err != nil {
				t.Fatalf("вопрос отвечен ошибкой: %v", err)
			}

			// (1) СПРОШЕНА — иначе «расхождений нет» означало бы «сравнений не было».
			if got := sh.askedKinds(); len(got) != 1 || got[0] != tc.kind {
				t.Fatalf("форме E задано %v, ожидался ровно один вопрос %q — вопрос, "+
					"уходящий движку без спрашивающего, оставляет сходимость измеренной "+
					"на другом подмножестве", got, tc.kind)
			}
			// (2) СВЕДЕНА — несведённый вопрос оставляет висеть теневой вызов с его сроком.
			if got := sh.settledKinds(); len(got) != 1 {
				t.Fatalf("исход сведён %d раз, ожидался 1 (%v)", len(got), got)
			}
			// (3) ПЕРВОЙ — сравнение, начатое после ответа движка, молчит там, где
			// движок ответил дёшево.
			shadowAt, engineAt := tr.firstIndexOf("форма E"), tr.firstIndexOf("движок")
			if engineAt < 0 {
				t.Fatalf("движок не спрошен вовсе — лента %v", tr.snapshot())
			}
			if shadowAt > engineAt {
				t.Fatalf("форма E спрошена ПОСЛЕ движка (лента %v) — тогда сравнение "+
					"происходит только там, где движок дошёл до ответа, и доля "+
					"сравнённого считается не от тех решений", tr.snapshot())
			}
		})
	}
}

// Движок вердикта не дал — форма E всё равно спрошена, а исход сведён как
// «не выполнилось». Иначе решение выпадает из знаменателя молча.
func TestDecisionAsksTheShadowFormEvenWhenTheEngineDoesNotAnswer(t *testing.T) {
	tr := &trace{}
	rel := &tracingRelations{tr: tr, checkErr: errors.New("движок недоступен")}
	sh := &tracingShadow{tr: tr}

	_, err := newTracedService(rel, sh).CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:usr_alice", Relation: "v_get", Object: "vpc_network:net-1",
	})
	if err == nil {
		t.Fatal("недоступный движок обязан отвечать ошибкой — fail-closed")
	}
	if got := sh.askedKinds(); len(got) != 1 {
		t.Fatalf("форма E не спрошена на пути, где движок не ответил (%v) — путь, "+
			"выпавший из сравнения молча, делает долю сравнённого неизвестной", got)
	}
	if got := sh.settledKinds(); len(got) != 1 {
		t.Fatalf("исход не сведён (%v) — теневой вызов остался висеть со своим сроком", got)
	}
}

// Объект, который не разбирается, форме E не задаётся — но решение обязано быть
// НАЗВАНО, а не пропущено молча.
func TestUnparsableObjectIsDeclaredUnaskableNotSkippedSilently(t *testing.T) {
	tr := &trace{}
	rel := &tracingRelations{tr: tr, allow: true}
	sh := &tracingShadow{tr: tr}

	if _, err := newTracedService(rel, sh).CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:usr_alice", Relation: "v_get", Object: "net-1-без-типа",
	}); err != nil {
		t.Fatalf("вопрос отвечен ошибкой: %v", err)
	}
	if got := sh.askedKinds(); len(got) != 0 {
		t.Fatalf("форма E спрошена о неразобранном объекте (%v) — её честное «нет» "+
			"стало бы расхождением, которого нет", got)
	}
	sh.mu.Lock()
	unaskable := len(sh.unaskable)
	sh.mu.Unlock()
	if unaskable != 1 {
		t.Fatalf("пропуск не назван (%d) — решение, не попавшее в знаменатель, делает "+
			"долю сравнённого лучше, ничего не улучшив", unaskable)
	}
}

// Ответ вызывающему НЕ меняется ни при каком исходе теневого пути.
func TestShadowPathNeverChangesTheAnswer(t *testing.T) {
	for _, engineAllows := range []bool{true, false} {
		tr := &trace{}
		rel := &tracingRelations{tr: tr, allow: engineAllows}
		sh := &tracingShadow{tr: tr}

		res, err := newTracedService(rel, sh).CheckRelation(context.Background(), CheckRelationRequest{
			Subject: "user:usr_alice", Relation: "v_get", Object: "vpc_network:net-1",
		})
		if err != nil {
			t.Fatalf("CheckRelation: %v", err)
		}
		if res.Allowed != engineAllows {
			t.Fatalf("ответ изменился теневым сравнением: %v вместо %v — исход формы E "+
				"не вправе влиять на вердикт, пока отвечает движок", res.Allowed, engineAllows)
		}
	}
}

// Движок ответил САМЫМ КОРОТКИМ путём — так выглядит закэшированный
// положительный вердикт: одно «разрешено» без запасных путей и вторых
// обращений. Сравнение обязано произойти и здесь, иначе оно покрывает ровно те
// решения, которые обошлись дороже, а доля считается от них же.
func TestComparisonHappensOnTheCheapestEngineAnswerToo(t *testing.T) {
	tr := &trace{}
	rel := &tracingRelations{tr: tr, allow: true}
	sh := &tracingShadow{tr: tr}

	res, err := newTracedService(rel, sh).CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:usr_alice", Relation: "v_get", Object: "vpc_network:net-1",
	})
	if err != nil || !res.Allowed {
		t.Fatalf("короткий путь движка отвечен неверно: allowed=%v err=%v", res.Allowed, err)
	}
	if got := sh.askedKinds(); len(got) != 1 {
		t.Fatalf("на самом дешёвом ответе движка форма E не спрошена (%v)", got)
	}
	sh.mu.Lock()
	verdicts := append([]bool(nil), sh.settledVerdict...)
	sh.mu.Unlock()
	if len(verdicts) != 1 || !verdicts[0] {
		t.Fatalf("сведение получило %v — сравнение обязано состояться и на пути, где движок "+
			"ответил дёшево, иначе доля сравнённого считается от решений, обошедшихся дороже",
			verdicts)
	}
	// Движок при этом спрошен РОВНО один раз: проба описывает короткий путь, а не
	// путь с запасными обращениями.
	engineCalls := 0
	for _, e := range tr.snapshot() {
		if e == "движок" {
			engineCalls++
		}
	}
	if engineCalls != 1 {
		t.Fatalf("движок спрошен %d раз — это не короткий путь, и проба описывает не то, "+
			"что называет", engineCalls)
	}
}
