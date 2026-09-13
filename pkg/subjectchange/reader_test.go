// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package subjectchange_test

// reader_test.go — как читатель НАЗЫВАЕТ субъекта (kacho#1022).
//
// # Почему это отдельная проба, а не следствие сквозной
//
// Журнал владельца отдаёт `subject_id` ГОЛЫМ идентификатором. Субъектом модели
// прав он становится только в паре с типом, а тип приезжает отдельным полем —
// которого у этого сообщения раньше не было вовсе. Ключ, под которым учтён
// открытый поток, обязан совпасть с именем отзыва ПО ПОСТРОЕНИЮ: голый
// идентификатор не совпадает с ним ни при каких условиях, и отзыв не имел бы
// действия на длинных соединениях вообще.
//
// Здесь настоящий gRPC владельца и настоящий адаптер; что это же имя закрывает
// настоящий открытый поток — утверждает сквозная проба у потребителя
// (`gateway/internal/subscriptionstream`, `TestPolledRevocationClosesTheOpenStreamEndToEnd`).

import (
	"context"
	"net"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/PRO-Robotech/corelib/authz"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// iamJournalStub — внутренний глагол iam, отдающий заготовленные порции.
//
// Порции ЗА ПЕРВОЙ отдаются только после того, как проба их отпустит: иначе
// «праймящий перепрос никого не закрыл» и «отзыв ещё не приехал» — одно и то же
// наблюдение, и утверждение о первом ничего бы не значило.
type iamJournalStub struct {
	iamv1.UnimplementedInternalIAMServiceServer
	mu      sync.Mutex
	batches [][]*iamv1.SubjectChange
	calls   int
	primed  chan struct{}
	release chan struct{}
}

func newIamJournalStub(batches ...[]*iamv1.SubjectChange) *iamJournalStub {
	return &iamJournalStub{
		batches: batches,
		primed:  make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (s *iamJournalStub) PollSubjectChanges(
	_ context.Context, _ *iamv1.PollSubjectChangesRequest,
) (*iamv1.PollSubjectChangesResponse, error) {
	s.mu.Lock()
	i := s.calls
	s.calls++
	var b []*iamv1.SubjectChange
	if i < len(s.batches) {
		b = s.batches[i]
	}
	s.mu.Unlock()

	if s.primed != nil {
		if i == 0 {
			close(s.primed)
		} else {
			<-s.release
		}
	}

	var head int64
	for _, c := range b {
		if c.GetId() > head {
			head = c.GetId()
		}
	}
	return &iamv1.PollSubjectChangesResponse{Changes: b, HeadId: head}, nil
}

// dial поднимает названную службу на bufconn и отдаёт соединение.
func dial(t *testing.T, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 16)
	srv := grpc.NewServer()
	register(srv)
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("дозвон: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return conn
}

// TestPolledRowWithoutSubjectTypeNamesNobody — строка БЕЗ типа субъекта.
//
// Такие строки записаны до того, как производители начали проставлять тип.
// Собрать из них субъекта нельзя, и выводить тип из написания идентификатора
// запрещено: этот приём уже давал совпадение с тем, чего продукт не производит.
// Строка обязана двигать курсор и НЕ закрывать никого — в том числе не закрывать
// «на всякий случай» всех.
func TestPolledRowWithoutSubjectTypeNamesNobody(t *testing.T) {
	iamStub := &iamJournalStub{batches: [][]*iamv1.SubjectChange{
		{{Id: 1, SubjectId: "usr00000000000000009", SubjectType: "user"}},
		{{Id: 2, SubjectId: "usr00000000000000001", Op: "binding_revoke"}},
	}}

	iamConn := dial(t, func(s *grpc.Server) {
		iamv1.RegisterInternalIAMServiceServer(s, iamStub)
	})
	poller := subjectchange.NewReader(iamConn)

	if _, _, err := poller.PollSubjectChanges(context.Background(), 0, 256); err != nil {
		t.Fatalf("первый перепрос: %v", err)
	}
	changes, _, err := poller.PollSubjectChanges(context.Background(), 1, 256)
	if err != nil {
		t.Fatalf("второй перепрос: %v", err)
	}
	if len(changes) != 1 {
		t.Fatalf("строк %d, ожидалась 1", len(changes))
	}
	if changes[0].ID != 2 {
		t.Errorf("номер строки %d — курсор обязан двигаться и по неименованной строке", changes[0].ID)
	}
	if changes[0].Subject != "" {
		t.Errorf("субъект собран как %q из строки без типа — тип выведен из написания идентификатора",
			changes[0].Subject)
	}
}

// TestPolledSubjectIsNamedTheWayTheRegistryKeysIt — форма имени, названная
// ДОСЛОВНО, а не вызовом того же кодека.
//
// Ожидание записано литералом намеренно: сверка с `listnarrow.Subject` была бы
// тождеством и осталась бы зелёной, если бы кодек сменил форму, — то есть
// утверждала бы о себе, а не о том, что реестр такой ключ содержит.
func TestPolledSubjectIsNamedTheWayTheRegistryKeysIt(t *testing.T) {
	iamStub := &iamJournalStub{batches: [][]*iamv1.SubjectChange{
		{{Id: 1, SubjectId: "usr00000000000000009", SubjectType: "user"}},
		{
			{Id: 2, SubjectId: "usr00000000000000001", SubjectType: "user"},
			{Id: 3, SubjectId: "sva00000000000000001", SubjectType: "service_account"},
			{Id: 4, SubjectId: "grp00000000000000001", SubjectType: "group"},
		},
	}}
	iamConn := dial(t, func(s *grpc.Server) {
		iamv1.RegisterInternalIAMServiceServer(s, iamStub)
	})
	poller := subjectchange.NewReader(iamConn)
	if _, _, err := poller.PollSubjectChanges(context.Background(), 0, 256); err != nil {
		t.Fatalf("первый перепрос: %v", err)
	}
	changes, _, err := poller.PollSubjectChanges(context.Background(), 1, 256)
	if err != nil {
		t.Fatalf("второй перепрос: %v", err)
	}

	want := []string{
		"user:usr00000000000000001",
		"service_account:sva00000000000000001",
		// Группа субъектом ПОТОКА не бывает: поток учитывается под тем, кто
		// предъявил удостоверение, а удостоверение предъявляет человек либо
		// служебная учётка. Смена состава группы приезжает отдельной строкой,
		// называющей УЧАСТНИКА.
		"",
	}
	if len(changes) != len(want) {
		t.Fatalf("строк %d, ожидалось %d", len(changes), len(want))
	}
	for i, w := range want {
		if changes[i].Subject != w {
			t.Errorf("строка %d названа %q, ожидалось %q", i, changes[i].Subject, w)
		}
	}
}

// TestPolledRowCarriesWhyItHasNoName — читатель НАЗЫВАЕТ причину безымянности,
// а не только оставляет имя пустым (kacho#1463).
//
// Проба идёт настоящим адаптером по настоящему gRPC намеренно: разбор исхода
// живёт ровно здесь, и утверждение о нём на подставном источнике осталось бы
// зелёным, если бы адаптер проставлял один и тот же исход всем строкам.
func TestPolledRowCarriesWhyItHasNoName(t *testing.T) {
	iamStub := &iamJournalStub{batches: [][]*iamv1.SubjectChange{
		{{Id: 1, SubjectId: "usr00000000000000009", SubjectType: "user"}},
		{
			{Id: 2, SubjectId: "usr00000000000000001", SubjectType: "user"},
			// НОРМА: потоков по множеству участников не заводится.
			{Id: 3, SubjectId: "grp00000000000000001", SubjectType: "group"},
			// ДЕФЕКТ: производитель не проставил тип — имя потеряно.
			{Id: 4, SubjectId: "usr00000000000000002"},
			// ДЕФЕКТ: тип вне словаря продукта. Считать его нормой значило бы
			// вернуть дефект в тихую корзину, только под другим именем.
			{Id: 5, SubjectId: "usr00000000000000003", SubjectType: "nonsense"},
		},
	}}
	iamConn := dial(t, func(s *grpc.Server) {
		iamv1.RegisterInternalIAMServiceServer(s, iamStub)
	})
	poller := subjectchange.NewReader(iamConn)
	if _, _, err := poller.PollSubjectChanges(context.Background(), 0, 256); err != nil {
		t.Fatalf("первый перепрос: %v", err)
	}
	changes, _, err := poller.PollSubjectChanges(context.Background(), 1, 256)
	if err != nil {
		t.Fatalf("второй перепрос: %v", err)
	}

	want := []authz.SubjectNaming{
		authz.SubjectNamed,
		authz.SubjectUserset,
		authz.SubjectUnnameable,
		authz.SubjectUnnameable,
	}
	if len(changes) != len(want) {
		t.Fatalf("строк %d, ожидалось %d", len(changes), len(want))
	}
	for i, w := range want {
		if changes[i].Naming != w {
			t.Errorf("строка %d (номер %d): исход %v, ожидался %v",
				i, changes[i].ID, changes[i].Naming, w)
		}
	}
}
