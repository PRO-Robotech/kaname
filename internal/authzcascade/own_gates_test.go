// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzcascade_test

// own_gates_test.go — ДВЕРЬ РЕШЕНИЯ: что она утверждает вызывающему.
//
// Предмет проб — не «метод есть», а ИСХОД, и прежде всего исход, который легче
// всего потерять: разница между «доступа нет» и «ответа нет». Слить их значило бы
// читать недоступность базы как законный отказ — молча и на каждом запросе.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho-iam/internal/clients"
)

// formStub — подставная форма. НЕ снисходительнее настоящей: она не «глотает»
// вход, а записывает, о чём именно её спросили, чтобы проба утверждала переданный
// вопрос, а не факт вызова.
type formStub struct {
	allowed   bool
	err       error
	manyOut   []bool
	manyErr   error
	subjects  []string
	nextAfter map[string]string
	sources   []string
	relations []string

	gotSubject    string
	gotObjectType string
	gotObjectID   string
	gotRelation   string
	gotIDs        []string
	pages         int
}

func (f *formStub) Allowed(_ context.Context, subject, objectType, objectID, relation string, _ map[string]any) (bool, error) {
	f.gotSubject, f.gotObjectType, f.gotObjectID, f.gotRelation = subject, objectType, objectID, relation
	return f.allowed, f.err
}

func (f *formStub) AllowedMany(_ context.Context, subject, objectType string, ids []string, relation string, _ map[string]any) ([]bool, error) {
	f.gotSubject, f.gotObjectType, f.gotRelation = subject, objectType, relation
	f.gotIDs = append([]string(nil), ids...)
	return f.manyOut, f.manyErr
}

func (f *formStub) SubjectsPage(_ context.Context, objectType, objectID, relation, after string, _ int) ([]string, string, error) {
	f.pages++
	f.gotObjectType, f.gotObjectID, f.gotRelation = objectType, objectID, relation
	if f.nextAfter == nil {
		return f.subjects, "", nil
	}
	return f.subjects, f.nextAfter[after], nil
}

func (f *formStub) Sources(_ context.Context, objectType, objectID, relation string) ([]string, error) {
	f.gotObjectType, f.gotObjectID, f.gotRelation = objectType, objectID, relation
	return f.sources, nil
}

func (f *formStub) DirectRelations(_ context.Context, subject, objectType, objectID string, _ int) ([]string, error) {
	f.gotSubject, f.gotObjectType, f.gotObjectID = subject, objectType, objectID
	return f.relations, nil
}

// Дверь обязана быть подставима на каждом порту, который провязывает корень.
var (
	_ clients.RelationStore   = (*authzcascade.Client)(nil)
	_ clients.RelationQueries = (*authzcascade.Client)(nil)
)

func TestCheckAsksTheFormAboutTheParsedObject(t *testing.T) {
	f := &formStub{allowed: true}
	c := authzcascade.Wrap(f)

	allowed, err := c.Check(context.Background(), "user:usr_a", "viewer", "vpc_network:net_1")
	require.NoError(t, err)
	require.True(t, allowed)

	// Вопрос передан РАЗОБРАННЫМ: форма спрашивается типом и идентификатором
	// отдельно, и склейка обратно потеряла бы идентификатор с двоеточием внутри.
	require.Equal(t, "user:usr_a", f.gotSubject)
	require.Equal(t, "vpc_network", f.gotObjectType)
	require.Equal(t, "net_1", f.gotObjectID)
	require.Equal(t, "viewer", f.gotRelation)
}

func TestObjectIDKeepsItsColons(t *testing.T) {
	f := &formStub{}
	c := authzcascade.Wrap(f)

	_, err := c.Check(context.Background(), "user:usr_a", "viewer", "registry_repository:reg_1/app:v2")
	require.NoError(t, err)
	require.Equal(t, "registry_repository", f.gotObjectType)
	require.Equal(t, "reg_1/app:v2", f.gotObjectID,
		"идентификатор режется по ПЕРВОМУ двоеточию: у репозитория реестра оно есть и внутри")
}

func TestUnparsableObjectIsAnErrorNotADenial(t *testing.T) {
	c := authzcascade.Wrap(&formStub{})

	allowed, err := c.Check(context.Background(), "user:usr_a", "viewer", "мусор-без-двоеточия")
	require.Error(t, err, "неразобранный объект обязан быть ОШИБКОЙ: вернув «нет», дверь "+
		"превратила бы опечатку в законный отказ, которого никто никогда не найдёт")
	require.False(t, allowed)
}

func TestFormNotWiredIsAnErrorNotADenial(t *testing.T) {
	c := authzcascade.Wrap(nil)

	allowed, err := c.Check(context.Background(), "user:usr_a", "viewer", "vpc_network:net_1")
	require.ErrorIs(t, err, authzcascade.ErrFormNotWired)
	require.False(t, allowed)
	require.False(t, c.FormReachable(), "страж старта обязан видеть непровязанную форму")
}

func TestFormErrorReachesTheCallerUntouched(t *testing.T) {
	boom := errors.New("база не ответила")
	c := authzcascade.Wrap(&formStub{err: boom})

	allowed, err := c.CheckWithContext(context.Background(), "user:usr_a", "viewer", "vpc_network:net_1", nil)
	require.ErrorIs(t, err, boom,
		"«не смог спросить» и «доступа нет» — разные миры; представление первого на "+
			"успешном пути делает недоступность базы неотличимой от законного отказа")
	require.False(t, allowed)
}

func TestBatchKeepsLengthAndOrder(t *testing.T) {
	f := &formStub{manyOut: []bool{true, false, true}}
	c := authzcascade.Wrap(f)

	got, err := c.BatchCheckWithContext(context.Background(), "user:usr_a", "v_list",
		[]string{"vpc_network:a", "vpc_network:b", "vpc_network:c"}, nil)
	require.NoError(t, err)
	require.Equal(t, []bool{true, false, true}, got,
		"верный, но переставленный вердикт отфильтровал бы страницу чужим ответом")
	require.Equal(t, []string{"a", "b", "c"}, f.gotIDs)
	require.Equal(t, "vpc_network", f.gotObjectType)
}

func TestBatchRefusesTwoObjectTypes(t *testing.T) {
	c := authzcascade.Wrap(&formStub{})

	_, err := c.BatchCheckWithContext(context.Background(), "user:usr_a", "v_list",
		[]string{"vpc_network:a", "compute_instance:b"}, nil)
	require.Error(t, err, "партия с двумя типами обязана быть ошибкой, а не молчаливым "+
		"разбиением: страница списка однотипна по построению, и партия, где это не так, "+
		"означает ошибку вызывающего")
}

func TestEmptyBatchAsksNothing(t *testing.T) {
	f := &formStub{}
	c := authzcascade.Wrap(f)

	got, err := c.BatchCheckWithContext(context.Background(), "user:usr_a", "v_list", nil, nil)
	require.NoError(t, err)
	require.Empty(t, got)
	require.Empty(t, f.gotIDs, "пустая партия не должна открывать чтение")
}

func TestListSubjectsPassesTheCursorThrough(t *testing.T) {
	f := &formStub{subjects: []string{"user:usr_a"}, nextAfter: map[string]string{"": "usr_a"}}
	c := authzcascade.Wrap(f)

	subs, next, err := c.ListSubjects(context.Background(), "vpc_network", "net_1", "viewer", 10, "")
	require.NoError(t, err)
	require.Equal(t, []string{"user:usr_a"}, subs)
	require.Equal(t, "usr_a", next,
		"курсор обязан проходить насквозь: страница без продолжения оставляет остаток "+
			"недостижимым при живых правах")
}

func TestListUsersNarrowsBySubjectTypeAndWalksPages(t *testing.T) {
	f := &formStub{
		subjects:  []string{"user:usr_a", "service_account:sva_b", "group:grp_c"},
		nextAfter: map[string]string{"": "usr_a"}, // одна дополнительная страница
	}
	c := authzcascade.Wrap(f)

	got, truncated, err := c.ListUsers(context.Background(), "vpc_network", "net_1", "viewer",
		[]string{"user", "service_account"})
	require.NoError(t, err)
	require.False(t, truncated,
		"признак усечения у формы всегда ложь, и это ЧЕСТНОЕ значение: перечисление "+
			"постранично и продолжаемо, неполного ответа без продолжения у неё не бывает")
	require.Equal(t, []string{
		"user:usr_a", "service_account:sva_b",
		"user:usr_a", "service_account:sva_b",
	}, got, "сужение по типу субъекта отбрасывает группу на КАЖДОЙ странице")
	require.Equal(t, 2, f.pages, "обход обязан идти по страницам, а не брать первую")
}

func TestListUsersWithoutFilterKeepsEverySubjectType(t *testing.T) {
	f := &formStub{subjects: []string{"user:usr_a", "group:grp_c"}}
	c := authzcascade.Wrap(f)

	got, _, err := c.ListUsers(context.Background(), "vpc_network", "net_1", "viewer", nil)
	require.NoError(t, err)
	require.Equal(t, []string{"user:usr_a", "group:grp_c"}, got,
		"пустой набор типов означает «любой», а не «никакой»")
}

func TestConsistentCheckAsksTheSameQuestion(t *testing.T) {
	f := &formStub{allowed: true}
	c := authzcascade.Wrap(f)

	allowed, err := c.CheckWithContextConsistent(context.Background(), "user:usr_a", "viewer", "account:acc_1", nil)
	require.NoError(t, err)
	require.True(t, allowed)
	require.Equal(t, "account", f.gotObjectType,
		"просьба «ответь не с реплики» адресовалась чужому хранилищу; форма читает "+
			"ведущую базу, поэтому требование выполнено безусловно — а вопрос тот же")
}

func TestDerivableTypesStayTheOwnersList(t *testing.T) {
	// Перечень читает перепись источников звена цепи областей. Пустой перечень
	// означал бы, что перепись молчит про КАЖДЫЙ тип, — и молчала бы она зелено.
	require.NotEmpty(t, authzcascade.DerivableTypes)
	for _, want := range []string{"account", "project", "iam_role", "iam_access_binding"} {
		require.Contains(t, authzcascade.DerivableTypes, want)
	}
}

// DirectRelationsMany — та же диагностика о СТРАНИЦЕ объектов, тем же оракулом,
// из которого отвечает пообъектная: подставная форма, отвечающая странице не то,
// что отвечает по одному, скрыла бы ровно то расхождение, ради которого её и
// подставляют.
func (f *formStub) DirectRelationsMany(ctx context.Context, subject, objectType string,
	objectIDs []string, limit int) (map[string][]string, error) {
	out := make(map[string][]string, len(objectIDs))
	for _, objectID := range objectIDs {
		rels, err := f.DirectRelations(ctx, subject, objectType, objectID, limit)
		if err != nil {
			return nil, err
		}
		if len(rels) > 0 {
			out[objectID] = rels
		}
	}
	return out, nil
}
