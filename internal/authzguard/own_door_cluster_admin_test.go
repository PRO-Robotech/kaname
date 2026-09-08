// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_cluster_admin_test.go — плоский надзор администратора облака ДЕЙСТВУЕТ
// и на собственной двери iam.
//
// # Предмет
//
// Надзор администратора облака — ПЛОСКИЙ супер-гейт: один факт
// `cluster:<singleton> # system_admin @ <субъект>`, а НЕ вывод модели. Он живёт
// отдельным звеном, и каждое место решения о доступе применяет его САМО:
//
//   - `authorize_service.check` — тем и отвечает шести соседям платформы и краю
//     (`SubjectIsClusterAdminPlainE`, короткое замыкание перед вопросом модели);
//   - `AllowsVerb`/`AllowsVGet` — собственные читающие стражи iam, тот же вызов
//     перед вопросом об объекте.
//
// Собственная дверь спрашивает ТОТ ЖЕ порт отношений (`svcs.ownGates`), но
// пересылала тройку прямо форме, минуя супер-гейт. То есть два места решения
// ВНУТРИ ОДНОГО сервиса судили одним портом и разным правилом.
//
// # Почему модель этого не закрывает и закрыть не может
//
// У части отношений арма надзора НЕТ НАМЕРЕННО. Каноничный пример и есть тот, на
// котором это найдено: `iam_user` объявляет `token_issuer: subject` — обладать им
// можно единственным способом, БЫТЬ этим человеком; ни кортежем, ни ролью, ни
// реконсайлером оно не выдаётся, и источников уровня аккаунта у него нет
// намеренно (персональный токен делает предъявителя самим человеком во ВСЕХ его
// аккаунтах). Значит машина приходит к этому глаголу ЕДИНСТВЕННЫМ путём —
// плоским надзором, — и дверь без надзора отвергает её ВСЕГДА, при любой выдаче.
//
// Наблюдалось: посев матрицы сквозных проб умирал на чеканке персонального
// токена — `UserTokenService/Issue` отвечал 403 `AUTHZ_DENIED`
// (`action=iam.issue_user_tokens.issue`, `scope=resource`) учётке первичной
// посадки, которая держит `system_admin` на кластере. Пять шардов из пяти не
// запускались вовсе: прогон недействителен, а не красен.
//
// # Инъекция в обе стороны
//
// Отрицание здесь идёт в паре с положительным близнецом: арендатор БЕЗ надзора
// на том же глаголе и том же объекте обязан остаться отвергнутым. Без него
// «администратор прошёл» зеленело бы и на двери, пропускающей всех, — то есть
// починка была бы неотличима от снятия двери.

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

const (
	// clusterAdminMachine — учётка, держащая плоский надзор. Вид субъекта здесь
	// несущий: посадочная учётка платформы — МАШИНА, а `token_issuer: subject`
	// принимает только `[user]`, поэтому вывода модели у неё нет ни при какой
	// выдаче.
	clusterAdminMachine = "sva00000000000000001"

	// foreignUser — человек, на которого чеканят токен. Не совпадает с
	// вызывающим намеренно: совпадение дало бы `subject`, то есть проба прошла бы
	// выводом модели и о надзоре не сказала бы ничего.
	foreignUser = "usr00000000000000042"

	// credentialMint — глагол, у которого армы надзора в модели нет.
	credentialMint = "/kaname.cloud.iam.v1.UserTokenService/Issue"
)

// clusterSuperGateFact — единственный факт, которым учётка первичной посадки
// заведена миграцией: `system_admin` на синглтоне кластера.
func clusterSuperGateFact(subject string) map[string]bool {
	return map[string]bool{
		subject + "|system_admin|" + "cluster:cluster_root": true,
	}
}

// machineCtx — контекст аутентифицированной служебной учётки.
func machineCtx(svaID string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "service_account", ID: svaID})
}

// mintRequest — вход глагола чеканки: объект двери берётся из `user_id`.
func mintRequest(userID string) *iamv1.IssueUserTokenRequest {
	return &iamv1.IssueUserTokenRequest{UserId: userID, Name: "own-door-probe"}
}

// ОТРИЦАНИЕ (RED до починки): администратор облака проходит там, где вывода
// модели у него нет ни при какой выдаче.
func TestOwnDoor_ClusterAdminPassesWhereTheModelHasNoArmForHim(t *testing.T) {
	store := &grantStore{allow: clusterSuperGateFact("service_account:" + clusterAdminMachine)}
	hit := false
	_, err := doorUnder(t, store)(
		machineCtx(clusterAdminMachine),
		mintRequest(foreignUser),
		&grpc.UnaryServerInfo{FullMethod: credentialMint},
		reached(&hit),
	)
	if err != nil || !hit {
		t.Fatalf("администратору облака отказано на глаголе без армы надзора: err=%v, "+
			"обработчик достигнут=%v.\n  спрошено у модели: %v\n"+
			"  плоский надзор — единственный путь машины к `token_issuer: subject`; "+
			"дверь, не спросившая его, отвергает посадочную учётку ВСЕГДА",
			err, hit, store.asked)
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: арендатор БЕЗ надзора на том же глаголе и объекте остаётся
// отвергнутым.
//
// Молчит и до починки, и после. Без него отрицание выше зеленело бы на двери,
// пропускающей всех, — то есть на снятой двери.
func TestOwnDoor_PlainCallerStaysRefusedOnAnothersCredentialMint(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		machineCtx(clusterAdminMachine),
		mintRequest(foreignUser),
		&grpc.UnaryServerInfo{FullMethod: credentialMint},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatalf("посторонний чеканит токен на чужого человека: обработчик достигнут=%v, err=%v.\n"+
			"  спрошено у модели: %v", hit, err, store.asked)
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ ВТОРОЙ: человек, чей это токен, проходит ВЫВОДОМ МОДЕЛИ, а не
// надзором.
//
// Держит вторую половину того же свойства: починка обязана добавить арму, а не
// заменить вопрос об объекте вопросом о надзоре.
func TestOwnDoor_SubjectMintsHisOwnCredentialThroughTheModel(t *testing.T) {
	store := &grantStore{allow: map[string]bool{
		"user:" + foreignUser + "|token_issuer|iam_user:" + foreignUser: true,
	}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(foreignUser),
		mintRequest(foreignUser),
		&grpc.UnaryServerInfo{FullMethod: credentialMint},
		reached(&hit),
	)
	if err != nil || !hit {
		t.Fatalf("человеку отказано в токене на самого себя: err=%v, обработчик достигнут=%v.\n"+
			"  спрошено у модели: %v", err, hit, store.asked)
	}
}

// partialStore — форма, которая на ОДИН вопрос отвечает, а на другой нет.
//
// Нужна затем, что общая фикстура роняет ВСЕ вопросы разом, и корень «объект не
// ответил, надзор ответил» ею невыразим — то есть решение об этой ветви осталось
// бы без держателя.
type partialStore struct {
	allow    map[string]bool
	failWhen func(relation, object string) bool
	asked    []string
}

func (p *partialStore) Check(_ context.Context, subject, relation, object string) (bool, error) {
	p.asked = append(p.asked, subject+"|"+relation+"|"+object)
	if p.failWhen != nil && p.failWhen(relation, object) {
		return false, context.DeadlineExceeded
	}
	return p.allow[subject+"|"+relation+"|"+object], nil
}

// НЕОТВЕТИВШИЙ ВОПРОС ОБ ОБЪЕКТЕ остаётся исходом «решить не удалось» — даже
// когда субъект администратор облака.
//
// Держатель ветви, разошедшейся с `AllowsVerb` намеренно: он спрашивает надзор
// первым и разрешил бы, дверь повторяет `verdict` и не разрешает. Расхождение
// названо в godoc checkAdapter; без этой пробы оно осталось бы объявлением.
func TestOwnDoor_ObjectOutageIsNotOverriddenByTheSuperGate(t *testing.T) {
	subject := "service_account:" + clusterAdminMachine
	store := &partialStore{
		allow: clusterSuperGateFact(subject),
		failWhen: func(relation, _ string) bool {
			return relation == "token_issuer"
		},
	}
	hit := false
	_, err := doorUnder(t, store)(
		machineCtx(clusterAdminMachine),
		mintRequest(foreignUser),
		&grpc.UnaryServerInfo{FullMethod: credentialMint},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatalf("вопрос об объекте не ответил, а вызов прошёл надзором: "+
			"обработчик достигнут=%v, err=%v.\n  спрошено: %v", hit, err, store.asked)
	}
	// Надзор здесь не спрашивается вовсе: второй вопрос неполученного ответа не
	// заменяет. Проверяется ОБЪЁМ спрошенного, иначе «не разрешил» было бы
	// неотличимо от «разрешил бы, да не успел».
	for _, q := range store.asked {
		if q == subject+"|system_admin|cluster:cluster_root" {
			t.Fatalf("надзор спрошен поверх неответившего объекта: %v", store.asked)
		}
	}
	t.Logf("спрошено у формы: %v", store.asked)
}

// НЕДОСТУПНОСТЬ МОДЕЛИ остаётся отказом и после того, как у двери появился второй
// вопрос.
//
// Проба существует потому, что второй вопрос — способ проглотить неполадку:
// «объект не разрешил, надзор не ответил» обязано остаться «решить не удалось», а
// не превратиться ни в разрешение, ни в молчаливый отказ по правам.
func TestOwnDoor_SuperGateOutageIsNotADecision(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}, err: context.DeadlineExceeded}
	hit := false
	_, err := doorUnder(t, store)(
		machineCtx(clusterAdminMachine),
		mintRequest(foreignUser),
		&grpc.UnaryServerInfo{FullMethod: credentialMint},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatalf("модель не ответила, а вызов прошёл: обработчик достигнут=%v, err=%v", hit, err)
	}
}
