// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_named_asker_test.go — ВОПРОС О ПРАВАХ, заданный НАЗВАННЫМ
// вызывающим, доходит до своего решателя.
//
// # Предмет
//
// Соседний файл (own_door_peer_question_test.go) утверждает вторую половину:
// вопрос БЕЗ личности арендатора дверь пропускает. Половина эта не полна, и
// неполнота её тихая — послабление двери снимается условием `!callerNamed`,
// поэтому вызывающий, личность приславший, идёт в дверь как за обычным
// объектом.
//
// Объекта у вопроса о правах нет. `BatchCheck` объявляет сужение по полю
// `scope_id`, и контракт называет это поле НЕОБЯЗАТЕЛЬНЫМ дословно: «Optional
// scope id for authz of the batch as a whole. When set, the gateway gates the
// entire batch on this scope's permission instead of per-item»
// (proto/kaname/cloud/iam/v1/authorize_service.proto). Незаданное поле означает
// «сужения нет, решает служба по данным», а выведенная карта читает его как
// заданное всегда: извлекатель отдаёт `project:` с пустым идентификатором,
// модель на такой объект отвечает «нет», и вызывающий получает отказ, к правам
// отношения не имеющий.
//
// # Кто задаёт этот вопрос названным
//
// Сужатель списочной выдачи, `pkg/listnarrow/client.go`: он оборачивает
// исходящий контекст `auth.PropagateOutgoing`, чтобы iam увидел РЕАЛЬНОГО
// арендатора, — и делает это намеренно, потому что решатель вопроса
// (`api/authorize/caller_authority.go`) пропускает субъекта, спрашивающего О
// СЕБЕ. Поля `scope_id` сужатель не заполняет ни в одном месте дерева
// (предикат: `git grep -n 'ScopeId' -- pkg/listnarrow` → пусто).
//
// # Что проба ловит
//
// Отказ `PermissionDenied` на `BatchCheck` у названного арендатора. Наблюдалось
// на прогоне 33965153510 (console-e2e, голова d1c7a4a89b): консоль показывала
// «Сервер не смог ответить · list filter: AuthorizeService.BatchCheck
// PermissionDenied: permission denied», списки всех ресурсов проекта были
// пусты, и пять сквозных проб падали на том, что предмет их не виден.
//
// # Почему проба идёт ПО ВСЕМ методам, а не по одному
//
// Соседний контроль назван «арендатор задаёт тот же вопрос и проходит» и
// проверяет РОВНО `Check`. `Check` объявлен `scope_filtered`, то есть объекта у
// него нет by construction и дверь его пропускает при любой личности — на нём
// утверждение истинно и без исправной двери. Перечень же освобождённых растёт,
// и каждая новая запись обязана быть проверена своим прогоном.

import (
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
)

// questionRequestFor — запрос того вида, который по этому RPC шлёт его
// ПРОИЗВОДИТЕЛЬ, а не выдуманный. Метод без записи здесь роняет пробу: новый
// освобождённый RPC обязан приехать вместе со своим входом, иначе перечень
// растёт, а проверяется по-прежнему один.
func questionRequestFor(method string) (any, bool) {
	switch method {
	case "/kaname.cloud.iam.v1.AuthorizeService/Check":
		// Край: вопрос о правах арендатора на пути его же запроса.
		return &iamv1.AuthorizeCheckRequest{Subject: "user:" + ownerUser}, true
	case "/kaname.cloud.iam.v1.AuthorizeService/BatchCheck":
		// Сужатель списочной выдачи: страница объектов, БЕЗ `scope_id` —
		// поле необязательное, и ни один вызывающий его не заполняет.
		return &iamv1.BatchAuthorizeCheckRequest{
			Checks: []*iamv1.AuthorizeCheckRequest{{Subject: "user:" + ownerUser}},
		}, true
	}
	return nil, false
}

// НАЗВАННЫЙ вызывающий задаёт вопрос о правах и доходит до решателя.
func TestOwnDoor_NamedAskerReachesTheHandlerOnEveryQuestionRpc(t *testing.T) {
	methods := authzguard.CallerAuthorityGatedMethods()
	if len(methods) == 0 {
		t.Fatal("освобождённых методов ноль: проба беспредметна — утверждать не о чем")
	}
	for _, method := range methods {
		req, known := questionRequestFor(method)
		if !known {
			t.Errorf("%s: освобождён, а входа для него проба не знает — "+
				"перечень вырос, проверка за ним не пошла", method)
			continue
		}
		// Модель не разрешает НИЧЕГО: решать, кто вправе спрашивать, обязан
		// обработчик, а не выданное отношение. Пустая выдача — тот самый случай,
		// в котором дверь и отказывала.
		store := &grantStore{allow: map[string]bool{}}
		hit := false
		_, err := doorUnder(t, store)(
			tenantCtx(ownerUser),
			req,
			&grpc.UnaryServerInfo{FullMethod: method},
			reached(&hit),
		)
		if err != nil {
			t.Errorf("%s: вопрос названного арендатора отвергнут дверью: %v (код %s). "+
				"Так выглядит пустой список у каждого арендатора: сужатель выдачи "+
				"спрашивает этот RPC на КАЖДОМ списке", method, err, status.Code(err))
			continue
		}
		if !hit {
			t.Errorf("%s: обработчик не достигнут — решать, кто вправе спрашивать, некому", method)
		}
	}
	t.Logf("осмотрено освобождённых методов: %d", len(methods))
}

// ПАРНОЕ ОТРИЦАНИЕ: послабление не распространяется на соседние RPC той же
// службы, даже когда вызывающий назван.
//
// Без него проба выше зеленела бы и на двери, снятой со всей службы.
func TestOwnDoor_NamedAskerIsStillRefusedOutsideTheQuestionRpcs(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(strangerUser),
		&iamv1.GetProjectRequest{ProjectId: victimProject},
		&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.ProjectService/Get"},
		reached(&hit),
	)
	if hit {
		t.Fatal("названный посторонний прошёл к чужому проекту — послабление шире своего предмета")
	}
	if err == nil {
		t.Fatal("отказа нет")
	}
	// Код здесь ИМЕННО `NotFound`, и это не послабление: у чужого проекта дверь
	// скрывает существование, а текст обязан побайтово совпасть с настоящим
	// промахом владельца. Первая редакция этой пробы ждала `PermissionDenied` и
	// была неправа — продукт отвечал верно.
	if status.Code(err) != codes.NotFound {
		t.Fatalf("ожидалось сокрытие существования, получено: %v", err)
	}
	if len(store.asked) == 0 {
		t.Fatal("модель не спрошена: дверь не отработала — отказ пришёл откуда-то ещё")
	}
}

// ПАРНОЕ ОТРИЦАНИЕ ВТОРОЙ ОСИ: модель о вопросе о правах не спрашивается вовсе.
//
// Утверждение «вызывающий прошёл» само по себе зеленело бы и на двери, которая
// спросила модель и получила разрешение по случайно выданному отношению.
func TestOwnDoor_ModelIsNotAskedAboutTheQuestionItself(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		&iamv1.BatchAuthorizeCheckRequest{
			Checks: []*iamv1.AuthorizeCheckRequest{{Subject: "user:" + ownerUser}},
		},
		&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.AuthorizeService/BatchCheck"},
		reached(&hit),
	)
	if err != nil || !hit {
		t.Fatalf("вопрос не дошёл до решателя: err=%v достигнут=%v", err, hit)
	}
	if len(store.asked) != 0 {
		t.Fatalf("модель спрошена об объекте вопроса о правах: %v — "+
			"объекта у него нет, и спрашивать не о чем", store.asked)
	}
}

// ПАРНОЕ ОТРИЦАНИЕ ТРЕТЬЕЙ ОСИ: назвавший область проходит дверь как прежде.
//
// Снятие двери привязано к ОТСУТСТВИЮ объекта, а не к имени RPC. Без этой пробы
// «названный проходит» зеленело бы и на двери, снятой с `BatchCheck` целиком, —
// то есть на послаблении шире своего предмета: запрос, назвавший `scope_id`,
// контракт гейтить велит («when set, the gateway gates the entire batch on this
// scope's permission»), и гейт этот обязан остаться.
func TestOwnDoor_BatchNamingItsScopeIsStillGated(t *testing.T) {
	// Выдачи нет: назвав область, вызывающий обязан получить отказ.
	refused := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, refused)(
		tenantCtx(strangerUser),
		&iamv1.BatchAuthorizeCheckRequest{
			Checks:  []*iamv1.AuthorizeCheckRequest{{Subject: "user:" + strangerUser}},
			ScopeId: victimProject,
		},
		&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.AuthorizeService/BatchCheck"},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatalf("названная область не гейтится: достигнут=%v err=%v — послабление шире предмета", hit, err)
	}
	if len(refused.asked) == 0 {
		t.Fatal("модель не спрошена: дверь отошла и на запросе, назвавшем область")
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ той же оси: с выдачей тот же запрос проходит.
	// Без него отрицание выше зеленело бы на двери, отвергающей всех и всегда.
	granted := &grantStore{allow: map[string]bool{
		"user:" + ownerUser + "|viewer|project:" + victimProject: true,
	}}
	hit = false
	if _, err := doorUnder(t, granted)(
		tenantCtx(ownerUser),
		&iamv1.BatchAuthorizeCheckRequest{
			Checks:  []*iamv1.AuthorizeCheckRequest{{Subject: "user:" + ownerUser}},
			ScopeId: victimProject,
		},
		&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.AuthorizeService/BatchCheck"},
		reached(&hit),
	); err != nil || !hit {
		t.Fatalf("выданному отказано на названной области: err=%v достигнут=%v (спрошено: %v)",
			err, hit, granted.asked)
	}
}
