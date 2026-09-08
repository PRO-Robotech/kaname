// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicauthzcensus

// door.go — что о каждом RPC говорит карта прав СОБСТВЕННОЙ ДВЕРИ iam.
//
// # Карта берётся у двери, а не выписывается рядом
//
// Перепись обязана судить ТУ ЖЕ карту, которую звено спрашивает в проде. Своё
// чтение каталога здесь было бы вторым объявлением одного предмета: оно
// разошлось бы с дверью молча — и разошлось бы ровно там, где расхождение
// невидимо, потому что обе стороны отвечают «покрыто» на покрытом.
//
// Поэтому источник один: `authzguard.OwnDoorProtoPackages` называет пакеты, а
// `catalogderive.Derive` строит карту — тот же вызов теми же аргументами, что
// внутри `NewOwnDoor`. Сменится набор пакетов у двери — сменится и здесь, без
// правки этого файла.
//
// # Стабы линкуются ЯВНО
//
// Карта выводится из дескрипторов, влинкованных в бинарь. Перепись живёт в
// своём тестовом бинаре, куда стабы сами не попадают, поэтому они импортируются
// пустым импортом ниже. Без них `Derive` отказывает — и это правильно: пустая
// карта означала бы «дверь не покрывает ничего», то есть вердикт о дереве,
// которого нет.

import (
	"fmt"

	// Стабы служб, которые iam поднимает на своих слушателях. Пустой импорт —
	// единственный способ влинковать дескрипторы в бинарь переписи; перечень
	// обязан совпадать с authzguard.OwnDoorProtoPackages, и расхождение
	// немедленно роняет Derive, а не проходит молча.
	_ "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	_ "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/quota/v1"
	_ "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/pkg/authz/catalogderive"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
)

// doorKind — что карта прав говорит об одном RPC.
type doorKind struct {
	name     string
	evidence string
}

var (
	// doorObjectScoped — дверь спрашивает модель об объекте перед обработчиком.
	doorObjectScoped = doorKind{name: "object"}
	// doorScopeFiltered — дверь единичного вопроса НЕ задаёт: авторизация
	// принадлежит пути обслуживания и идёт по данным.
	doorScopeFiltered = doorKind{name: "filtered"}
	// doorExempt — контракт освободил RPC от пообъектного вопроса.
	doorExempt = doorKind{name: "exempt"}
)

// doorCoverage возвращает вердикт карты по каждому RPC, который дверь знает.
//
// Ключ — та же пара «служба/метод», что и у переписи: полное имя метода из
// карты («/kaname.cloud.iam.v1.ProjectService/Get») разбирается обратно, чтобы
// единица счёта осталась одна на весь пакет.
func doorCoverage() (map[RPC]doorKind, error) {
	m, err := catalogderive.Derive(authzguard.OwnDoorProtoPackages()...)
	if err != nil {
		return nil, err
	}
	if len(m) == 0 {
		return nil, fmt.Errorf("карта пуста: дверь не покрывает ни одного RPC")
	}
	out := make(map[RPC]doorKind, len(m))
	for fullMethod, entry := range m {
		rpc, ok := rpcFromFullMethod(fullMethod)
		if !ok {
			continue
		}
		switch {
		case entry.Public:
			out[rpc] = doorExempt
		case entry.ScopeFiltered:
			out[rpc] = doorScopeFiltered
		case entry.Relation != "" && entry.Extract != nil:
			k := doorObjectScoped
			k.evidence = "отношение " + entry.Relation + " на объекте запроса"
			out[rpc] = k
		default:
			// Ни отношения, ни освобождения, ни полосы данных: запись есть, а
			// двери нет. Не кладём в карту вовсе — перепись назовёт RPC находкой
			// по отсутствию записи, и это верно по существу.
			continue
		}
	}
	return out, nil
}

// rpcFromFullMethod разбирает «/пакет.Служба/Метод» в пару переписи.
func rpcFromFullMethod(fullMethod string) (RPC, bool) {
	if len(fullMethod) == 0 || fullMethod[0] != '/' {
		return RPC{}, false
	}
	rest := fullMethod[1:]
	slash := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' {
			slash = i
			break
		}
	}
	if slash < 0 || slash == len(rest)-1 {
		return RPC{}, false
	}
	svcFQN, method := rest[:slash], rest[slash+1:]
	dot := -1
	for i := len(svcFQN) - 1; i >= 0; i-- {
		if svcFQN[i] == '.' {
			dot = i
			break
		}
	}
	if dot < 0 || dot == len(svcFQN)-1 {
		return RPC{}, false
	}
	return RPC{Service: svcFQN[dot+1:], Method: method}, true
}
