// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package seed — приведение состояния при старте, идемпотентное.
//
// Точки входа, которыми пакет пользуются извне (перечень не полон — пакет несёт
// 109 объявлений верхнего уровня; названы те, о которых говорит эта шапка):
//   - `seed.LoadPermissionRegistry` — зеркало каталога прав из embed в память.
//     Реестр живёт в памяти и самодостаточен в образе: таблицы за ним нет;
//   - `seed.RunBootstrapAdmin` — выдача первому администратору кластера, когда
//     объявлен `KANAME_BOOTSTRAP_ROOT_EMAIL`;
//   - `seed.NewBootstrapReconciler` — тот же предмет петлёй, а не одним вызовом
//     (довод — шапка `bootstrap_reconciler.go`).
//
// Единой функции «выполнить весь посев» в пакете НЕТ, и это не пропуск: порядок
// шагов принадлежит композиционному корню (`cmd/kaname/serve.go`), потому что
// между ними стоят чужие условия — приведение схемы, страж паритета каталога,
// доставленные манифесты. Прежняя редакция этой шапки называла такую функцию и
// объявляла корнем `cmd/kaname/main.go`; ни того, ни другого в дереве нет.
//
// ─── ЗЕРКАЛО КАТАЛОГА ПРАВ: КТО ЕГО ЧИТАЕТ ──────────────────────────────────
//
// ЧИТАТЕЛЕЙ РЕЕСТРА В ПРОД-КОДЕ: 3
// ЧИТАТЕЛЕЙ РЕЕСТРА В ОСНАСТКЕ ПРОБ: 1
//
// Оба числа сверяет с деревом гейт `catalog_mirror_header_test.go` разбором, а не
// подстрокой: он считает узлы вызова сам. Читатели оснастки считаются отдельно —
// слив их с прод-читателями, нельзя было бы отличить «зеркало читает рантайм» от
// «зеркало читает фикстура», а это и есть предмет числа.
//
// Зеркало читается НА ПУТИ ЗАПРОСА, а не только при сборке процесса: порог
// доверия для внутренних RPC, вынесенных на край (`authzguard.ACRFloor`),
// политика вызывающего на публичном слушателе (`authzguard.PublicCallerPolicy`) и
// производитель подробности отказа (`authzguard.DenyDetailUnary`) спрашивают его
// на каждом вызове. При сборке его же читают производитель правил роли модуля и
// перепись порогов каталога для самоотчёта о посадке.
//
// Прежняя редакция объявляла обратное — «зеркало, НЕ источник истины рантайма,
// используется ТОЛЬКО интеграционными пробами» — и двумя абзацами ниже сама себе
// противоречила, объявляя lookup-API, читаемое обработчиком проверки доступа.
// Цена такой шапки не в числе неверных утверждений: это каталог ПРАВ, и читатель,
// поверивший ей, вправе снять либо чтение, либо его источник.
//
// ─── СОСТАВ КАТАЛОГА ────────────────────────────────────────────────────────
//
// ЗАПИСЕЙ КАТАЛОГА: 350
// ЗАПИСЕЙ БЕЗ ПРАВА: 0
// ЗАПИСЕЙ БЕЗ ОТНОШЕНИЯ: 53
//
// Три числа, каждое из embed-файла, каждое своим маркером и каждое сверяется тем
// же гейтом. Аннотации наполнены: записи без права нет ни одной, поэтому
// `PermissionsForRole("kacho-system.viewer")` разворачивается в права
// читающего класса, а не в пустой список. Право записывается тремя сегментами
// (`<домен>.<ресурс>.<глагол>`); 22 записи вместо права несут литерал изъятия
// `catalogderive.ExemptPermission`, и это НЕ пустое поле: изъятие объявлено, а
// не забыто.
//
// Прежняя редакция описывала обратное состояние — «бо́льшая часть записей с двумя
// пустыми полями, это ожидаемо; как только раскатка аннотаций завершится, признак
// вернёт false, проба инвертируется синхронно». Раскатка завершилась, признак
// возвращает false, и проба инвертирована с тех пор, как это произошло.
//
// ─── КОПИЯ КРАЯ: ЧЕГО ЗДЕСЬ НЕ УТВЕРЖДАЕТСЯ ─────────────────────────────────
//
// Каталог прав — ОДИН, и копия края обязана совпадать с этой байт в байт. Но
// СВЕРИТЬ их в этом дереве нечем: второй операнд уехал вместе с вынесенной
// службой, и его отсутствие сделало бы «сверено» неотличимым от «нечего было
// сверять». Поэтому здесь не утверждается ни того, что копии совпадают, ни того,
// что расхождение безопасно: свойство «служба исполняет ту же копию» стало
// предметом дерева платформы, и утверждать его отсюда было бы нечем.
//
// Прежняя редакция объявляла расхождение версий «НЕ инцидентом» и отправляла за
// подробностями в документ архитектуры, которого нет ни в одном из двух
// репозиториев. Читатель, поверивший первому, счёл бы копии независимыми.
package seed

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"
)

// PermissionEntry — one row from permission_catalog.json.
type PermissionEntry struct {
	FQN              string `json:"fqn"`
	Permission       string `json:"permission"`
	RequiredRelation string `json:"required_relation"`
	ScopeExtractor   struct {
		ObjectType       string `json:"object_type"`
		FromRequestField string `json:"from_request_field"`
	} `json:"scope_extractor"`
	RequiredACRMin string `json:"required_acr_min,omitempty"`

	// ScopeFiltered — the method is authorized over the DATA by its owning
	// service: the edge runs no per-RPC check and passes the call through, so
	// the refusal (and the machine-readable reason on it) is iam's to produce.
	// Mirrors `corelib.authz.v1.scope_filtered` in the proto. Without this
	// field parsed here iam could not even enumerate the band it is responsible
	// for authorizing.
	ScopeFiltered bool `json:"scope_filtered,omitempty"`
}

// permissionCatalogJSON — каталог прав, встроенный в образ.
//
// Файл закоммичен и встраивается напрямую, поэтому служба собирается и
// поднимается самостоятельно. Полный каталог по транзитивному набору всех
// доменных service.proto собирает конвейер края; сюда он приезжает копией.
//
// Кто читает эту копию и чего о совпадении с копией края здесь НЕ утверждается —
// шапка пакета. Прежде на этом месте стояло «зеркало, не читаемое рантаймом» и
// ссылка в несуществующий документ; предмета у обоих утверждений не было.
//
//go:embed embedded/permission_catalog.json
var permissionCatalogJSON []byte

// PermissionRegistry — реестр в памяти, загружаемый из embed при старте.
//
// Что именно у него спрашивают на пути запроса — шапка пакета, §«кто его
// читает». Здесь это не повторяется: два места об одном предмете расходятся
// молча, и ровно так разошлась прежняя редакция, объявившая читателем
// обработчик проверки доступа.
type PermissionRegistry struct {
	entries []PermissionEntry
	byFQN   map[string]PermissionEntry
	byPerm  map[string][]PermissionEntry // permission → entries (deduped по permission)
}

// LoadPermissionRegistry — embed → registry. Idempotent (the caller may
// invoke it multiple times). Guarantees deterministic ordering (entries
// sorted by FQN).
//
// Источник каталога один — встроенный `embedded/permission_catalog.json`.
// Второго пути НЕТ, и переопределяющей ручки тоже: прежняя редакция называла
// «планируемую» переменную окружения, которой в дереве не было ни одного
// вхождения. Объявленная и неисполнимая возможность хуже отсутствующей — по ней
// оператор строит план и обнаруживает отказ на стенде.
func LoadPermissionRegistry(ctx context.Context, logger *slog.Logger) (*PermissionRegistry, error) {
	if logger == nil {
		logger = slog.Default()
	}
	var entries []PermissionEntry
	if err := json.Unmarshal(permissionCatalogJSON, &entries); err != nil {
		return nil, fmt.Errorf("seed: unmarshal permission_catalog.json: %w", err)
	}

	// Deterministic ordering: entries sorted by FQN.
	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].FQN < entries[j].FQN
	})

	reg := &PermissionRegistry{
		entries: entries,
		byFQN:   make(map[string]PermissionEntry, len(entries)),
		byPerm:  make(map[string][]PermissionEntry, len(entries)),
	}
	for _, e := range entries {
		reg.byFQN[e.FQN] = e
		if e.Permission != "" {
			reg.byPerm[e.Permission] = append(reg.byPerm[e.Permission], e)
		}
	}

	logger.InfoContext(ctx, "permission catalog loaded",
		slog.Int("entries", len(entries)),
		slog.Int("distinct_permissions", len(reg.byPerm)),
	)
	return reg, nil
}

// All — all entries in deterministic order (FQN ascending).
func (r *PermissionRegistry) All() []PermissionEntry {
	out := make([]PermissionEntry, len(r.entries))
	copy(out, r.entries)
	return out
}

// LookupFQN — entry by fully-qualified RPC name.
func (r *PermissionRegistry) LookupFQN(fqn string) (PermissionEntry, bool) {
	e, ok := r.byFQN[fqn]
	return e, ok
}

// RequiredACRMin returns the catalog `required_acr_min` for the given RPC FQN
// (e.g. "kaname.cloud.iam.v1.InternalClusterService/GrantAdmin"), or "" if the
// FQN is unknown or carries no acr requirement. Satisfies the
// authzguard.ACRRequirementLookup port for the internal acr-floor.
// (The api-gateway is the runtime catalog source-of-truth on the public path;
// this in-iam lookup gates the gateway-fronted internal RPCs on :9091.)
func (r *PermissionRegistry) RequiredACRMin(fqn string) string {
	if e, ok := r.byFQN[fqn]; ok {
		return e.RequiredACRMin
	}
	return ""
}

// PermissionsForRole — права, семантически приписанные роли.
//
// `kacho-system.admin` → `["*.*.*.*"]`: маску сопоставляет рантайм, фильтр по
// каталогу здесь не нужен. `kacho-system.viewer` → права каталога, чей последний
// сегмент читающий (`read` / `list` / `get`).
//
// Маска администратора четырёхсегментная, а права каталога трёхсегментные, и это
// НЕ расхождение: сопоставление берёт последний сегмент и формы не требует.
func (r *PermissionRegistry) PermissionsForRole(roleName string) []string {
	switch roleName {
	case "kacho-system.admin":
		// Wildcard role: matches anything via Check.
		return []string{"*.*.*.*"}
	case "kacho-system.viewer":
		var perms []string
		seen := make(map[string]struct{})
		for _, e := range r.entries {
			if e.Permission == "" {
				continue
			}
			if !isReadVerb(e.Permission) {
				continue
			}
			if _, ok := seen[e.Permission]; ok {
				continue
			}
			seen[e.Permission] = struct{}{}
			perms = append(perms, e.Permission)
		}
		sort.Strings(perms)
		return perms
	default:
		return nil
	}
}

// CatalogIsUnannotated — признак ВЫРОЖДЕНИЯ каталога: true, когда право не
// названо у ≥99 % записей.
//
// Сегодня он возвращает false, и проба состава каталога утверждает именно false.
// True здесь означал бы, что каталог уехал назад в состояние, из которого
// аннотации ещё не раскатаны, — то есть регрессию конвейера, а не ожидаемое
// начальное состояние.
//
// Имя прежде говорило о «первой фазе начальной раскатки». Фазы нет, а имя
// продолжало объявлять её действующей, поэтому имя названо по предмету: признак
// меряет, названо ли право, а не то, какая фаза на дворе.
func (r *PermissionRegistry) CatalogIsUnannotated() bool {
	if len(r.entries) == 0 {
		return false
	}
	emptyCount := 0
	for _, e := range r.entries {
		if e.Permission == "" {
			emptyCount++
		}
	}
	// Порог 99 %, а не 100 %: он терпит единичные записи системных ролей,
	// если те окажутся в каталоге, и при этом отличает их от невыполненной
	// раскатки аннотаций.
	return float64(emptyCount)/float64(len(r.entries)) >= 0.99
}

func isReadVerb(perm string) bool {
	// Форма права — `<домен>.<ресурс>.<глагол>`; берётся хвост после последней
	// точки. Литерал изъятия точки не несёт и читающим не признаётся.
	idx := strings.LastIndexByte(perm, '.')
	if idx < 0 || idx == len(perm)-1 {
		return false
	}
	verb := perm[idx+1:]
	switch verb {
	case "read", "list", "get":
		return true
	default:
		return false
	}
}

// ActionForMethod — the permission name the catalog gives a method, or "" when
// the catalog has no entry for it or the entry is exempt.
//
// "" is meaningful, not merely absent: an empty action is exactly how a caller
// recognises "this method is in no catalog row", so a row that names no
// permission must not be reported as if it named one.
//
// Implements authzguard.DenyActionLookup. fqn is the full method name WITHOUT
// the leading slash — the same normalisation the edge applies before its own
// catalog lookup, so both layers key on one string.
// ScopeForMethod — the object type on which the method's permission is granted
// (project / account / cluster), or "" when the catalog names none or the row
// is exempt.
//
// "" is meaningful here too: a method whose row carries no scope extractor has
// no single object to point a caller at, and inventing one would send them to
// ask the wrong owner. Implements the second half of
// authzguard.DenyActionLookup — see its doc for why both halves must be
// functions of the METHOD alone.
func (r *PermissionRegistry) ScopeForMethod(fqn string) string {
	e, ok := r.byFQN[fqn]
	if !ok || e.Permission == catalogderive.ExemptPermission {
		return ""
	}
	return e.ScopeExtractor.ObjectType
}

func (r *PermissionRegistry) ActionForMethod(fqn string) string {
	e, ok := r.byFQN[fqn]
	if !ok || e.Permission == catalogderive.ExemptPermission {
		return ""
	}
	return e.Permission
}
