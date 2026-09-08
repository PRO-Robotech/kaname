// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package authzmap maps a role's permissions[] to FGA relations and owns the
// closed (module,resource)→fga_object_type table. Adapter-free (stdlib only):
// consumed from AccessBinding tuple-emission paths without coupling to
// internal/repo or internal/clients.
//
// permissions_to_relations.go — single mapper from a role's permissions[] to
// a deduplicated set of FGA relations.
//
// Replaces the name-based name→relation collapse that lived in
// `internal/apps/kaname/api/access_binding/tuples.go::roleNameToRelation`.
//
// Strategy (conservative — granular FGA model is out of scope for this mapper):
//
//  1. nil / empty permissions       → []Relation{"viewer"} (least privilege).
//
//  2. Group permissions by verb-class (read-only / write / admin), pick the
//     STRONGEST tier present:
//
//     read-only verbs : get | list | view | watch | describe → "viewer"
//     write verbs     : create | update | delete | write | patch | put → "editor"
//     admin / wildcard: admin | * | manage                            → "admin"
//
// # Это НЕ пер-RPC карта прав, и вывести её из аннотаций нельзя (замерено 2026-08-10)
//
// Файл дважды принимали за «рукописную карту прав iam», которую осталось
// перевести на вывод из аннотаций дескрипторов (`pkg/authz/catalogderive`), как
// сделано у шести сервисов. Это ошибка опознания, и стоит она дорого: перевод
// «по аналогии» подменил бы один словарь другим и поехал бы молча — оба ведь
// выглядят как `модуль.ресурс.глагол`.
//
// Здесь отображается РОЛЬ (её `permissions[]`) в ярус отношения FGA при эмиссии
// кортежей AccessBinding. Пер-RPC карта отвечает на другой вопрос — «что
// проверить перед ЭТИМ вызовом» — и у iam её нет вовсе: iam не перепроверяет
// конечного пользователя на своих слушателях, он и есть точка решения
// (`internal/authzguard/interceptor.go`).
//
// Предикаты, которыми это установлено, — повторяйте их, а не верьте строке:
//
//   - перепись объявлений типа карты прав из `pkg/authz` по не-тестовым файлам
//     под `services/` даёт 5 файлов в 4 сервисах (vpc·compute·nlb·registry); в
//     iam — НОЛЬ.
//
//     ОСТОРОЖНО, предикат ТЕКСТОВЫЙ: он считает и упоминания в комментариях.
//     Проверено на себе — первая редакция этого абзаца выписала имя типа
//     дословно, и перепись немедленно выросла до 6 файлов в 5 сервисах, показав
//     «карту у iam» ровно там, где абзац утверждал её отсутствие. Поэтому имя
//     здесь названо описательно, а считать надо по ИСПОЛНЯЕМОЙ части (разбор
//     AST либо `grep -v` по этому файлу);
//
//   - словари не пересекаются ВООБЩЕ: у аннотаций 253 уникальных строки
//     разрешения (`iam.cluster_admins.grant`, `vpc.networks.get` — третий сегмент
//     это ГЛАГОЛ RPC), у ролей 55 (`compute.disk.edit` — третий сегмент это ЯРУС),
//     пересечение — 0. Вывести отсюда нечего: аннотации не содержат ни одной
//     строки, которую этот маппер принимает на вход.
//
// Отсюда правило для следующего захода: «у iam осталась рукописная карта» —
// утверждение о пер-RPC карте прав, а не об этом файле. Если однажды iam заведёт
// пер-RPC карту, она будет выведена из аннотаций и будет жить рядом с его
// рубежами — этот маппер останется на месте, потому что его предмет другой.
package authzmap

import "strings"

// Relation — typed string for FGA relation names.
type Relation string

// PermissionsToRelations derives FGA relations from a role's permission list.
//
// See package-level doc-comment for the strategy.
//
// Output is deduplicated, never nil (always at least one relation — viewer
// fallback for the empty case).
func PermissionsToRelations(permissions []string) []Relation {
	if len(permissions) == 0 {
		return []Relation{"viewer"}
	}

	// Tier mapping. Pick the STRONGEST tier present in the permission set
	// (admin > editor > viewer). The strongest tier supersedes the others
	// because the FGA model declares `admin` ⇒ `editor` ⇒ `viewer` via
	// computed relations — emitting all three would just be redundant
	// bookkeeping.
	hasAdmin, hasWrite, hasRead := false, false, false
	for _, p := range permissions {
		switch verbClass(p) {
		case classAdmin:
			hasAdmin = true
		case classWrite:
			hasWrite = true
		case classRead:
			hasRead = true
		}
	}
	switch {
	case hasAdmin:
		return []Relation{"admin"}
	case hasWrite:
		return []Relation{"editor"}
	case hasRead:
		return []Relation{"viewer"}
	default:
		// unrecognised permission shape — least privilege.
		return []Relation{"viewer"}
	}
}

// PermissionsCoveringType keeps only the permissions that actually name the given
// FGA object type, resolved over the closed (module, resource) table.
//
// # Why the caller needs this
//
// PermissionsToRelations answers "how strong is this role?" and deliberately
// ignores the module and resource segments — the tier comes from the verb. That
// is the right answer for the question it asks, and the wrong one for the
// question a tuple builder asks, which is "what may this role grant ON THIS
// OBJECT?". Applied to a hierarchy anchor the difference is not cosmetic:
// `vpc.network.*.*` is a verb-position wildcard, so the whole role reads as the
// admin tier, and `account:<A>#admin` accepts direct subjects and derives
// `project.super_admin: admin from account`, which every leaf type reads as
// `super_admin from project`. A role that only ever named vpc networks would
// hand over every resource in the account.
//
// The rules path never had the gap — a rule carries (module, resource) and the
// anchor arm matches only when it covers the anchor's own type. This restores the
// same discipline on the legacy permissions-only path.
//
// # Matching
//
// A permission is `module.resource.<group>.<verb>` (the seeded form, e.g.
// "vpc.network.*.*"); only the first two segments are read here. A `*` in either
// position broadens the pattern, and the closed table decides what it expands to
// — never a substring or prefix guess, so `iam.*` covers the account because
// "iam.account" is in the table, not because the strings look alike.
//
// Returns nil when nothing covers the type. Callers must treat that as "grants
// nothing here" and NOT hand the empty slice to PermissionsToRelations, whose
// empty-input contract is the least-privilege viewer fallback — that fallback is
// for a role with no permissions at all, and reusing it here would turn "grants
// nothing on this anchor" into "grants read on this anchor".
func PermissionsCoveringType(permissions []string, fgaType string) []string {
	if fgaType == "" {
		return nil
	}
	var out []string
	for _, p := range permissions {
		if permissionCoversType(p, fgaType) {
			out = append(out, p)
		}
	}
	return out
}

// permissionCoversType — does one permission's (module, resource) reach fgaType?
func permissionCoversType(permission, fgaType string) bool {
	seg := strings.Split(permission, ".")
	if len(seg) < 2 {
		return false // not a module.resource-shaped token — covers nothing
	}
	module, resource := seg[0], seg[1]

	switch {
	case module == wildcardSegment && resource == wildcardSegment:
		return true
	case module == wildcardSegment || resource == wildcardSegment:
		// One side is concrete: the pattern covers fgaType iff SOME entry of the
		// closed table matches the concrete side and maps to fgaType.
		for dotted, typ := range objectTypes {
			if typ != fgaType {
				continue
			}
			m, r, ok := SplitObjectType(dotted)
			if !ok {
				continue
			}
			if (module == wildcardSegment || module == m) &&
				(resource == wildcardSegment || resource == r) {
				return true
			}
		}
		return false
	default:
		typ, ok := ObjectType(module, resource)
		return ok && typ == fgaType
	}
}

// wildcardSegment — the `*` segment of a permission token.
const wildcardSegment = "*"

type verbClassKind int

const (
	classUnknown verbClassKind = iota
	classRead
	classWrite
	classAdmin
)

// verbClass — classify a permission string by its trailing verb.
//
// Tier is determined by the VERB (last `.`-segment), not by whether the module
// or resource segment is wildcarded:
//
//   - `vpc.networks.get`       → read   (specific resource, read verb)
//   - `*.*.read`               → read   (global read-only — viewer-tier)
//   - `vpc.networks.create`    → write  (specific resource, write verb)
//   - `vpc.networks.*`         → admin  (verb-position wildcard = full CRUD)
//   - `vpc.*.*`                → admin  (verb-position wildcard, broader scope)
//   - `*.*.*`                  → admin  (global all-verbs = admin-grade)
//   - `iam.accessBindings.admin` → admin
//
// Rule: wildcard ONLY at the verb position escalates to admin; wildcards at
// module/resource positions just broaden scope but keep the verb's tier.
func verbClass(perm string) verbClassKind {
	if perm == "" {
		return classUnknown
	}
	verb := perm
	if i := strings.LastIndexByte(verb, '.'); i >= 0 {
		verb = verb[i+1:]
	}
	verb = strings.ToLower(verb)
	if verb == "*" {
		return classAdmin
	}
	switch verb {
	case "get", "list", "view", "watch", "describe", "viewer", "read",
		// Read-style domain verbs introduced by kacho-nlb.
		// Aliased lowercase: gettargetstates / listoperations.
		"gettargetstates", "listoperations":
		return classRead
	case "create", "update", "delete", "write", "patch", "put", "editor", "edit",
		// Write-style domain verbs (kacho-nlb action RPCs + Move). All mutate
		// state, so they belong in the editor tier.
		"start", "stop", "move",
		"addtargets", "removetargets",
		"attachtargetgroup", "detachtargetgroup",
		"enablezones", "disablezones",
		"addlistener", "removelistener":
		return classWrite
	case "admin", "manage":
		return classAdmin
	}
	return classUnknown
}
