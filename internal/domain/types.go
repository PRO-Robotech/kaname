// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"errors"
	"fmt"
	"regexp"

	"github.com/PRO-Robotech/kacho/pkg/validate/nameform"
)

// Self-validating domain newtypes.
//
// `Validate()` enforces regex + length rules per field. Field semantics
// (e.g. Permission-regex with wildcard semantics) are encoded directly in
// the regexes below — change them by editing the regex and DB CHECKs in
// lockstep.

type (
	// AccountID / ProjectID / ... — newtypes over string, never bare ids.
	AccountID        string
	ProjectID        string
	UserID           string
	ServiceAccountID string
	GroupID          string
	RoleID           string
	AccessBindingID  string
	OperationID      string

	// SubjectID — opaque id (user, service_account, or group). The paired
	// SubjectType defines the semantics.
	SubjectID string

	// Names — every newtype has its own regex.
	AccountName    string
	ProjectName    string
	GroupName      string
	RoleName       string
	SvcAccountName string

	// OAuthClientName — человекочитаемое имя токена (SA-key / user-token).
	// Судится единственной формой имени дерева, как и остальные имена iam.
	//
	// Пустая строка остаётся законным ВХОДОМ выпуска и означает «назови сам»:
	// до записи её заменяет имя, производное от идентификатора
	// (`validate.NameOrDefault` в use-case). Здесь пустое уже не проходит —
	// эта проверка судит то, что БУДЕТ ЗАПИСАНО, а записи с пустым именем не
	// бывает.
	OAuthClientName string

	DisplayName     string
	Email           string
	ExternalSubject string // OIDC sub
	Description     string

	LabelKey string
	LabelVal string
	// Labels — key→val map.
	Labels map[LabelKey]LabelVal

	Permission  string
	Permissions []Permission

	// SubjectType — enum: user|service_account|group.
	SubjectType string
	// ResourceType — ЯКОРЬ ОБЛАСТИ привязки: один из трёх ярусов иерархии
	// (`cluster`/`account`/`project`). Вокабуляр объявлен ОДИН раз —
	// `scopeAnchorTiers` в access_binding_scope.go, — и `Validate()` судит по
	// нему. Пообъектный тип якорем не бывает: он живёт на оси `target` (F8).
	ResourceType string
)

// SubjectType values.
const (
	SubjectTypeUser           SubjectType = "user"
	SubjectTypeServiceAccount SubjectType = "service_account"
	SubjectTypeGroup          SubjectType = "group"
)

// Regex / limits — centralised so domain.Validate and the DB CHECKs agree.
//
// Формы имени ресурса здесь БОЛЬШЕ НЕТ: она объявлена один раз на всё дерево
// (`pkg/validate/nameform`), и iam читает то же объявление (#1279). Прежде
// здесь стояла своя — `^[a-z][-a-z0-9]{2,62}$`, — и расходилась с каноном в
// обе стороны: была УЖЕ него по началу имени (буква вместо буквы-или-цифры) и
// по длине (от 3 вместо 1), и ШИРЕ него по хвосту (допускала имя, кончающееся
// дефисом). Гейт единственности формы её не видел by construction: он ловит
// байт-идентичную копию канона, а независимо написанную регулярку — нет, и
// свою слепую зону называет сам.
//
// Идентификатор роли остаётся своим и формой имени НЕ судится: `roles/vpc.admin`
// — то, на что ссылаются привязки, а не косметическая метка (записанное решение
// владельца, #715).
// CustomRoleNameForm — форма имени ПОЛЬЗОВАТЕЛЬСКОЙ роли. Зеркало ограничения
// таблицы `roles_custom_name_check` (`0056_role_definition_tier.sql`,
// применённая миграция, ban #5).
const CustomRoleNameForm = `^[a-z][a-z0-9_]{0,40}$`

// SystemRoleNameForm — форма имени СИСТЕМНОЙ роли. Зеркало ограничения таблицы
// `roles_system_name_check` того же файла: нижний регистр, дефис в первом
// сегменте, подчёркивание в сегментах после первого, не более трёх сегментов.
//
// Здесь стояло `^roles/[a-z]+\.[a-z]+$`, и этой форме не удовлетворяла НИ ОДНА
// живая строка: предикат `grep -c "'roles/"` по каталогу миграций даёт ноль во
// всех файлах, а имена продукта записаны как `vpc.network.admin`. То есть
// `Role.Validate()` отвергал каждую системную роль платформы — и покраснеть это
// не могло, потому что системную роль в Go до задачи #1824 никто не строил.
//
// Правило пережило свой предмет молча; сегодня оно зеркалит ограничение,
// которое действительно судит записываемую строку.
const SystemRoleNameForm = `^[a-z][-a-z0-9]*(\.[a-z][a-z0-9_]*){0,2}$`

var (
	roleNameCustomRe    = regexp.MustCompile(CustomRoleNameForm)
	roleNameSystemRe    = regexp.MustCompile(SystemRoleNameForm)
	emailRe             = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
	labelKeyRe          = regexp.MustCompile(`^[a-z][-_./@a-z0-9]{0,62}$`)
	permissionElementRe = regexp.MustCompile(`^(\*|[a-z][a-z0-9-]*)\.(\*|[a-z][a-zA-Z0-9_-]*)\.(\*|[a-zA-Z0-9_-]+)\.(\*|[a-z][a-zA-Z0-9_-]*)$`)
)

// Validate — per newtype.

func (n AccountName) Validate() error    { return validateResourceName("name", string(n)) }
func (n ProjectName) Validate() error    { return validateResourceName("name", string(n)) }
func (n GroupName) Validate() error      { return validateResourceName("name", string(n)) }
func (n SvcAccountName) Validate() error { return validateResourceName("name", string(n)) }

// Validate — OAuthClientName судится той же формой, что и остальные имена.
//
// Прежде здесь стояла ветка «пустое допустимо», и она была единственным местом
// iam, где имя доживало до записи пустым. Пустое имя — не «имя, которого нет»,
// а ресурс, который не ищется, не отличается в списке и показывается прочерком.
// Ветка снята: пустое заменяется умолчанием ДО записи, в use-case выпуска.
func (n OAuthClientName) Validate() error { return validateResourceName("name", string(n)) }

// Validate — форма имени роли БЕЗ различения яруса: годна любая из двух.
// Оставлена для вызывающих, которым ярус неизвестен; сама сущность судится
// `ValidateAtTier`, потому что ограничений в таблице ДВА и каждое условлено
// вычисляемым `is_system`.
func (n RoleName) Validate() error {
	if roleNameCustomRe.MatchString(string(n)) || roleNameSystemRe.MatchString(string(n)) {
		return nil
	}
	return fmt.Errorf("Illegal argument name: must match %s (custom) or %s (system)",
		CustomRoleNameForm, SystemRoleNameForm)
}

// ValidateAtTier — форма имени роли ПО ЯРУСУ, зеркало двух ограничений таблицы.
//
// Различать обязательно: в базе стоят ДВА условленных ограничения
// (`roles_custom_name_check` под `is_system OR …` и `roles_system_name_check`
// под `NOT is_system OR …`), и правило, не различающее ярусов, расходится с
// ними в обе стороны сразу — принимает точечное имя у пользовательской роли и
// отвергает его у системной. Отказ тогда приезжает от базы (SQLSTATE 23514) без
// имени поля и без координаты.
func (n RoleName) ValidateAtTier(isSystem bool) error {
	if isSystem {
		if roleNameSystemRe.MatchString(string(n)) {
			return nil
		}
		return fmt.Errorf("Illegal argument name: system role name must match %s "+
			"(constraint roles_system_name_check)", SystemRoleNameForm)
	}
	if roleNameCustomRe.MatchString(string(n)) {
		return nil
	}
	return fmt.Errorf("Illegal argument name: custom role name must match %s "+
		"(constraint roles_custom_name_check)", CustomRoleNameForm)
}

func (d DisplayName) Validate() error {
	if len(d) == 0 || len(d) > 128 {
		return fmt.Errorf("Illegal argument display_name: length must be 1..128")
	}
	return nil
}

func (e Email) Validate() error {
	if len(e) == 0 || len(e) > 254 || !emailRe.MatchString(string(e)) {
		return fmt.Errorf("Illegal argument email: invalid format")
	}
	return nil
}

func (s ExternalSubject) Validate() error {
	if len(s) == 0 || len(s) > 256 {
		return fmt.Errorf("Illegal argument external_id: length must be 1..256")
	}
	return nil
}

func (d Description) Validate() error {
	if len(d) > 256 {
		return fmt.Errorf("Illegal argument description: length must be <=256")
	}
	return nil
}

func (k LabelKey) Validate() error {
	if !labelKeyRe.MatchString(string(k)) {
		return fmt.Errorf("Illegal argument label key: invalid format")
	}
	return nil
}

func (v LabelVal) Validate() error {
	if len(v) > 63 {
		return fmt.Errorf("Illegal argument label value: length must be <=63")
	}
	return nil
}

// Validate — Labels: cardinality ≤64; each pair via LabelKey/LabelVal.
func (l Labels) Validate() error {
	if len(l) > 64 {
		return fmt.Errorf("Illegal argument labels: cardinality must be <=64")
	}
	for k, v := range l {
		if err := k.Validate(); err != nil {
			return err
		}
		if err := v.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate — Permission: one element with wildcard semantics.
func (p Permission) Validate() error {
	if !permissionElementRe.MatchString(string(p)) {
		return fmt.Errorf("Illegal argument permissions: invalid format")
	}
	return nil
}

// Validate — Permissions: cardinality 1..1024; each — Permission.Validate.
//
// The ≥1 lower bound applies to the LEGACY permissions-only role path (a role
// authored as a bare permission set must carry at least one). Cap raised 256→1024
// in lockstep with the DB CHECK iam_permissions_valid (migration 0025) and the
// proto (size) bound, so the compiled-permission set derived from a role's rules
// (CompileRules, ≤MaxCompiledPermissions) always passes domain + DB validation
// (acceptance R-12 / A-12). A rules-role uses ValidateCompiled (no lower bound) —
// a label-only role compiles to an EMPTY set by design (ARM_LABELS excluded).
func (p Permissions) Validate() error {
	if len(p) == 0 {
		return fmt.Errorf("Illegal argument permissions: must contain at least 1")
	}
	return p.validateGrammarAndCap()
}

// ValidateCompiled validates the INTERNAL compiled-permission projection of a
// rules-role: the 4-segment grammar parity + the ≤1024 cap, but WITHOUT the ≥1
// lower bound. A rules-role whose rules are ALL ARM_LABELS compiles to an EMPTY
// permission set (matchLabels is not compiled — R-7 / fix #8), which is valid; the
// authority lives in rules[], not permissions[]. Only the legacy permissions-only
// path keeps the ≥1 floor (Validate). Acceptance A-10 (label-only positive).
func (p Permissions) ValidateCompiled() error {
	return p.validateGrammarAndCap()
}

// validateGrammarAndCap — shared 4-seg grammar + ≤1024 cap check (no lower bound).
func (p Permissions) validateGrammarAndCap() error {
	if len(p) > MaxCompiledPermissions {
		return fmt.Errorf("Illegal argument permissions: cardinality must be <=%d", MaxCompiledPermissions)
	}
	for _, perm := range p {
		if err := perm.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// Validate — SubjectType — enum check.
func (s SubjectType) Validate() error {
	switch s {
	case SubjectTypeUser, SubjectTypeServiceAccount, SubjectTypeGroup:
		return nil
	default:
		return fmt.Errorf("Illegal argument subject_type %q (allowed: user|service_account|group)", string(s))
	}
}

// Validate — ResourceType — ярус иерархии, и только он.
//
// Судит ЕДИНСТВЕННОЕ объявление вокабуляра якоря (`scopeAnchorTiers`), а не своя
// копия: копия здесь была, разошлась с ним на 20 записей и принимала пообъектные
// типы, которых не производит ни один путь записи. Разбор — у самого объявления.
func (r ResourceType) Validate() error {
	if IsScopeAnchorKind(string(r)) {
		return nil
	}
	return fmt.Errorf("Illegal argument resource_type %q", string(r))
}

// validateResourceName — единственная проверка формы имени ресурса iam.
//
// Делегирует ЕДИНСТВЕННОМУ объявлению формы (`pkg/validate/nameform`), а не
// повторяет его: два места об одном предмете расходятся молча — так и разошлись
// прежние четыре валидатора дерева (#715) и эта, пятая, форма iam (#1279).
//
// Пакет формы намеренно БЕЗ транспорта, поэтому его вправе читать слой домена,
// которому grpc запрещён (`architecture.md`): в Go зависимость пакетная, и
// импорт валидаторов ради одной строки затянул бы сюда grpc целиком.
//
// Текст отказа называет ДЕЙСТВУЮЩУЮ форму, взяв её из того же объявления:
// выписанная копия пережила бы смену канона и посылала бы арендатора чинить имя
// по несуществующему правилу.
func validateResourceName(field, v string) error {
	if !nameform.OK(v) {
		return fmt.Errorf("Illegal argument %s: must match %s", field, nameform.Form)
	}
	return nil
}

// ErrEmpty — sentinel for empty required fields (used in NULL-validation
// before repo).
var ErrEmpty = errors.New("required field is empty")
