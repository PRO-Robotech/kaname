// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	authzv1 "github.com/PRO-Robotech/corelib/api/corelib/authz/v1"
	"github.com/PRO-Robotech/corelib/authz"
	"github.com/PRO-Robotech/corelib/authz/catalogderive"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/bootstrap_token"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/child_registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/clusterpublic"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/identityquota"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/interactive_client"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/membership"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/module"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/permission_catalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/resource_metadata"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/sa_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/session_revocations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user_tokens"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

type catalogGrantVerb struct {
	module, resource, verb string
}

func (v catalogGrantVerb) String() string {
	return v.module + "." + v.resource + "." + v.verb
}

func (v catalogGrantVerb) complete() bool {
	return v.module != "" && v.resource != "" && v.verb != ""
}

type catalogGrantDeclaration struct {
	coordinate          catalogGrantVerb
	effect              grantpolicy.CatalogEffect
	direction           grantpolicy.CatalogDirection
	requiresCheck       bool
	withdrawalAuthority grantpolicy.WithdrawalAuthority
	fullMethod          string
	catalogCoordinate   catalogGrantVerb
	dispatch            authz.RPCEntry
	contract            check.ContractMethod
	dispatchReason      string
}

type catalogGrantCensus struct {
	examined, changing int
	findings           []string
}

// judgeCatalogGrantDeclarations сверяет весь переданный каталог с декларациями.
// Тип эффекта и наличие проверки поступают от владельцев исполняемых операций.
// Для глагола с несколькими вариантами requiresCheck означает, что проверка
// обязательна во всех вариантах, меняющих держателей или ярус.
func judgeCatalogGrantDeclarations(verbs []catalogGrantVerb, declarations []catalogGrantDeclaration) catalogGrantCensus {
	census := catalogGrantCensus{}
	add := func(v catalogGrantVerb, finding string) {
		census.findings = append(census.findings, fmt.Sprintf("%s: %s", v, finding))
	}
	byVerb := make(map[catalogGrantVerb]catalogGrantDeclaration, len(declarations))
	for _, declaration := range declarations {
		if !declaration.coordinate.complete() {
			add(declaration.coordinate, "неполная координата декларации")
			continue
		}
		if _, duplicate := byVerb[declaration.coordinate]; duplicate {
			add(declaration.coordinate, "повторная декларация эффекта")
			continue
		}
		byVerb[declaration.coordinate] = declaration
	}
	if len(verbs) == 0 {
		census.findings = append(census.findings, "каталог не содержит ни одного глагола для проверки")
	}
	seen := make(map[catalogGrantVerb]bool, len(verbs))
	for _, verb := range verbs {
		if !verb.complete() {
			add(verb, "неполная координата каталога")
			continue
		}
		if seen[verb] {
			add(verb, "повторная координата каталога")
			continue
		}
		seen[verb] = true
		census.examined++
		declaration := byVerb[verb]
		validDirection := declaration.direction == grantpolicy.UnspecifiedDirection ||
			declaration.direction == grantpolicy.WithdrawsAccess || declaration.direction == grantpolicy.ExpandsOrMixesAccess
		if !validDirection {
			add(verb, "неизвестное направление изменения доступа")
		}
		withdrawal := validCatalogWithdrawal(declaration)
		if declaration.withdrawalAuthority != grantpolicy.NoWithdrawalAuthority && !withdrawal {
			add(verb, "полномочие чистого отзыва не подтверждено для RPC, координаты, эффекта и действующей авторизации")
		}
		switch declaration.effect {
		case grantpolicy.UnchangedAccess, grantpolicy.AuthorityInput:
			if declaration.direction != grantpolicy.UnspecifiedDirection {
				add(verb, "направление изменения не соответствует объявленному эффекту")
			}
		case grantpolicy.ChangesHolders, grantpolicy.ChangesTier, grantpolicy.ChangesHoldersAndTier:
			// Чистый отзыв остаётся в M: полномочие меняет основание допуска,
			// но не факт изменения держателей или яруса.
			census.changing++
			if !catalogGrantCheckValid(declaration) && !withdrawal {
				add(verb, "нет обязательной проверки права выдавать или подтверждённого полномочия чистого отзыва")
			}
		default:
			add(verb, "эффект на держателей или ярус не объявлен")
		}
	}
	for _, declaration := range declarations {
		if declaration.coordinate.complete() && !seen[declaration.coordinate] {
			add(declaration.coordinate, "декларация не относится ни к одному глаголу каталога")
		}
	}
	return census
}

// validCatalogWithdrawal не выводит исключение из имени глагола или направления.
// Координата независимо пришла из сверенного каталога, dispatch — из тех же
// дескрипторов, что использует OwnDoor на обоих слушателях. Поведение обработчика
// держат ESC §2 п.4, ESC-24, GD-30/31, CE-01/02, SAC-12/16, CVR-01–08,
// Ф7-25/27, IC-SECRET-10, KN-FRV-14 и гейт delegated_path_callers_test.go.
func validCatalogWithdrawal(d catalogGrantDeclaration) bool {
	if d.direction != grantpolicy.WithdrawsAccess || !d.coordinate.complete() ||
		d.coordinate != d.catalogCoordinate || d.fullMethod != "/"+d.contract.FullMethod || d.dispatch.ScopeFiltered {
		return false
	}
	switch d.withdrawalAuthority {
	case grantpolicy.TargetGroupMembershipWithdrawal:
		return d.fullMethod == iamv1.GroupService_RemoveMember_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "group", "removemember"}) &&
			d.effect == grantpolicy.ChangesHolders &&
			validScopedCatalogWithdrawal(d, "v_update", "iam_group", "group_id", map[string]any{
				"grp00000000000000001": &iamv1.RemoveGroupMemberRequest{GroupId: "grp00000000000000001"},
				"grp00000000000000002": &iamv1.RemoveGroupMemberRequest{GroupId: "grp00000000000000002"},
			})
	case grantpolicy.TargetRoleDeletionWithdrawal:
		return d.fullMethod == iamv1.RoleService_Delete_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "role", "delete"}) &&
			d.effect == grantpolicy.ChangesHoldersAndTier &&
			validScopedCatalogWithdrawal(d, "v_delete", "iam_role", "role_id", map[string]any{
				"rol00000000000000001": &iamv1.DeleteRoleRequest{RoleId: "rol00000000000000001"},
				"rol00000000000000002": &iamv1.DeleteRoleRequest{RoleId: "rol00000000000000002"},
			})
	case grantpolicy.TargetGroupDeletionWithdrawal:
		return d.fullMethod == iamv1.GroupService_Delete_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "group", "delete"}) &&
			d.effect == grantpolicy.ChangesHoldersAndTier &&
			validScopedCatalogWithdrawal(d, "v_delete", "iam_group", "group_id", map[string]any{
				"grp00000000000000001": &iamv1.DeleteGroupRequest{GroupId: "grp00000000000000001"},
				"grp00000000000000002": &iamv1.DeleteGroupRequest{GroupId: "grp00000000000000002"},
			})
	case grantpolicy.TargetServiceAccountDeletionWithdrawal:
		return d.fullMethod == iamv1.ServiceAccountService_Delete_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "serviceAccount", "delete"}) &&
			d.effect == grantpolicy.ChangesHoldersAndTier &&
			validScopedCatalogWithdrawal(d, "v_delete", "iam_service_account", "service_account_id", map[string]any{
				"sva00000000000000001": &iamv1.DeleteServiceAccountRequest{ServiceAccountId: "sva00000000000000001"},
				"sva00000000000000002": &iamv1.DeleteServiceAccountRequest{ServiceAccountId: "sva00000000000000002"},
			})
	case grantpolicy.TargetServiceAccountDisableWithdrawal:
		return d.fullMethod == iamv1.ServiceAccountService_Disable_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "serviceAccount", "disable"}) &&
			d.effect == grantpolicy.ChangesHolders &&
			validScopedCatalogWithdrawal(d, "v_update", "iam_service_account", "service_account_id", map[string]any{
				"sva00000000000000001": &iamv1.DisableServiceAccountRequest{ServiceAccountId: "sva00000000000000001"},
				"sva00000000000000002": &iamv1.DisableServiceAccountRequest{ServiceAccountId: "sva00000000000000002"},
			})
	case grantpolicy.TargetUserCredentialWithdrawal:
		if d.effect != grantpolicy.ChangesHolders {
			return false
		}
		switch d.fullMethod {
		case iamv1.UserTokenService_Revoke_FullMethodName:
			return d.coordinate == (catalogGrantVerb{"iam", "userToken", "revoke"}) &&
				validScopedCatalogWithdrawal(d, "token_issuer", "iam_user", "user_id", map[string]any{
					"usr00000000000000001": &iamv1.RevokeUserTokenRequest{UserId: "usr00000000000000001"},
					"usr00000000000000002": &iamv1.RevokeUserTokenRequest{UserId: "usr00000000000000002"},
				})
		case iamv1.AccessKeyService_Revoke_FullMethodName:
			return d.coordinate == (catalogGrantVerb{"iam", "accessKey", "revoke"}) &&
				validScopedCatalogWithdrawal(d, "token_issuer", "iam_user", "user_id", map[string]any{
					"usr00000000000000001": &iamv1.RevokeAccessKeyRequest{UserId: "usr00000000000000001"},
					"usr00000000000000002": &iamv1.RevokeAccessKeyRequest{UserId: "usr00000000000000002"},
				})
		default:
			return false
		}
	case grantpolicy.TargetServiceAccountKeyWithdrawal:
		return d.fullMethod == iamv1.SAKeyService_Revoke_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "sAKey", "revoke"}) &&
			d.effect == grantpolicy.ChangesHolders &&
			validScopedCatalogWithdrawal(d, "v_update", "iam_service_account", "service_account_id", map[string]any{
				"sva00000000000000001": &iamv1.RevokeSAKeyRequest{ServiceAccountId: "sva00000000000000001"},
				"sva00000000000000002": &iamv1.RevokeSAKeyRequest{ServiceAccountId: "sva00000000000000002"},
			})
	case grantpolicy.TargetUserIdentityWithdrawal:
		return d.fullMethod == iamv1.UserService_Delete_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "user", "delete"}) &&
			d.effect == grantpolicy.ChangesHoldersAndTier &&
			validScopedCatalogWithdrawal(d, "identity_remover", "iam_user", "user_id", map[string]any{
				"usr00000000000000001": &iamv1.DeleteUserRequest{UserId: "usr00000000000000001"},
				"usr00000000000000002": &iamv1.DeleteUserRequest{UserId: "usr00000000000000002"},
			})
	case grantpolicy.TargetAccountMembershipWithdrawal:
		return d.fullMethod == iamv1.UserService_RemoveFromAccount_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "user", "removefromaccount"}) &&
			d.effect == grantpolicy.ChangesHoldersAndTier &&
			validScopedCatalogWithdrawal(d, "member_remover", "account", "account_id", map[string]any{
				"acc00000000000000001": &iamv1.RemoveUserFromAccountRequest{UserId: "usr00000000000000002", AccountId: "acc00000000000000001"},
				"acc00000000000000002": &iamv1.RemoveUserFromAccountRequest{UserId: "usr00000000000000001", AccountId: "acc00000000000000002"},
			})
	case grantpolicy.TargetUserBlockWithdrawal:
		return d.fullMethod == iamv1.UserService_Block_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "user", "block"}) &&
			d.effect == grantpolicy.ChangesHolders &&
			validScopedCatalogWithdrawal(d, "identity_suspender", "iam_user", "user_id", map[string]any{
				"usr00000000000000001": &iamv1.BlockUserRequest{UserId: "usr00000000000000001"},
				"usr00000000000000002": &iamv1.BlockUserRequest{UserId: "usr00000000000000002"},
			})
	case grantpolicy.TargetUserAccessKeysWithdrawal:
		return d.fullMethod == iamv1.UserService_ResetAccessKeys_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "user", "resetaccesskeys"}) &&
			d.effect == grantpolicy.ChangesHolders &&
			validScopedCatalogWithdrawal(d, "identity_suspender", "iam_user", "user_id", map[string]any{
				"usr00000000000000001": &iamv1.ResetAccessKeysRequest{UserId: "usr00000000000000001"},
				"usr00000000000000002": &iamv1.ResetAccessKeysRequest{UserId: "usr00000000000000002"},
			})
	case grantpolicy.TargetAccountDeletionWithdrawal:
		return d.fullMethod == iamv1.AccountService_Delete_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "account", "delete"}) &&
			d.effect == grantpolicy.ChangesHoldersAndTier &&
			validScopedCatalogWithdrawal(d, "v_delete", "account", "account_id", map[string]any{
				"acc00000000000000001": &iamv1.DeleteAccountRequest{AccountId: "acc00000000000000001"},
				"acc00000000000000002": &iamv1.DeleteAccountRequest{AccountId: "acc00000000000000002"},
			})
	case grantpolicy.TargetProjectDeletionWithdrawal:
		return d.fullMethod == iamv1.ProjectService_Delete_FullMethodName &&
			d.coordinate == (catalogGrantVerb{"iam", "project", "delete"}) &&
			d.effect == grantpolicy.ChangesHoldersAndTier &&
			validScopedCatalogWithdrawal(d, "v_delete", "project", "project_id", map[string]any{
				"prj00000000000000001": &iamv1.DeleteProjectRequest{ProjectId: "prj00000000000000001"},
				"prj00000000000000002": &iamv1.DeleteProjectRequest{ProjectId: "prj00000000000000002"},
			})
	case grantpolicy.ActiveDelegationBindingWithdrawal:
		return (d.fullMethod == iamv1.AccessBindingService_Delete_FullMethodName ||
			d.fullMethod == iamv1.AccessBindingService_Revoke_FullMethodName) &&
			d.effect == grantpolicy.ChangesHoldersAndTier && d.dispatch.Public &&
			d.contract.Annotations.Permission == catalogderive.ExemptPermission && d.dispatchReason == "HANDLER_DECIDES" &&
			d.dispatch.Relation == "" && d.dispatch.Extract == nil
	default:
		return false
	}
}

// Внутренний слушатель не вызывает OwnDoor. Для этих RPC обработчик
// подтверждает system_admin сам, а аннотации задают тот же контракт на краю.
func catalogGrantCheckValid(d catalogGrantDeclaration) bool {
	if !d.requiresCheck {
		return false
	}
	var action string
	var request any
	direction := grantpolicy.ExpandsOrMixesAccess
	switch d.fullMethod {
	case iamv1.InternalInteractiveClientService_Create_FullMethodName:
		action, request = "create", &iamv1.CreateInteractiveClientRequest{}
	case iamv1.InternalInteractiveClientService_Update_FullMethodName:
		action, request = "update", &iamv1.UpdateInteractiveClientRequest{}
	case iamv1.InternalInteractiveClientService_Delete_FullMethodName:
		action, request = "delete", &iamv1.DeleteInteractiveClientRequest{}
		direction = grantpolicy.WithdrawsAccess
	default:
		return d.coordinate.module != "iam" || d.coordinate.resource != "interactiveClient"
	}
	a := d.contract.Annotations
	if d.coordinate != (catalogGrantVerb{"iam", "interactiveClient", "internal" + action}) ||
		d.coordinate != d.catalogCoordinate || d.fullMethod != "/"+d.contract.FullMethod ||
		d.effect != grantpolicy.ChangesHolders || d.direction != direction ||
		d.dispatch.Public || d.dispatch.ScopeFiltered || d.dispatch.Relation != "system_admin" ||
		d.dispatch.Extract == nil || a.Permission != "iam.interactive_clients."+action ||
		a.RequiredRelation != "system_admin" || a.ScopeObjectType != "cluster" ||
		a.ScopeFromRequestField != "*" || a.ScopeObjectTypeFromRequest != "" {
		return false
	}
	object, target, err := d.dispatch.Extract(request)
	return err == nil && object == "cluster" && target == domain.ClusterSingletonID
}

// Две разные цели исключают извлечение фиксированного либо чужого объекта.
func validScopedCatalogWithdrawal(d catalogGrantDeclaration, relation, objectType, requestField string, requests map[string]any) bool {
	if len(requests) != 2 || d.dispatch.Public || d.dispatch.Relation != relation || d.dispatch.Extract == nil ||
		d.contract.Annotations.ScopeObjectType != objectType ||
		d.contract.Annotations.ScopeFromRequestField != requestField ||
		d.contract.Annotations.ScopeObjectTypeFromRequest != "" {
		return false
	}
	for id, req := range requests {
		object, target, err := d.dispatch.Extract(req)
		if err != nil || object != objectType || target != id {
			return false
		}
	}
	return true
}

func TestCatalogGrantDeclarationDecision(t *testing.T) {
	create := catalogGrantVerb{"iam", "accessBinding", "create"}
	update := catalogGrantVerb{"iam", "role", "update"}
	list := catalogGrantVerb{"iam", "accessBinding", "list"}
	verbs := []catalogGrantVerb{create, update, list}
	declared := []catalogGrantDeclaration{
		{coordinate: create, effect: grantpolicy.ChangesHolders, requiresCheck: true},
		{coordinate: update, effect: grantpolicy.ChangesTier, requiresCheck: true},
		{coordinate: list, effect: grantpolicy.UnchangedAccess},
	}

	t.Run("законный близнец", func(t *testing.T) {
		got := judgeCatalogGrantDeclarations(verbs, declared)
		if got.examined != 3 || got.changing != 2 || len(got.findings) != 0 {
			t.Fatalf("неверная перепись: %+v", got)
		}
	})
	t.Run("новый глагол меняет ярус", func(t *testing.T) {
		newVerb := catalogGrantVerb{"iam", "accessBinding", "promote"}
		expanded := append([]catalogGrantVerb{newVerb}, verbs...)
		withoutCheck := append([]catalogGrantDeclaration{{coordinate: newVerb, effect: grantpolicy.ChangesTier, direction: grantpolicy.ExpandsOrMixesAccess}}, declared...)
		refused := judgeCatalogGrantDeclarations(expanded, withoutCheck)
		require.Equal(t, 4, refused.examined)
		require.Equal(t, 3, refused.changing)
		require.Equal(t, []string{"iam.accessBinding.promote: нет обязательной проверки права выдавать или подтверждённого полномочия чистого отзыва"}, refused.findings)

		withCheck := append([]catalogGrantDeclaration{{coordinate: newVerb, effect: grantpolicy.ChangesTier, direction: grantpolicy.ExpandsOrMixesAccess, requiresCheck: true}}, declared...)
		accepted := judgeCatalogGrantDeclarations(expanded, withCheck)
		require.Equal(t, refused.examined, accepted.examined)
		require.Equal(t, refused.changing, accepted.changing)
		require.Empty(t, accepted.findings)
	})
	t.Run("отсутствие декларации", func(t *testing.T) {
		got := judgeCatalogGrantDeclarations(verbs, declared[1:])
		if got.examined != 3 || got.changing != 1 || len(got.findings) != 1 ||
			got.findings[0] != "iam.accessBinding.create: эффект на держателей или ярус не объявлен" {
			t.Fatalf("неверная перепись: %+v", got)
		}
	})
	t.Run("пустой обход", func(t *testing.T) {
		got := judgeCatalogGrantDeclarations(nil, nil)
		if got.examined != 0 || got.changing != 0 || len(got.findings) == 0 {
			t.Fatalf("пустой обход принят: %+v", got)
		}
	})
	t.Run("неполная координата", func(t *testing.T) {
		broken := catalogGrantVerb{module: "iam", resource: "role"}
		got := judgeCatalogGrantDeclarations([]catalogGrantVerb{broken}, []catalogGrantDeclaration{
			{coordinate: broken, effect: grantpolicy.UnchangedAccess},
		})
		if got.examined != 0 || got.changing != 0 || len(got.findings) != 2 {
			t.Fatalf("неполная координата принята: %+v", got)
		}
	})
}

type catalogGrantInventory struct {
	verbs           []catalogGrantVerb
	methods         map[string]catalogGrantVerb
	rpcVerbs        map[catalogGrantVerb]struct{}
	manifestRows    map[catalogGrantVerb]struct{}
	tierInputs      []catalogGrantVerb
	dispatch        authz.RPCMap
	contracts       map[string]check.ContractMethod
	dispatchReasons map[string]string
}

func catalogTierAuthorityInputs(rows []catalog.VerbRow, rpcVerbs map[catalogGrantVerb]struct{}) []catalogGrantVerb {
	var inputs []catalogGrantVerb
	for _, row := range rows {
		coordinate := catalogGrantVerb{row.Module, row.Resource, row.Verb}
		if _, hasRPC := rpcVerbs[coordinate]; !hasRPC {
			inputs = append(inputs, coordinate)
		}
	}
	return inputs
}

// readCatalogGrantInventory выводит две популяции из их штатных источников:
// RPC из дескрипторов и копии каталога, грантуемые глаголы из манифеста.
func readCatalogGrantInventory(t *testing.T) catalogGrantInventory {
	t.Helper()
	return readCatalogGrantSources(t).inventory(t)
}

type catalogGrantSources struct {
	rpcRows  []catalogderive.Entry
	methods  []check.ContractMethod
	manifest *manifest.Manifest
}

func readCatalogGrantSources(t *testing.T) catalogGrantSources {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	root, err := platformtree.ModuleRootFrom(wd)
	require.NoError(t, err)

	catalogJSON, err := os.ReadFile(filepath.Join(root, "internal/apps/kaname/seed/embedded/permission_catalog.json")) // #nosec G304 -- фиксированный путь внутри корня модуля
	require.NoError(t, err)
	var rpcRows []catalogderive.Entry
	require.NoError(t, json.Unmarshal(catalogJSON, &rpcRows))
	methods, files := check.OwnContractMethods("kaname/")
	require.Positive(t, files)
	body, err := os.ReadFile(filepath.Join(root, "manifest.yaml")) // #nosec G304 -- фиксированный путь внутри корня модуля
	require.NoError(t, err)
	m, err := manifest.Load(body)
	require.NoError(t, err)
	return catalogGrantSources{rpcRows: rpcRows, methods: methods, manifest: m}
}

func (src catalogGrantSources) inventory(t *testing.T) catalogGrantInventory {
	t.Helper()
	rpcRows, methods := src.rpcRows, src.methods
	findings, census, err := check.CompareCatalogWithContract(rpcRows, methods)
	require.NoError(t, err)
	require.Empty(t, findings, census.String())

	byFQN := make(map[string]catalogderive.Entry, len(rpcRows))
	own := make(map[string]bool, len(methods))
	for _, method := range methods {
		own[method.FullMethod] = true
	}
	for _, row := range rpcRows {
		if own[row.FQN] {
			require.NotContains(t, byFQN, row.FQN, "повторная строка собственного RPC")
			byFQN[row.FQN] = row
		}
	}
	var source []roleexport.CatalogEntry
	for _, method := range methods {
		row := byFQN[method.FullMethod]
		source = append(source, roleexport.CatalogEntry{FQN: row.FQN, RequiredRelation: row.RequiredRelation,
			ScopeObjectType: row.ScopeExtractor.ObjectType})
	}
	actions, faults := roleexport.Attribute(source)
	require.Empty(t, faults)
	require.Len(t, actions, len(methods))

	rows, err := modulecatalog.RowsOf(src.manifest)
	require.NoError(t, err)
	require.NotEmpty(t, rows.Verbs)

	dispatch, err := catalogderive.Derive(authzguard.OwnDoorProtoPackages()...)
	require.NoError(t, err)
	contracts := make(map[string]check.ContractMethod, len(methods))
	for _, method := range methods {
		contracts["/"+method.FullMethod] = method
	}
	dispatchReasons := make(map[string]string)
	catalogderive.RangeAnnotated(authzguard.OwnDoorProtoPackages(), func(full string, md protoreflect.MethodDescriptor, _ catalogderive.Annotations) {
		dispatchReasons[full], _ = proto.GetExtension(md.Options(), authzv1.E_ExemptReason).(string)
	})
	inventory := catalogGrantInventory{
		contracts: contracts, dispatchReasons: dispatchReasons,
		dispatch:     dispatch,
		methods:      make(map[string]catalogGrantVerb, len(actions)),
		rpcVerbs:     make(map[catalogGrantVerb]struct{}, len(actions)),
		manifestRows: make(map[catalogGrantVerb]struct{}, len(rows.Verbs)),
	}
	for _, action := range actions {
		coordinate := catalogGrantVerb{action.Module, action.Resource, modulecatalog.CanonicalVerbToken(action.Verb)}
		require.NotContains(t, inventory.rpcVerbs, coordinate, "несколько RPC дали один ключ каталога")
		inventory.rpcVerbs[coordinate] = struct{}{}
		inventory.methods[action.FQN] = coordinate
		inventory.verbs = append(inventory.verbs, coordinate)
	}
	for _, row := range rows.Verbs {
		coordinate := catalogGrantVerb{row.Module, row.Resource, row.Verb}
		require.NotContains(t, inventory.manifestRows, coordinate, "повторная строка манифеста")
		inventory.manifestRows[coordinate] = struct{}{}
		if _, exists := inventory.rpcVerbs[coordinate]; !exists {
			inventory.verbs = append(inventory.verbs, coordinate)
		}
	}
	inventory.tierInputs = catalogTierAuthorityInputs(rows.TierOnlyVerbs, inventory.rpcVerbs)
	for _, coordinate := range inventory.tierInputs {
		require.Contains(t, inventory.manifestRows, coordinate, "ярусная строка отсутствует в каталоге манифеста")
	}
	return inventory
}

func TestCatalogTierAuthorityInputWithSameCoordinateRPC(t *testing.T) {
	key := catalogGrantVerb{"iam", "user", "create"}
	rows := []catalog.VerbRow{{Module: key.module, Resource: key.resource, Verb: key.verb}}
	require.Equal(t, []catalogGrantVerb{key}, catalogTierAuthorityInputs(rows, nil))
	require.Empty(t, catalogTierAuthorityInputs(rows, map[catalogGrantVerb]struct{}{key: {}}))
}

// Новый метод вводится на входе сверки контракта с каталогом. Обе декларации
// проходят тот же обход полного набора, что и декларации действующих владельцев.
func TestCatalogGrantNewTierVerbJoinsOwnCatalog(t *testing.T) {
	src := readCatalogGrantSources(t)
	live := src.inventory(t)
	before := judgeCatalogGrantDeclarations(live.verbs, catalogGrantDeclarations(t, live))

	key := catalogGrantVerb{"iam", "accessBinding", "promote"}
	require.NotContains(t, live.verbs, key)
	for i := range src.manifest.Resources {
		resource := &src.manifest.Resources[i]
		if resource.Name == key.resource {
			resource.Verbs = append(resource.Verbs, manifest.Verb{Name: key.verb, Class: "update"})
		}
	}
	manifestOnly := src.inventory(t)
	require.Contains(t, manifestOnly.verbs, key)
	require.NotContains(t, manifestOnly.rpcVerbs, key)
	require.NotContains(t, manifestOnly.tierInputs, key)

	update := strings.TrimPrefix(iamv1.AccessBindingService_Update_FullMethodName, "/")
	promote := strings.TrimSuffix(update, "/Update") + "/Promote"
	method := live.contracts["/"+update]
	require.Equal(t, update, method.FullMethod)
	method.FullMethod = promote
	method.Annotations.Permission = "iam.access_bindings.promote"
	method.Annotations.RequiredRelation = "v_promote"
	src.methods = append(src.methods, method)
	for _, row := range src.rpcRows {
		if row.FQN == update {
			row.FQN = promote
			row.Permission = method.Annotations.Permission
			row.RequiredRelation = method.Annotations.RequiredRelation
			src.rpcRows = append(src.rpcRows, row)
			break
		}
	}

	expanded := src.inventory(t)
	require.Equal(t, key, expanded.methods[promote])
	require.Contains(t, expanded.manifestRows, key)
	declarations := catalogGrantDeclarations(t, expanded)
	undeclared := judgeCatalogGrantDeclarations(expanded.verbs, declarations)
	require.Equal(t, before.examined+1, undeclared.examined)
	require.Equal(t, before.changing, undeclared.changing)
	require.ElementsMatch(t, append(before.findings, key.String()+": эффект на держателей или ярус не объявлен"), undeclared.findings)

	owner := grantpolicy.CatalogDeclaration{
		FullMethod: "/" + promote, Effect: grantpolicy.ChangesTier, Direction: grantpolicy.ExpandsOrMixesAccess,
	}
	judge := func(owner grantpolicy.CatalogDeclaration) catalogGrantCensus {
		return judgeCatalogGrantDeclarations(expanded.verbs, append(declarations, catalogGrantDeclarationOf(t, expanded, owner)))
	}
	denied := judge(owner)
	require.Equal(t, undeclared.examined, denied.examined)
	require.Equal(t, before.changing+1, denied.changing)
	require.ElementsMatch(t, append(before.findings, key.String()+": нет обязательной проверки права выдавать или подтверждённого полномочия чистого отзыва"), denied.findings)

	owner.RequiresCheck = true
	allowed := judge(owner)
	require.Equal(t, denied.examined, allowed.examined)
	require.Equal(t, denied.changing, allowed.changing)
	require.ElementsMatch(t, before.findings, allowed.findings)
}

func TestCatalogGrantBindingCreateJoinsProduction(t *testing.T) {
	inventory := readCatalogGrantInventory(t)
	declaration := access_binding.CreateGrantDeclaration()
	require.Equal(t, iamv1.AccessBindingService_Create_FullMethodName, declaration.FullMethod)
	coordinate, exists := inventory.methods[strings.TrimPrefix(declaration.FullMethod, "/")]
	require.True(t, exists, "Create должен иметь каталожную строку собственного RPC")
	require.Contains(t, inventory.manifestRows, coordinate, "Create должен иметь строку глагола в IAM-манифесте")
	census := judgeCatalogGrantDeclarations([]catalogGrantVerb{coordinate}, []catalogGrantDeclaration{
		catalogGrantDeclarationOf(t, inventory, declaration),
	})
	require.Equal(t, 1, census.examined)
	require.Equal(t, 1, census.changing)
	require.Empty(t, census.findings)
}

func TestCatalogGrantCapabilityJoinsManifest(t *testing.T) {
	inventory := readCatalogGrantInventory(t)
	owners := grantpolicy.CatalogCapabilityDeclarations()
	var keys []catalogGrantVerb
	var declarations []catalogGrantDeclaration
	for _, owner := range owners {
		d := catalogGrantDeclarationOf(t, inventory, owner)
		keys = append(keys, d.coordinate)
		declarations = append(declarations, d)
	}
	require.ElementsMatch(t, []catalogGrantVerb{{"iam", "role", "bind"}, {"iam", "accessLabel", "apply"}}, keys)
	census := judgeCatalogGrantDeclarations(keys, declarations)
	require.Equal(t, len(keys), census.examined)
	require.Zero(t, census.changing)
	require.Empty(t, census.findings)
}

func catalogGrantDeclarations(t *testing.T, inventory catalogGrantInventory) []catalogGrantDeclaration {
	t.Helper()
	owners := access_binding.GrantDeclarations()
	owners = append(owners, access_keys.GrantDeclarations()...)
	owners = append(owners, account.GrantDeclarations()...)
	owners = append(owners, authorize.GrantDeclarations()...)
	owners = append(owners, bootstrap_token.GrantDeclarations()...)
	owners = append(owners, child_registration.GrantDeclarations()...)
	owners = append(owners, cluster.GrantDeclarations()...)
	owners = append(owners, clusterpublic.GrantDeclarations()...)
	owners = append(owners, grant_delegation.GrantDeclarations()...)
	owners = append(owners, group.GrantDeclarations()...)
	owners = append(owners, humansession.GrantDeclarations()...)
	owners = append(owners, identityquota.GrantDeclarations()...)
	owners = append(owners, interactiveclient.GrantDeclarations()...)
	owners = append(owners, internal_iam.GrantDeclarations()...)
	owners = append(owners, internal_operations.GrantDeclarations()...)
	owners = append(owners, membership.GrantDeclarations()...)
	owners = append(owners, module.GrantDeclarations()...)
	owners = append(owners, permission_catalog.GrantDeclarations()...)
	owners = append(owners, project.GrantDeclarations()...)
	owners = append(owners, resource_metadata.GrantDeclarations()...)
	owners = append(owners, role.GrantDeclarations()...)
	owners = append(owners, sa_keys.GrantDeclarations()...)
	owners = append(owners, service_account.GrantDeclarations()...)
	owners = append(owners, session_revocations.GrantDeclarations()...)
	owners = append(owners, user.GrantDeclarations()...)
	owners = append(owners, user_tokens.GrantDeclarations()...)
	owners = append(owners, grantpolicy.CatalogCapabilityDeclarations()...)
	var declarations []catalogGrantDeclaration
	for _, coordinate := range inventory.tierInputs {
		declarations = append(declarations, catalogGrantDeclaration{coordinate: coordinate, effect: grantpolicy.AuthorityInput})
	}
	for _, owner := range owners {
		declarations = append(declarations, catalogGrantDeclarationOf(t, inventory, owner))
	}
	return declarations
}

func TestCatalogGrantDeclarationsCoverOwnCatalog(t *testing.T) {
	inventory := readCatalogGrantInventory(t)
	census := judgeCatalogGrantDeclarations(inventory.verbs, catalogGrantDeclarations(t, inventory))
	t.Logf("RPC %d, строк манифеста %d, проверено глаголов %d, меняют держателей или ярус %d",
		len(inventory.methods), len(inventory.manifestRows), census.examined, census.changing)
	for _, finding := range census.findings {
		t.Error(finding)
	}
}

// catalogGrantDeclarationOf переносит все признаки владельца в общую перепись.
func catalogGrantDeclarationOf(t *testing.T, inventory catalogGrantInventory, owner grantpolicy.CatalogDeclaration) catalogGrantDeclaration {
	t.Helper()
	coordinate := declaredCatalogGrantVerb(t, inventory, owner)
	return catalogGrantDeclaration{
		coordinate: coordinate,
		effect:     owner.Effect, direction: owner.Direction, requiresCheck: owner.RequiresCheck,
		withdrawalAuthority: owner.WithdrawalAuthority, fullMethod: owner.FullMethod,
		catalogCoordinate: inventory.methods[strings.TrimPrefix(owner.FullMethod, "/")],
		dispatch:          inventory.dispatch[owner.FullMethod],
		contract:          inventory.contracts[owner.FullMethod], dispatchReason: inventory.dispatchReasons[owner.FullMethod],
	}
}

func TestCatalogModuleApplyRequiresClusterAdministration(t *testing.T) {
	inventory := readCatalogGrantInventory(t)
	var apply []grantpolicy.CatalogDeclaration
	for _, owner := range module.GrantDeclarations() {
		if owner.FullMethod == iamv1.InternalModuleService_Apply_FullMethodName {
			apply = append(apply, owner)
		}
	}
	require.Len(t, apply, 1)
	d := catalogGrantDeclarationOf(t, inventory, apply[0])
	require.Equal(t, catalogGrantVerb{"iam", "module", "internalapply"}, d.coordinate)
	require.Equal(t, grantpolicy.ChangesHoldersAndTier, d.effect)
	require.Equal(t, grantpolicy.ExpandsOrMixesAccess, d.direction)
	require.Equal(t, grantpolicy.NoWithdrawalAuthority, d.withdrawalAuthority)
	require.True(t, d.requiresCheck)
	require.False(t, d.dispatch.Public)
	require.False(t, d.dispatch.ScopeFiltered)
	require.Equal(t, "system_admin", d.dispatch.Relation)
	require.Equal(t, "cluster", d.contract.Annotations.ScopeObjectType)
	require.Equal(t, "*", d.contract.Annotations.ScopeFromRequestField)
	require.Empty(t, d.contract.Annotations.ScopeObjectTypeFromRequest)
	judge := func() catalogGrantCensus {
		return judgeCatalogGrantDeclarations([]catalogGrantVerb{d.coordinate}, []catalogGrantDeclaration{d})
	}
	require.Empty(t, judge().findings)
	// Смешанный эффект остаётся непокрытым без исполняемой проверки;
	// имя внутреннего RPC и его proto-аннотации сами разрешением не служат.
	d.requiresCheck = false
	require.NotEmpty(t, judge().findings)
}

func TestCatalogForceLogoutUsesClusterAdministration(t *testing.T) {
	inventory := readCatalogGrantInventory(t)
	var logout []grantpolicy.CatalogDeclaration
	for _, owner := range internal_iam.GrantDeclarations() {
		if owner.FullMethod == iamv1.InternalIAMService_ForceLogout_FullMethodName {
			logout = append(logout, owner)
		}
	}
	require.Len(t, logout, 1)
	d := catalogGrantDeclarationOf(t, inventory, logout[0])
	require.Equal(t, catalogGrantVerb{"iam", "iAM", "internalforcelogout"}, d.coordinate)
	require.Equal(t, grantpolicy.ChangesHolders, d.effect)
	require.Equal(t, grantpolicy.WithdrawsAccess, d.direction)
	require.Equal(t, grantpolicy.NoWithdrawalAuthority, d.withdrawalAuthority)
	require.True(t, d.requiresCheck)
	require.Equal(t, "INTERNAL_LISTENER", d.dispatchReason)
	judged := judgeCatalogGrantDeclarations([]catalogGrantVerb{d.coordinate}, []catalogGrantDeclaration{d})
	require.Equal(t, 1, judged.changing)
	require.Empty(t, judged.findings)

	// Декларация без исполняемой кластерной проверки обязана дать находку.
	d.requiresCheck = false
	judged = judgeCatalogGrantDeclarations([]catalogGrantVerb{d.coordinate}, []catalogGrantDeclaration{d})
	require.Equal(t, 1, judged.changing)
	require.NotEmpty(t, judged.findings)
}

func TestCatalogInteractiveClientMutationsRequireClusterAdministration(t *testing.T) {
	inventory := readCatalogGrantInventory(t)
	declarations := interactiveclient.GrantDeclarations()
	for _, method := range []struct {
		name      string
		direction grantpolicy.CatalogDirection
	}{
		{iamv1.InternalInteractiveClientService_Create_FullMethodName, grantpolicy.ExpandsOrMixesAccess},
		{iamv1.InternalInteractiveClientService_Update_FullMethodName, grantpolicy.ExpandsOrMixesAccess},
		{iamv1.InternalInteractiveClientService_Delete_FullMethodName, grantpolicy.WithdrawsAccess},
	} {
		t.Run(method.name, func(t *testing.T) {
			var owners []grantpolicy.CatalogDeclaration
			for _, declaration := range declarations {
				if declaration.FullMethod == method.name {
					owners = append(owners, declaration)
				}
			}
			require.Len(t, owners, 1)
			require.Equal(t, grantpolicy.ChangesHolders, owners[0].Effect)
			require.Equal(t, method.direction, owners[0].Direction)
			d := catalogGrantDeclarationOf(t, inventory, owners[0])
			judge := func(d catalogGrantDeclaration) catalogGrantCensus {
				return judgeCatalogGrantDeclarations([]catalogGrantVerb{d.coordinate}, []catalogGrantDeclaration{d})
			}
			require.Contains(t, authzguard.GatewayFrontedInternalRPCs(), method.name)
			require.Equal(t, 1, judge(d).changing)
			require.Empty(t, judge(d).findings)

			for _, mutate := range []func(*catalogGrantDeclaration){
				func(d *catalogGrantDeclaration) { d.requiresCheck = false },
				func(d *catalogGrantDeclaration) { d.dispatch.Public = true },
				func(d *catalogGrantDeclaration) { d.dispatch.Relation = "system_viewer" },
				func(d *catalogGrantDeclaration) { d.contract.Annotations.ScopeObjectType = "account" },
				func(d *catalogGrantDeclaration) { d.coordinate.verb = "other" },
				func(d *catalogGrantDeclaration) {
					d.dispatch.Extract = func(any) (string, string, error) {
						return "cluster", "other", nil
					}
				},
			} {
				changed := d
				mutate(&changed)
				require.NotEmpty(t, judge(changed).findings)
			}
		})
	}
}

func TestCatalogMixedResourceEffectsRequireGrantAuthority(t *testing.T) {
	inventory := readCatalogGrantInventory(t)
	for _, tc := range []struct {
		method string
		owners []grantpolicy.CatalogDeclaration
	}{
		{iamv1.AccountService_Update_FullMethodName, account.GrantDeclarations()},
		{iamv1.ProjectService_Update_FullMethodName, project.GrantDeclarations()},
		{iamv1.InternalIAMService_UnregisterResource_FullMethodName, internal_iam.GrantDeclarations()},
	} {
		t.Run(tc.method, func(t *testing.T) {
			var declared []grantpolicy.CatalogDeclaration
			for _, owner := range tc.owners {
				if owner.FullMethod == tc.method {
					declared = append(declared, owner)
				}
			}
			require.Len(t, declared, 1)
			d := catalogGrantDeclarationOf(t, inventory, declared[0])
			require.Equal(t, grantpolicy.ChangesHoldersAndTier, d.effect)
			require.Equal(t, grantpolicy.ExpandsOrMixesAccess, d.direction)
			require.Equal(t, grantpolicy.NoWithdrawalAuthority, d.withdrawalAuthority)
			d.requiresCheck = false
			got := judgeCatalogGrantDeclarations([]catalogGrantVerb{d.coordinate}, []catalogGrantDeclaration{d})
			require.Equal(t, 1, got.changing)
			require.NotEmpty(t, got.findings)
		})
	}
}

func TestCatalogMetadataPublicationAndChildDeclarations(t *testing.T) {
	inventory := readCatalogGrantInventory(t)
	owners := resource_metadata.GrantDeclarations()
	owners = append(owners, module.GrantDeclarations()...)
	owners = append(owners, child_registration.GrantDeclarations()...)
	byMethod := make(map[string]grantpolicy.CatalogDeclaration, len(owners))
	for _, owner := range owners {
		require.NotContains(t, byMethod, owner.FullMethod)
		byMethod[owner.FullMethod] = owner
	}
	for _, tc := range []struct {
		method     string
		coordinate catalogGrantVerb
		effect     grantpolicy.CatalogEffect
		check      bool
	}{
		{iamv1.ResourceMetadataService_Get_FullMethodName, catalogGrantVerb{"iam", "resourceMetadata", "get"}, grantpolicy.UnchangedAccess, false},
		{iamv1.ResourceMetadataService_Update_FullMethodName, catalogGrantVerb{"iam", "resourceMetadata", "update"}, grantpolicy.ChangesHoldersAndTier, true},
		{iamv1.CatalogPublicationService_PlanPublication_FullMethodName, catalogGrantVerb{"iam", "catalogPublication", "planpublication"}, grantpolicy.UnchangedAccess, false},
		{iamv1.CatalogPublicationService_ApplyPublication_FullMethodName, catalogGrantVerb{"iam", "catalogPublication", "applypublication"}, grantpolicy.ChangesHoldersAndTier, true},
		{iamv1.ChildRegistrationService_Register_FullMethodName, catalogGrantVerb{"iam", "childRegistration", "register"}, grantpolicy.ChangesHoldersAndTier, false},
	} {
		t.Run(tc.method, func(t *testing.T) {
			owner, exists := byMethod[tc.method]
			require.True(t, exists)
			d := catalogGrantDeclarationOf(t, inventory, owner)
			require.Equal(t, tc.coordinate, d.coordinate)
			require.Equal(t, tc.effect, d.effect)
			require.Equal(t, tc.check, d.requiresCheck)
			require.Equal(t, grantpolicy.NoWithdrawalAuthority, d.withdrawalAuthority)
			if tc.effect == grantpolicy.UnchangedAccess {
				require.Equal(t, grantpolicy.UnspecifiedDirection, d.direction)
				return
			}
			require.Equal(t, grantpolicy.ExpandsOrMixesAccess, d.direction)
			census := judgeCatalogGrantDeclarations([]catalogGrantVerb{d.coordinate}, []catalogGrantDeclaration{d})
			require.Equal(t, 1, census.changing)
			require.Equal(t, tc.check, len(census.findings) == 0)
		})
	}
}

func TestCatalogGrantWithdrawalsJoinProduction(t *testing.T) {
	inventory := readCatalogGrantInventory(t)
	owners := group.GrantDeclarations()
	owners = append(owners, role.GrantDeclarations()...)
	owners = append(owners, access_binding.GrantDeclarations()...)
	owners = append(owners, grant_delegation.GrantDeclarations()...)
	owners = append(owners, service_account.GrantDeclarations()...)
	owners = append(owners, user_tokens.GrantDeclarations()...)
	owners = append(owners, access_keys.GrantDeclarations()...)
	owners = append(owners, sa_keys.GrantDeclarations()...)
	owners = append(owners, interactiveclient.GrantDeclarations()...)
	owners = append(owners, user.GrantDeclarations()...)
	owners = append(owners, membership.GrantDeclarations()...)
	owners = append(owners, account.GrantDeclarations()...)
	owners = append(owners, project.GrantDeclarations()...)
	byMethod := make(map[string]grantpolicy.CatalogDeclaration, len(owners))
	for _, owner := range owners {
		byMethod[owner.FullMethod] = owner
	}
	enableOwner, exists := byMethod[iamv1.ServiceAccountService_Enable_FullMethodName]
	require.True(t, exists)
	enable := catalogGrantDeclarationOf(t, inventory, enableOwner)
	t.Run("Enable сохраняет находку", func(t *testing.T) {
		require.Equal(t, grantpolicy.ChangesHolders, enable.effect)
		require.Equal(t, grantpolicy.ExpandsOrMixesAccess, enable.direction)
		require.False(t, enable.requiresCheck)
		require.Equal(t, grantpolicy.NoWithdrawalAuthority, enable.withdrawalAuthority)
		census := judgeCatalogGrantDeclarations([]catalogGrantVerb{enable.coordinate}, []catalogGrantDeclaration{enable})
		require.Equal(t, 1, census.changing)
		require.NotEmpty(t, census.findings)
	})
	for _, tc := range []struct {
		method     string
		effect     grantpolicy.CatalogEffect
		checked    bool
		coordinate catalogGrantVerb
	}{
		{iamv1.GroupService_RemoveMember_FullMethodName, grantpolicy.ChangesHolders, false, catalogGrantVerb{"iam", "group", "removemember"}},
		{iamv1.RoleService_Delete_FullMethodName, grantpolicy.ChangesHoldersAndTier, false, catalogGrantVerb{"iam", "role", "delete"}},
		{iamv1.GroupService_Delete_FullMethodName, grantpolicy.ChangesHoldersAndTier, false, catalogGrantVerb{"iam", "group", "delete"}},
		{iamv1.ServiceAccountService_Delete_FullMethodName, grantpolicy.ChangesHoldersAndTier, false, catalogGrantVerb{"iam", "serviceAccount", "delete"}},
		{iamv1.ServiceAccountService_Disable_FullMethodName, grantpolicy.ChangesHolders, false, catalogGrantVerb{"iam", "serviceAccount", "disable"}},
		{iamv1.UserTokenService_Revoke_FullMethodName, grantpolicy.ChangesHolders, false, catalogGrantVerb{"iam", "userToken", "revoke"}},
		{iamv1.AccessKeyService_Revoke_FullMethodName, grantpolicy.ChangesHolders, false, catalogGrantVerb{"iam", "accessKey", "revoke"}},
		{iamv1.SAKeyService_Revoke_FullMethodName, grantpolicy.ChangesHolders, false, catalogGrantVerb{"iam", "sAKey", "revoke"}},
		{iamv1.InternalInteractiveClientService_Delete_FullMethodName, grantpolicy.ChangesHolders, true, catalogGrantVerb{"iam", "interactiveClient", "internaldelete"}},
		{iamv1.UserService_Delete_FullMethodName, grantpolicy.ChangesHoldersAndTier, false, catalogGrantVerb{"iam", "user", "delete"}},
		{iamv1.UserService_RemoveFromAccount_FullMethodName, grantpolicy.ChangesHoldersAndTier, false, catalogGrantVerb{"iam", "user", "removefromaccount"}},
		{iamv1.UserService_Block_FullMethodName, grantpolicy.ChangesHolders, false, catalogGrantVerb{"iam", "user", "block"}},
		{iamv1.UserService_ResetAccessKeys_FullMethodName, grantpolicy.ChangesHolders, false, catalogGrantVerb{"iam", "user", "resetaccesskeys"}},
		{iamv1.AccountService_Delete_FullMethodName, grantpolicy.ChangesHoldersAndTier, false, catalogGrantVerb{"iam", "account", "delete"}},
		{iamv1.ProjectService_Delete_FullMethodName, grantpolicy.ChangesHoldersAndTier, false, catalogGrantVerb{"iam", "project", "delete"}},
		{iamv1.AccessBindingService_Delete_FullMethodName, grantpolicy.ChangesHoldersAndTier, false, catalogGrantVerb{"iam", "accessBinding", "delete"}},
		{iamv1.AccessBindingService_Revoke_FullMethodName, grantpolicy.ChangesHoldersAndTier, false, catalogGrantVerb{"iam", "accessBinding", "revoke"}},
		{iamv1.GrantDelegationService_Revoke_FullMethodName, grantpolicy.ChangesHoldersAndTier, true, catalogGrantVerb{"iam", "grantDelegation", "revoke"}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			owner, exists := byMethod[tc.method]
			require.True(t, exists, "нет декларации операции отзыва")
			require.Equal(t, tc.effect, owner.Effect)
			require.Equal(t, grantpolicy.WithdrawsAccess, owner.Direction)
			require.Equal(t, tc.checked, owner.RequiresCheck)
			declaration := catalogGrantDeclarationOf(t, inventory, owner)
			require.Equal(t, tc.coordinate, declaration.coordinate, "RPC и глагол каталога разошлись")
			require.Equal(t, owner.Direction, declaration.direction, "перепись потеряла направление эффекта")
			census := judgeCatalogGrantDeclarations([]catalogGrantVerb{declaration.coordinate}, []catalogGrantDeclaration{declaration})
			require.Equal(t, 1, census.examined)
			require.Equal(t, 1, census.changing, "отзыв должен остаться в числе меняющих доступ")
			require.Empty(t, census.findings)
			if tc.checked {
				// Эти RPC требуют исполняемой проверки, включая чистый отзыв.
				require.Equal(t, grantpolicy.NoWithdrawalAuthority, owner.WithdrawalAuthority)
				declaration.requiresCheck = false
				require.NotEmpty(t, judgeCatalogGrantDeclarations([]catalogGrantVerb{declaration.coordinate}, []catalogGrantDeclaration{declaration}).findings)
				return
			}
			twins := []struct {
				name   string
				mutate func(*catalogGrantDeclaration)
			}{
				{"чужой RPC", func(d *catalogGrantDeclaration) { d.fullMethod = iamv1.AccessBindingService_Create_FullMethodName }},
				{"другой RPC отзыва", func(d *catalogGrantDeclaration) {
					if d.fullMethod == iamv1.RoleService_Delete_FullMethodName {
						d.fullMethod = iamv1.GroupService_Delete_FullMethodName
					} else if d.fullMethod == iamv1.GroupService_Delete_FullMethodName {
						d.fullMethod = iamv1.RoleService_Delete_FullMethodName
					} else if d.fullMethod == iamv1.AccessBindingService_Delete_FullMethodName {
						d.fullMethod = iamv1.AccessBindingService_Revoke_FullMethodName
					} else {
						d.fullMethod = iamv1.AccessBindingService_Delete_FullMethodName
					}
				}},
				{"другое полномочие", func(d *catalogGrantDeclaration) {
					switch d.withdrawalAuthority {
					case grantpolicy.TargetRoleDeletionWithdrawal:
						d.withdrawalAuthority = grantpolicy.TargetGroupDeletionWithdrawal
					case grantpolicy.TargetGroupDeletionWithdrawal:
						d.withdrawalAuthority = grantpolicy.TargetRoleDeletionWithdrawal
					case grantpolicy.TargetGroupMembershipWithdrawal:
						d.withdrawalAuthority = grantpolicy.ActiveDelegationBindingWithdrawal
					default:
						d.withdrawalAuthority = grantpolicy.TargetGroupMembershipWithdrawal
					}
				}},
				{"чужой модуль", func(d *catalogGrantDeclaration) { d.coordinate.module = "other" }},
				{"чужой ресурс", func(d *catalogGrantDeclaration) { d.coordinate.resource = "other" }},
				{"чужой глагол", func(d *catalogGrantDeclaration) { d.coordinate.verb = "promote" }},
				{"одна метка сужения", func(d *catalogGrantDeclaration) { d.withdrawalAuthority = grantpolicy.NoWithdrawalAuthority }},
				{"неизвестное полномочие", func(d *catalogGrantDeclaration) { d.withdrawalAuthority = grantpolicy.WithdrawalAuthority(255) }},
				{"направление не объявлено", func(d *catalogGrantDeclaration) { d.direction = grantpolicy.UnspecifiedDirection }},
				{"расширение или смешанное изменение", func(d *catalogGrantDeclaration) { d.direction = grantpolicy.ExpandsOrMixesAccess }},
				{"неизвестное направление даже с проверкой", func(d *catalogGrantDeclaration) {
					d.direction = grantpolicy.CatalogDirection(255)
					d.requiresCheck = true
				}},
				{"неизвестный эффект", func(d *catalogGrantDeclaration) { d.effect = grantpolicy.UnknownEffect }},
				{"смена эффекта", func(d *catalogGrantDeclaration) { d.effect = grantpolicy.ChangesTier }},
				{"невалидное исключение даже с проверкой", func(d *catalogGrantDeclaration) {
					d.fullMethod = iamv1.AccessBindingService_Create_FullMethodName
					d.requiresCheck = true
				}},
				{"изменена авторизация", func(d *catalogGrantDeclaration) { d.dispatch.ScopeFiltered = true }},
				{"публичность изменена", func(d *catalogGrantDeclaration) { d.dispatch.Public = !d.dispatch.Public }},
				{"другое право метода", func(d *catalogGrantDeclaration) { d.dispatch.Relation = "other" }},
				{"сломана собственная дверь", func(d *catalogGrantDeclaration) {
					if !d.dispatch.Public {
						objectType := d.contract.Annotations.ScopeObjectType
						id := "grp00000000000000001"
						if objectType == "iam_role" {
							id = "rol00000000000000001"
						} else if objectType == "iam_service_account" {
							id = "sva00000000000000001"
						}
						d.dispatch.Extract = func(any) (string, string, error) { return objectType, id, nil }
					} else {
						d.dispatchReason = "SELF_SERVICE"
					}
				}},
			}
			if declaration.withdrawalAuthority == grantpolicy.TargetServiceAccountDisableWithdrawal {
				twins = append(twins, struct {
					name   string
					mutate func(*catalogGrantDeclaration)
				}{"полномочие Disable не переносится на Enable", func(d *catalogGrantDeclaration) {
					// Берём настоящие RPC, координату и дверь Enable, чтобы отказ
					// не объяснялся несогласованностью скопированных дескрипторов.
					*d = enable
					d.direction = grantpolicy.WithdrawsAccess
					d.withdrawalAuthority = grantpolicy.TargetServiceAccountDisableWithdrawal
				}})
			}
			var expansionMethods []string
			switch tc.method {
			case iamv1.UserTokenService_Revoke_FullMethodName:
				expansionMethods = []string{iamv1.UserTokenService_Issue_FullMethodName}
			case iamv1.AccessKeyService_Revoke_FullMethodName:
				expansionMethods = []string{iamv1.AccessKeyService_FinishRegistration_FullMethodName}
			case iamv1.ServiceAccountService_Delete_FullMethodName:
				expansionMethods = []string{
					iamv1.ServiceAccountService_Create_FullMethodName,
					iamv1.ServiceAccountService_Update_FullMethodName,
					iamv1.ServiceAccountService_Enable_FullMethodName,
				}
			case iamv1.SAKeyService_Revoke_FullMethodName:
				expansionMethods = []string{iamv1.SAKeyService_Issue_FullMethodName}
			case iamv1.UserService_Delete_FullMethodName:
				expansionMethods = []string{iamv1.UserService_Invite_FullMethodName}
			case iamv1.UserService_RemoveFromAccount_FullMethodName:
				expansionMethods = []string{iamv1.UserService_Invite_FullMethodName, iamv1.MembershipService_Create_FullMethodName}
			case iamv1.UserService_Block_FullMethodName, iamv1.UserService_ResetAccessKeys_FullMethodName:
				expansionMethods = []string{iamv1.UserService_ResetSecondFactor_FullMethodName, iamv1.UserService_Unblock_FullMethodName}
			case iamv1.AccountService_Delete_FullMethodName:
				expansionMethods = []string{iamv1.AccountService_Update_FullMethodName}
			case iamv1.ProjectService_Delete_FullMethodName:
				expansionMethods = []string{iamv1.ProjectService_Update_FullMethodName}
			}
			for _, method := range expansionMethods {
				expansionOwner, exists := byMethod[method]
				require.True(t, exists)
				expansion := catalogGrantDeclarationOf(t, inventory, expansionOwner)
				twins = append(twins, struct {
					name   string
					mutate func(*catalogGrantDeclaration)
				}{"полномочие отзыва не действует в " + expansion.coordinate.String(), func(d *catalogGrantDeclaration) {
					*d = expansion
					d.direction = grantpolicy.WithdrawsAccess
					d.withdrawalAuthority = declaration.withdrawalAuthority
				}})
			}
			if !declaration.dispatch.Public {
				twins = append(twins, []struct {
					name   string
					mutate func(*catalogGrantDeclaration)
				}{
					{"согласованная чужая координата", func(d *catalogGrantDeclaration) {
						d.coordinate.resource = "other"
						d.catalogCoordinate = d.coordinate
					}},
					{"чужой тип области", func(d *catalogGrantDeclaration) { d.contract.Annotations.ScopeObjectType = "foreign_object" }},
					{"чужое поле области", func(d *catalogGrantDeclaration) { d.contract.Annotations.ScopeFromRequestField = "foreign_id" }},
					{"тип области из запроса", func(d *catalogGrantDeclaration) { d.contract.Annotations.ScopeObjectTypeFromRequest = "resource_type" }},
					{"извлекатель отсутствует", func(d *catalogGrantDeclaration) { d.dispatch.Extract = nil }},
					{"извлечён чужой тип", func(d *catalogGrantDeclaration) {
						extract := d.dispatch.Extract
						d.dispatch.Extract = func(req any) (string, string, error) {
							_, target, err := extract(req)
							return "foreign_object", target, err
						}
					}},
				}...)
			}
			for _, twin := range twins {
				t.Run(twin.name, func(t *testing.T) {
					changed := declaration
					twin.mutate(&changed)
					got := judgeCatalogGrantDeclarations([]catalogGrantVerb{changed.coordinate}, []catalogGrantDeclaration{changed})
					require.Equal(t, 1, got.examined)
					if changed.effect != grantpolicy.UnknownEffect {
						require.Equal(t, 1, got.changing)
					}
					require.NotEmpty(t, got.findings, "невалидный близнец принят")
				})
			}
		})
	}
}

func declaredCatalogGrantVerb(t *testing.T, catalog catalogGrantInventory, declaration grantpolicy.CatalogDeclaration) catalogGrantVerb {
	t.Helper()
	if declaration.Capability == "" {
		require.NotEqual(t, grantpolicy.AuthorityInput, declaration.Effect, "для RPC требуется эффект исполняемой операции")
		key, exists := catalog.methods[strings.TrimPrefix(declaration.FullMethod, "/")]
		require.True(t, exists, "декларация ссылается на отсутствующий RPC %s", declaration.FullMethod)
		return key
	}
	require.Empty(t, declaration.FullMethod, "управляющая декларация не может также объявлять RPC")
	require.Equal(t, grantpolicy.AuthorityInput, declaration.Effect, "управляющее право описывает вход расчёта полномочий")
	rule, exists := declaration.Capability.RuleRef()
	require.True(t, exists, "неизвестное управляющее право %s", declaration.Capability)
	key := catalogGrantVerb{rule.Module, rule.Resource, rule.Verb}
	require.Contains(t, catalog.manifestRows, key, "в манифесте нет управляющего права %s", key)
	require.NotContains(t, catalog.rpcVerbs, key, "координате %s требуется декларация самого RPC", key)
	return key
}
