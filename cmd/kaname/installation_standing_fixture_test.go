// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/operations"
	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	serviceaccountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/callerorigin"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/presentedcred"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

// installationStandingWorld расширяет утверждённый Given начального O. C создаётся
// штатными Operation под O, без вставки SQL фикстуры. Административные изменения
// используют существующую настоящую фикстуру второй блокировки mTLS с НАСТОЯЩИМ кластерным обработчиком.
// Передаваемые ниже идентичность и ACR получаются только повторной проверкой
// настоящего удостоверяющего материала церемонии O. Этот помощник — внутреннее доказательство, а не утверждение
// о выполнении финальной полной приёмки serve/слушателей.
type installationStandingWorld struct {
	*installationBootstrapWorld
	cfg            config.Config
	creator        domain.ServiceAccountID
	credentialFile string
	authentication *installationAuthentication
	cluster        iamv1.InternalClusterServiceClient
	ops            operations.Repo
}

func (f *installationBootstrapWorld) verifyOperator(t *testing.T, parent context.Context) context.Context {
	t.Helper()
	var verified context.Context
	incoming := metadata.NewIncomingContext(parent, metadata.Pairs(presentedcred.MetadataKey, "Bearer "+f.operatorToken))
	_, err := f.reader.UnaryOver(nil)(incoming, nil, &grpc.UnaryServerInfo{FullMethod: grantAdminFQN},
		func(ctx context.Context, _ any) (any, error) { verified = ctx; return nil, nil })
	require.NoError(t, err, "O must still pass normal presented-credential verification")
	p, ok := operations.PrincipalFromContextOK(verified)
	require.True(t, ok)
	require.Equal(t, "user", p.Type)
	require.Equal(t, string(f.world.user), p.ID)
	return verified
}

// gatewayOperator передаёт только значения из проверенного токена O. Вызывающий
// не выбирает субъекта/ACR из конфигурации, и идентичность контекста не засеивается.
func (f *installationStandingWorld) gatewayOperator(t *testing.T, parent context.Context) context.Context {
	t.Helper()
	verified := f.verifyOperator(t, parent)
	p, ok := operations.PrincipalFromContextOK(verified)
	require.True(t, ok)
	acr, ok := callerorigin.AssuranceFrom(verified)
	require.True(t, ok)
	require.Equal(t, "2", acr)
	require.NoError(t, authzguard.RequireClusterAdmin(verified, f.relations))
	return metadata.NewOutgoingContext(parent, metadata.Pairs(
		grpcsrv.MDKeyPrincipalType, p.Type, grpcsrv.MDKeyPrincipalID, p.ID, grpcsrv.MDKeyTokenACR, acr))
}

func newInstallationStandingWorld(t *testing.T, pace int, accessTTL time.Duration) *installationStandingWorld {
	t.Helper()
	require.Contains(t, []int{1, 5}, pace, "acceptance uses actual production pace1/5, not an unlimited fixture")
	require.Positive(t, accessTTL)
	base := newInstallationBootstrapWorld(t)
	cfg, err := config.Load("")
	require.NoError(t, err)
	cfg.AuthN.ClientToken.Enabled = true
	cfg.AuthN.ClientToken.AllowedAudiences = "https://api.kacho.local"
	cfg.AuthN.ClientToken.DefaultAudience = "https://api.kacho.local"
	cfg.AuthN.ClientToken.ExchangesPerClientPerSec = pace
	cfg.AuthN.ClientToken.TokenTTL = accessTTL
	// Явный существующий профиль нативного стенда; умолчания конфигурации нулевые,
	// поскольку производственный код требует объявления этих пределов выдачи.
	cfg.AuthN.ClientToken.BodyCeiling = 16384
	cfg.AuthN.ClientToken.InFlightCeiling = 32
	cfg.AuthN.ClientToken.FailedProofsPerSource = 50
	cfg.AuthN.ClientToken.FailedProofWindow = 15 * time.Minute
	cfg.AuthN.PresentedCredential.Enabled = true
	cfg.AuthN.PresentedCredential.Audience = "https://api.kacho.local"
	normalOperations := operations.NewRepo(base.world.pool, "kaname")
	f := &installationStandingWorld{installationBootstrapWorld: base, cfg: cfg, ops: normalOperations}
	pool := base.world.pool
	grants := kanamepg.NewClusterAdminGrantWriter(pool)
	grantReads := kanamepg.NewClusterAdminGrantReader(pool)
	txb := kanamepg.NewPoolTxBeginner(pool)
	emit := kanamepg.NewFGAOutboxEmitter()
	audit := kanamepg.NewAuditOutboxEmitter(pool)
	grant := clusterapp.NewGrantAdminUseCase(grants, grantReads, emit, txb, normalOperations).
		WithSubjectStateReader(kanamepg.NewSubjectStateReader(pool)).WithAdminChecker(f.relations).WithAuditEmitter(audit)
	revoke := clusterapp.NewRevokeAdminUseCase(grants, emit, txb, normalOperations).WithAdminChecker(f.relations).WithAuditEmitter(audit)
	handler := clusterapp.NewHandler(clusterapp.NewGetClusterUseCase(kanamepg.NewClusterReader(pool)), grant, revoke, clusterapp.NewListAdminsUseCase(grantReads))
	registry, err := seed.LoadPermissionRegistry(base.world.ctx, nil)
	require.NoError(t, err)
	// Существующий помощник использует настоящую проверку CA/конечного сертификата TLS и производственную
	// цепочку извлечения идентичности -> политики вызывающего шлюза -> нижней границы ACR каталога.
	f.cluster = iamv1.NewInternalClusterServiceClient(serveSecondLock(t, registry, handler))
	operator := f.verifyOperator(t, base.world.ctx)
	require.NoError(t, authzguard.RequireClusterAdmin(operator, f.relations))
	_, system, err := kanamepg.NewInstallationReader(pool).InstallationAccounts(operator, "", 2)
	require.NoError(t, err)
	create := serviceaccountapp.NewCreateServiceAccountUseCase(kanamepg.New(pool, nil), f.ops).WithRelationStore(f.relations, quietLogger())
	op, err := create.Execute(operator, domain.ServiceAccount{AccountID: system, Name: "rid-standing-creator"})
	require.NoError(t, err)
	require.NoError(t, waitInstallationOperation(operator, f.ops, op.ID))
	saved, err := f.ops.Get(operator, op.ID)
	require.NoError(t, err)
	var creator iamv1.ServiceAccount
	require.NoError(t, saved.Response.UnmarshalTo(&creator))
	require.Equal(t, string(system), creator.AccountId, "C is not owner/admin of any tenant")
	f.creator = domain.ServiceAccountID(creator.Id)
	require.NotEmpty(t, f.creator)
	granted, err := f.cluster.GrantAdmin(f.gatewayOperator(t, base.world.ctx), &iamv1.GrantClusterAdminRequest{
		SubjectType: iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, SubjectId: string(f.creator)})
	require.NoError(t, err)
	require.NoError(t, waitInstallationOperation(operator, f.ops, granted.GetId()))
	// Используем настоящий обработчик ключей корня композиции, сохраняя аудит, срок,
	// скрытие одноразового ответа и штатную регистрацию удостоверяющего материала.
	keys := buildSAKeysHandler(pool, f.ops, cfg, quietLogger())
	issued, err := keys.Issue(operator, &iamv1.IssueSAKeyRequest{ServiceAccountId: string(f.creator), Description: "RID standing creator", TtlSeconds: 7200})
	require.NoError(t, err)
	require.NoError(t, waitInstallationOperation(operator, f.ops, issued.GetId()))
	saved, err = f.ops.Get(operator, issued.GetId())
	require.NoError(t, err)
	var key iamv1.IssueSAKeyResponse
	require.NoError(t, saved.Response.UnmarshalTo(&key))
	require.NotEmpty(t, key.ClientId)
	require.NotEmpty(t, key.KeyId)
	require.NotEmpty(t, key.PrivateKeyPem)
	require.Equal(t, "ES256", key.Algorithm)
	material, err := json.Marshal(installationCredential{ClientID: key.ClientId, KeyID: key.KeyId, PrivateKeyPEM: key.PrivateKeyPem})
	require.NoError(t, err)
	f.credentialFile = filepath.Join(t.TempDir(), "standing-creator.json")
	require.NoError(t, os.WriteFile(f.credentialFile, material, 0600))
	f.cfg.ModuleSeedInstaller.CredentialFile = f.credentialFile
	f.authentication, err = prepareInstallationAuthentication(pool, f.cfg, base.world.signer, base.reader, quietLogger())
	require.NoError(t, err)
	verified, err := f.authentication.Authenticate(base.world.ctx)
	require.NoError(t, err)
	p, ok := operations.PrincipalFromContextOK(verified)
	require.True(t, ok)
	require.Equal(t, "service_account", p.Type)
	require.Equal(t, string(f.creator), p.ID)
	require.NoError(t, authzguard.RequireClusterAdmin(verified, f.relations))
	return f
}
