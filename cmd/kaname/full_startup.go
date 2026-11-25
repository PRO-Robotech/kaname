// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	childregistrationapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/child_registration"
	internaliamapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Ранний read-only профиль: до первой проекции, посева и maintenance writer.
// Ни этот сборщик, ни serve не выполняют Stage/Activate. Пустая/неактивная база
// в full-режиме означает отказ старта, а не предложение запустить legacy.
type fullStartupProfile struct {
	contract    *kanamepg.FullWriterContract
	primary     *kanamepg.Repository
	bundle      *granteffect.Bundle
	manifests   []*manifest.Manifest
	model       preparedModel
	publication *publishedStartupProfile
}

func prepareFullStartup(ctx context.Context, cfg config.Config, pool *pgxpool.Pool, logger *slog.Logger) (context.Context, *fullStartupProfile, error) {
	if err := cfg.AuthorityProtocol.Validate(); err != nil {
		return ctx, nil, err
	}
	repository := kanamepg.New(pool, nil)
	if !cfg.AuthorityProtocol.FullSemantics {
		// До startup-записей отвергает gen2 даже при legacy/пустом participation.
		if err := repository.ValidateStagedWriterContract(ctx); err != nil {
			return ctx, nil, fmt.Errorf("authority-protocol staged startup: %w", err)
		}
		return ctx, nil, nil
	}
	var published bool
	if err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM kaname.publication_model_revision)`).Scan(&published); err != nil {
		return ctx, nil, fmt.Errorf("проверить наличие опубликованной редакции: %w", err)
	}
	if published {
		return preparePublishedFullStartup(ctx, pool, repository)
	}
	manifests, err := loadDeliveredManifests(logger, cfg.Manifests)
	if err != nil {
		return ctx, nil, err
	}
	model, err := prepareComposedModel(logger, manifests)
	if err != nil {
		return ctx, nil, err
	}
	anchor, err := modulecatalog.AnchorOfDelivery(manifests)
	if err != nil {
		return ctx, nil, err
	}
	census, err := seed.AssertCatalogParity(ctx, kanamepg.NewCatalogRepo(pool), anchor)
	if err != nil {
		return ctx, nil, fmt.Errorf("authority-protocol full installed catalog: %w", err)
	}
	expected, err := granteffect.NewBundle(ctx, model.text, census.Halves(), granteffect.ProjectorVersion, model.report.KeyTerms...)
	if err != nil {
		return ctx, nil, err
	}
	installed, err := repository.LoadAuthorityBundle(ctx, model.text, model.report.KeyTerms...)
	if err != nil {
		return ctx, nil, fmt.Errorf("authority-protocol full installed bundle: %w", err)
	}
	if installed.Identity() != expected.Identity() {
		return ctx, nil, fmt.Errorf("authority-protocol full installed identity differs from delivered model/catalog")
	}
	contract, err := kanamepg.NewFullWriterContract(ctx, repository, expected)
	if err != nil {
		return ctx, nil, fmt.Errorf("authority-protocol full writer contract: %w", err)
	}
	tagged, err := repository.WithFullWriterContract(contract)
	if err != nil {
		return ctx, nil, err
	}
	return contract.Context(ctx), &fullStartupProfile{contract: contract, primary: tagged, bundle: expected, manifests: manifests, model: model}, nil
}

// Эти ЖЕ handle возвращаются serve для login lane и фонового reconciler.
// Они не пересоздаются после public composition и не заменяются legacy store.
type fullStartupParticipants struct {
	membership *kanamepg.GroupMembershipParticipant
	admission  *kanamepg.HumanAdmissionParticipant
	invites    *kanamepg.InviteDecisions
	cluster    *kanamepg.ClusterAdminParticipant
	resources  *kanamepg.ResourceObjectParticipant
	objects    *reconcile.Reconciler
	groups     *reconcile.Reconciler
	bindings   reconcile.StagedBindingReconciler
}

// Единственная production composition полного public контракта. Каждая фабрика
// получает tagged repository; immutable profile сам не является DB authority.
func wireFullStartupServices(ctx context.Context, profile *fullStartupProfile, repo *kanamepg.Repository, svcs *services, pool *pgxpool.Pool, roleDependencies ...*kanamepg.RolePolicyWriters) (*fullStartupParticipants, error) {
	if profile == nil || profile.contract == nil || repo == nil || svcs == nil || pool == nil {
		return nil, fmt.Errorf("authority-protocol full service composition is incomplete")
	}
	if svcs.internalIAMHandler == nil {
		return nil, fmt.Errorf("authority-protocol full internal IAM handler is absent")
	}
	// Отдельная role-зависимость необязательна. Ошибка явно переданной
	// зависимости не разрешает тихий возврат к общему runtime LOGIN.
	if len(roleDependencies) > 1 {
		return nil, fmt.Errorf("authority-protocol role dependency is ambiguous")
	}
	var roleWriters *kanamepg.RolePolicyWriters
	if len(roleDependencies) == 1 {
		roleWriters = roleDependencies[0]
		if err := roleWriters.ValidateFor(repo, profile.bundle); err != nil {
			return nil, fmt.Errorf("authority-protocol role dependency: %w", err)
		}
	}
	if svcs.accessBindingHandler == nil || svcs.roleHandler == nil || svcs.groupHandler == nil ||
		svcs.grantDelegationCreate == nil || svcs.grantDelegationUpdate == nil || svcs.grantDelegationRevoke == nil || svcs.fullModuleHandler == nil ||
		svcs.accountMetadataUpdate == nil || svcs.projectMetadataUpdate == nil || svcs.serviceAccountMetadataUpdate == nil || svcs.serviceAccountEnable == nil || svcs.serviceAccountDisable == nil {
		return nil, fmt.Errorf("authority-protocol full public handlers are absent")
	}
	if svcs.accountCreate == nil ||
		svcs.accountDelete == nil ||
		svcs.projectCreate == nil ||
		svcs.projectDelete == nil ||
		svcs.serviceAccountCreate == nil ||
		svcs.serviceAccountDelete == nil ||
		svcs.roleDelete == nil {
		return nil, fmt.Errorf("authority-protocol full CRUD handlers are absent")
	}
	if svcs.resourceRegistrar == nil || svcs.resourceGate == nil {
		return nil, fmt.Errorf("authority-protocol full resource composition is incomplete")
	}
	moduleHandler, err := svcs.fullModuleHandler(profile.contract)
	if err != nil {
		return nil, err
	}
	if moduleHandler == nil {
		return nil, fmt.Errorf("authority-protocol full module handler is absent")
	}
	svcs.moduleHandler = moduleHandler
	if profile.publication != nil {
		return wirePublishedFullStartupServices(ctx, profile.publication, svcs)
	}
	// Те же участники, что staged serve; full-ветка строит их из fullRepo.
	membership, err := kanamepg.NewGroupMembershipParticipant(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	stages, err := membership.NewBindingStageParticipant(ctx, slog.Default())
	if err != nil {
		return nil, err
	}
	resources, err := kanamepg.NewResourceObjectParticipant(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	resourceDecisions, err := kanamepg.NewResourceDecisionRunner(ctx, repo, profile.bundle, svcs.resourceGate)
	if err != nil {
		return nil, err
	}
	objects, err := resourceDecisions.NewObjectReconciler(slog.Default())
	if err != nil {
		return nil, err
	}
	groups, err := membership.NewGroupObjectReconciler(slog.Default())
	if err != nil {
		return nil, err
	}
	cluster, err := kanamepg.NewClusterAdminParticipant(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	admission, err := kanamepg.NewHumanAdmissionParticipant(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	invites, err := kanamepg.NewInviteDecisionRunner(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	// Тот же gate, что у публичного handler: полномочия заново судит prepared attempt.
	if err = svcs.resourceRegistrar.WithResourceDecisionRunner(resourceDecisions); err != nil {
		return nil, err
	}
	objects.WithSizeRecorder(svcs.bindingSizeRecorder)
	if err = svcs.bindingReconciler.WithObjectReconciler(objects); err != nil {
		return nil, err
	}
	svcs.internalClusterHandler.WithAdminTxBeginner(cluster)
	svcs.userHandler.WithIdentityLifecycleWriter(admission)
	svcs.userInvite.WithInviteDecisions(invites)
	svcs.groupHandler.WithMembershipWriter(membership).WithLifecycleWriter(membership)
	if err = svcs.bindingReconciler.WithStagedBindingReconciler(stages); err != nil {
		return nil, err
	}
	if err = svcs.bindingReconciler.WithGroupObjectReconciler(groups); err != nil {
		return nil, err
	}
	writers, err := kanamepg.NewGrantPolicyWriters(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	delegated, err := kanamepg.NewGrantDelegationParticipant(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	withdrawal, err := kanamepg.NewGrantDelegationRevokeParticipant(ctx, stages)
	if err != nil {
		return nil, err
	}
	metadata, err := kanamepg.NewMetadataMutationWriters(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	metadataPorts, err := metadata.WithInstalledAccessLabels(ctx)
	if err != nil {
		return nil, fmt.Errorf("metadata access label installation: %w", err)
	}
	// Правка метаданных и CRUD используют разные программы записи.
	svcs.accountMetadataUpdate.WithAccountMetadataWriter(metadataPorts)
	svcs.projectMetadataUpdate.WithProjectMetadataWriter(metadataPorts)
	svcs.serviceAccountMetadataUpdate.WithServiceAccountMetadataWriter(metadataPorts)
	state, err := kanamepg.NewServiceAccountStateWriters(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	svcs.serviceAccountEnable.WithServiceAccountStateWriter(state)
	svcs.serviceAccountDisable.WithServiceAccountStateWriter(state)
	crud, err := kanamepg.NewCRUDWriters(ctx, repo, profile.bundle)
	if err != nil {
		return nil, err
	}
	svcs.accountCreate.WithAccountCreateWriter(crud)
	svcs.accountDelete.WithAccountDeleteWriter(crud)
	svcs.projectCreate.WithProjectCreateWriter(crud)
	svcs.projectDelete.WithProjectDeleteWriter(crud)
	svcs.serviceAccountCreate.WithServiceAccountCreateWriter(crud)
	svcs.serviceAccountDelete.WithServiceAccountDeleteWriter(crud)
	svcs.roleDelete.WithRoleDeleteWriter(crud)
	svcs.accessBindingHandler.WithBindingDecisions(writers).WithBindingWithdrawal(stages)
	if roleWriters == nil {
		svcs.roleHandler.WithRoleAuthorityWriter(writers)
	} else {
		svcs.roleHandler.WithRoleAuthorityWriter(roleWriters)
	}
	svcs.groupHandler.WithGroupAdditionAuthorityWriter(writers)
	svcs.grantDelegationCreate.WithAuthorityWriter(delegated)
	svcs.grantDelegationUpdate.WithAuthorityWriter(delegated)
	svcs.grantDelegationRevoke.WithRevokeAuthorityWriter(withdrawal)
	// Публичная регистрация потомка получает тот же FULL runner и runtime repo.
	// До завершения этой сборки поле пусто, поэтому слушатель не объявляет RPC.
	svcs.childRegistrationHandler = childregistrationapp.NewHandler(internaliamapp.NewUserChildRegistration(resourceDecisions))
	// Закрытие родителя получает тот же FULL runner только на внутренней службе.
	svcs.internalIAMHandler.WithChildParentClose(resourceDecisions)
	return &fullStartupParticipants{membership: membership, admission: admission, invites: invites,
		cluster: cluster, resources: resources, objects: objects, groups: groups, bindings: stages}, nil
}

func wirePublishedFullStartupServices(ctx context.Context, publication *publishedStartupProfile, svcs *services) (*fullStartupParticipants, error) {
	writers := publication.writers
	if err := writers.installResourceGate(ctx, svcs.resourceGate); err != nil {
		return nil, err
	}
	// Маршрутизатор сам выбирает движок одного поколения для ресурса или группы.
	objects, err := reconcile.NewObjectDecisionReconciler(writers, slog.Default(), catalog.Fixed{F: publication.snapshot.Facts})
	if err != nil {
		return nil, err
	}
	if err := svcs.resourceRegistrar.WithResourceDecisionRunner(writers); err != nil {
		return nil, err
	}
	if err := wireObjectAndBindingAuthorityParticipants(svcs.bindingReconciler, writers, objects); err != nil {
		return nil, err
	}
	svcs.internalClusterHandler.WithAdminTxBeginner(writers)
	svcs.userHandler.WithIdentityLifecycleWriter(writers)
	svcs.userInvite.WithInviteDecisions(writers)
	svcs.groupHandler.WithMembershipWriter(writers).WithLifecycleWriter(writers).WithGroupAdditionAuthorityWriter(writers)
	svcs.accountMetadataUpdate.WithAccountMetadataWriter(writers)
	svcs.projectMetadataUpdate.WithProjectMetadataWriter(writers)
	svcs.serviceAccountMetadataUpdate.WithServiceAccountMetadataWriter(writers)
	svcs.serviceAccountEnable.WithServiceAccountStateWriter(writers)
	svcs.serviceAccountDisable.WithServiceAccountStateWriter(writers)
	svcs.accountCreate.WithAccountCreateWriter(writers)
	svcs.accountDelete.WithAccountDeleteWriter(writers)
	svcs.projectCreate.WithProjectCreateWriter(writers)
	svcs.projectDelete.WithProjectDeleteWriter(writers)
	svcs.serviceAccountCreate.WithServiceAccountCreateWriter(writers)
	svcs.serviceAccountDelete.WithServiceAccountDeleteWriter(writers)
	svcs.roleDelete.WithRoleDeleteWriter(writers)
	svcs.accessBindingHandler.WithBindingDecisions(writers).WithBindingWithdrawal(writers)
	svcs.roleHandler.WithRoleAuthorityWriter(writers)
	svcs.grantDelegationCreate.WithAuthorityWriter(writers)
	svcs.grantDelegationUpdate.WithAuthorityWriter(writers)
	svcs.grantDelegationRevoke.WithRevokeAuthorityWriter(writers)
	svcs.childRegistrationHandler = childregistrationapp.NewHandler(internaliamapp.NewUserChildRegistration(writers))
	svcs.internalIAMHandler.WithChildParentClose(writers)
	return &fullStartupParticipants{objects: objects, bindings: writers}, nil
}

// Общая настоящая провязка фоновой очереди. Вызывается serve и native holder;
// configured nil по-прежнему ошибка, не молчаливый legacy fallback.
func wireBackgroundAuthorityParticipants(engine *reconcile.Reconciler, bindings reconcile.StagedBindingReconciler,
	objects *reconcile.Reconciler, groups *reconcile.Reconciler) error {
	if groups == nil {
		return fmt.Errorf("authority-protocol background group participant is absent")
	}
	if err := wireObjectAndBindingAuthorityParticipants(engine, bindings, objects); err != nil {
		return err
	}
	return engine.WithGroupObjectReconciler(groups)
}

func wireObjectAndBindingAuthorityParticipants(engine *reconcile.Reconciler, bindings reconcile.StagedBindingReconciler,
	objects *reconcile.Reconciler) error {
	if engine == nil || bindings == nil || objects == nil {
		return fmt.Errorf("authority-protocol background participants are incomplete")
	}
	if err := engine.WithStagedBindingReconciler(bindings); err != nil {
		return err
	}
	// Повторно используем engine выбранного startup profile; FULL не откатывается к legacy factory.
	return engine.WithObjectReconciler(objects)
}
