// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_profiles.go — ЗАКРЫТЫЕ ПЕРЕЧНИ методов внутреннего слушателя на каждый
// профиль личности модуля (kaname#984).
//
// # Предмет
//
// Прежде пол внутреннего слушателя отвечал на один вопрос — «проверенный ли это
// модуль». Ответ «да» открывал ВСЕ методы, кроме круга края и чеканки, в том
// числе освобождённые от проверки отношений: модуль плоскости данных доставал до
// разбора базовых удостоверений, до опроса изменений субъектов и до записи
// отношений, хотя ни одно из них ему не нужно. Освобождение от проверки
// отношений означает «вопроса к модели здесь нет», а не «звать вправе всякий».
//
// Теперь у каждой личности — профиль, а у профиля — перечень. Метод вне перечня
// отвергается до обработчика, какой бы ни была запись метода в каталоге.
//
// # Откуда взяты перечни — замер, а не допущение
//
// Вызывающие внутреннего слушателя перемерены по дереву платформы
// (2026-10-26): модули-владельцы ресурсов зовут ровно `RegisterResource`,
// `UnregisterResource` и `Check` службы доступа и `Check`/`BatchCheck`
// службы решений; край — фронтируемые им глаголы и горячие пути предъявления
// (разбор и живость базовых удостоверений, отзыв сессии, сессия человека,
// поток изменений, решения о доступе). Плоскости данных нужен один вопрос о
// доступе; сужение его области — kaname#987 и kaname#943.
//
// Чеканка (`MintBootstrapToken`) не входит ни в один профиль: её судит рукав
// точных идентификаторов, стоящий выше и терминально.
package authzguard

import (
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
)

// Методы внутреннего слушателя, которые называют перечни профилей. Полные имена
// объявлены здесь один раз: перечни ссылаются на имена, а не повторяют строки.
const (
	internalCheckMethod                = "/kaname.cloud.iam.v1.InternalIAMService/Check"
	internalLookupSubjectMethod        = "/kaname.cloud.iam.v1.InternalIAMService/LookupSubject"
	internalPollSubjectChangesMethod   = "/kaname.cloud.iam.v1.InternalIAMService/PollSubjectChanges"
	internalRegisterResourceMethod     = "/kaname.cloud.iam.v1.InternalIAMService/RegisterResource"
	internalUnregisterResourceMethod   = "/kaname.cloud.iam.v1.InternalIAMService/UnregisterResource"
	internalResolveBasicMethod         = "/kaname.cloud.iam.v1.InternalIAMService/ResolveBasicCredential"
	internalGetRoleCompiledMethod      = "/kaname.cloud.iam.v1.InternalIAMService/GetRoleCompiled"
	internalCheckBasicLiveMethod       = "/kaname.cloud.iam.v1.InternalIAMService/CheckBasicCredentialLive"
	internalIsRevokedMethod            = "/kaname.cloud.iam.v1.InternalSessionRevocationsService/IsRevoked"
	internalSessionCutoffOfMethod      = "/kaname.cloud.iam.v1.InternalSessionRevocationsService/SessionCutoffOf"
	internalUserGetMethod              = "/kaname.cloud.iam.v1.InternalUserService/Get"
	internalHumanSessionResolveMethod  = "/kaname.cloud.iam.v1.InternalHumanSessionService/Resolve"
	internalSubscribeMethod            = "/corelib.subscription.InternalSubscriptionService/Subscribe"
	authorizeCheckFullMethod           = "/kaname.cloud.iam.v1.AuthorizeService/Check"
	authorizeBatchCheckFullMethod      = "/kaname.cloud.iam.v1.AuthorizeService/BatchCheck"
	authorizeListSubjectsFullMethod    = "/kaname.cloud.iam.v1.AuthorizeService/ListSubjects"
	authorizeExpandRelationsFullMethod = "/kaname.cloud.iam.v1.AuthorizeService/ExpandRelations"
	authorizeWhoAmIFullMethod          = "/kaname.cloud.iam.v1.AuthorizeService/WhoAmI"
)

// ProfileMethods — закрытый перечень методов внутреннего слушателя профиля p.
// Неизвестный профиль — пустой перечень: по нему не открыт ни один метод.
func ProfileMethods(p moduleidentity.Profile) []string {
	switch p {
	case moduleidentity.ProfileEdge:
		return append(GatewayFrontedInternalRPCs(),
			internalCheckMethod,
			internalLookupSubjectMethod,
			internalPollSubjectChangesMethod,
			internalResolveBasicMethod,
			internalGetRoleCompiledMethod,
			internalCheckBasicLiveMethod,
			internalIsRevokedMethod,
			internalSessionCutoffOfMethod,
			internalUserGetMethod,
			internalHumanSessionResolveMethod,
			internalSubscribeMethod,
			authorizeCheckFullMethod,
			authorizeBatchCheckFullMethod,
			authorizeListSubjectsFullMethod,
			authorizeExpandRelationsFullMethod,
			authorizeWhoAmIFullMethod,
		)
	case moduleidentity.ProfileModuleWriter:
		return []string{
			internalRegisterResourceMethod,
			internalUnregisterResourceMethod,
			internalCheckMethod,
			authorizeCheckFullMethod,
			authorizeBatchCheckFullMethod,
		}
	case moduleidentity.ProfileDataPlane:
		return []string{internalCheckMethod}
	default:
		return nil
	}
}

// profileMethodSets — перечни всех профилей словаря множествами: строятся один
// раз при сборке стража.
func profileMethodSets() map[moduleidentity.Profile]map[string]struct{} {
	out := make(map[moduleidentity.Profile]map[string]struct{}, len(moduleidentity.Profiles()))
	for _, p := range moduleidentity.Profiles() {
		methods := ProfileMethods(p)
		set := make(map[string]struct{}, len(methods))
		for _, m := range methods {
			set[m] = struct{}{}
		}
		out[p] = set
	}
	return out
}
