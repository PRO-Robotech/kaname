// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// public_id_form.go — судья формы идентификатора для звена публичного
// слушателя (`authzguard.OwnDoor.FormUnary`, kaname#168).
//
// Судья — та же функция, которой отвечают обработчики службы
// (`shared.ValidateResourceID`): приставка ОЖИДАЕМОГО вида, затем длина
// чеканной формы либо закрытый перечень посеянного. Второй копии правила
// здесь нет — есть лишь отображение «вид объекта двери → приставка и имя вида
// в тексте отказа», которого у двери нет: она знает вид модели, обработчик —
// приставку и имя. Живёт отображение в корне, потому что корень уже зависит от
// прикладного пакета формы, а транспортный страж — нет и не должен.

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// idFormOf — вид объекта двери → приставка собственного идентификатора и имя
// вида в тексте отказа (таблица §11.3 приёмки). Имя — побайтово то, которым
// обработчики службы называют свой идентификатор.
//
// Приставка возвращается только селектором `domain.Prefix…`: так её признаёт
// страж `TestStrictIDFormatCheckStaysOwnerScoped` — строгая форма судит лишь
// СВОЙ идентификатор.
func idFormOf(objectType string) (prefix, name string, ok bool) {
	switch objectType {
	case "project":
		return domain.PrefixProject, "project", true
	case "account":
		return domain.PrefixAccount, "account", true
	case "iam_user":
		return domain.PrefixUser, "user", true
	case "iam_service_account":
		return domain.PrefixServiceAccount, "service account", true
	case "iam_group":
		return domain.PrefixGroup, "group", true
	case "iam_role":
		return domain.PrefixRole, "role", true
	case "iam_access_binding":
		return domain.PrefixAccessBinding, "access binding", true
	}
	return "", "", false
}

// publicIDForm — реализация порта `authzguard.IDFormJudge`.
type publicIDForm struct{}

// Judges — знает ли судья форму вида. Звено спрашивает это при сборке по
// каждому виду своего класса и отказывает в сборке на незнакомом.
func (publicIDForm) Judges(objectType string) bool {
	_, _, ok := idFormOf(objectType)
	return ok
}

// Check — форма идентификатора objectID объекта вида objectType.
//
// Незнакомый вид сюда не приходит: звено не собирается, если судья не знает
// вида хоть одного глагола класса. Ветвь всё же отвечает отказом, а не
// пропуском: пропуск выдал бы незнакомый вид за годную форму.
func (publicIDForm) Check(objectType, objectID string) error {
	prefix, name, ok := idFormOf(objectType)
	if !ok {
		return status.Error(codes.Internal, "internal error")
	}
	return shared.ValidateResourceID(objectID, prefix, name)
}
