// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Команда iamctl — инструмент оператора над каталогом прав модуля: пять
// действий, не двенадцать (задача #1036).
//
//	iamctl validate [-root=КАТАЛОГ]                   форма манифестов дерева
//	iamctl plan МОДУЛЬ                                последствия числом + отпечаток
//	iamctl apply МОДУЛЬ -expected-state=ОТПЕЧАТОК     применение под отпечаток
//	iamctl export {МОДУЛЬ | -all}                     действующий каталог
//	iamctl doctor                                     разбор состояния предикатом
//
// ТОНКАЯ: разбор вызова, классификация чужого отказа, тексты и коды возврата
// живут в services/iam/internal/iamctl; локальная проверка дерева — в
// services/iam/internal/manifestcheckrun, том же исполнителе, что зовёт
// сборочная цель module-manifest-check. Здесь — только флаги посадки и вызов.
//
// Прецедент формы — соседи по каталогу: migrator и authzmap-tables.
//
// # Почему у validate нет ни адреса, ни удостоверения
//
// Он обязан идти в pre-commit, то есть там, где ни кластера, ни сертификатов нет
// вовсе. Посадка разбирается ВНУТРИ соединения и только теми действиями, которым
// служба нужна; разбор её на старте отнял бы у validate эту способность.
//
// # Коды возврата
//
//	0  годно
//	1  находка — вердикт о предмете получен, и он отрицательный
//	2  VOID    — предмета нет: проверять и выгружать нечего
//	3  НЕ ИСПОЛНЯЛОСЬ — вердикта не получено вовсе
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PRO-Robotech/kacho/services/iam/internal/iamctl"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifestcheckrun"
)

func main() {
	// Флаги посадки разбираются ДО действия и его собственных флагов: у
	// действий свои наборы, и общий набор с ними не смешивается.
	fs := flag.NewFlagSet("iamctl", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	endpoint := fs.String("endpoint", envOr("KACHO_IAMCTL_ENDPOINT", ""),
		"адрес ВНУТРЕННЕГО слушателя iam (:9091): глаголы каталога модуля внешним маршрутизатором не обслуживаются")
	serverName := fs.String("server-name", envOr("KACHO_IAMCTL_SERVER_NAME", ""),
		"имя, сверяемое с SAN сертификата службы")
	caFiles := fs.String("ca", envOr("KACHO_IAMCTL_CA_FILES", ""),
		"корни доверия через запятую: ими проверяется сертификат службы")
	certFile := fs.String("cert", envOr("KACHO_IAMCTL_CERT_FILE", ""),
		"СВОЁ удостоверение: служба решает по личности вызывающего, а не по факту достижимости")
	keyFile := fs.String("key", envOr("KACHO_IAMCTL_KEY_FILE", ""),
		"ключ к своему удостоверению")
	timeout := fs.Duration("timeout", 30*time.Second,
		"срок КАЖДОГО вызова службы")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "iamctl — инструмент оператора над каталогом прав модуля.")
		fmt.Fprintln(os.Stderr, "  iamctl [флаги посадки] ДЕЙСТВИЕ [аргументы действия]")
		fmt.Fprintln(os.Stderr, "Действий пять: validate · plan · apply · export · doctor.")
		fmt.Fprintln(os.Stderr, "Флаги посадки:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		// Разбор у ContinueOnError уже напечатал причину; код возврата свой,
		// потому что двойка занята исходом «предмета нет».
		os.Exit(iamctl.ExitNotRun)
	}

	deps := iamctl.Deps{
		Endpoint: *endpoint,
		Connect: iamctl.Connector(iamctl.DialConfig{
			Endpoint:   *endpoint,
			ServerName: *serverName,
			CAFiles:    splitList(*caFiles),
			CertFile:   *certFile,
			KeyFile:    *keyFile,
			Timeout:    *timeout,
		}),
		Validate: manifestcheckrun.Run,
	}
	os.Exit(iamctl.Run(context.Background(), fs.Args(), os.Stdout, os.Stderr, deps))
}

// envOr — умолчание из окружения: инструмент запускается Job'ом, и переменные
// посадки удобнее монтировать, чем собирать строку вызова.
func envOr(name, fallback string) string {
	if v, ok := os.LookupEnv(name); ok {
		return v
	}
	return fallback
}

// splitList — перечень путей через запятую, без пустых записей.
//
// Пустые отбрасываются НАМЕРЕННО: одинокая запятая дала бы список длиной один и
// нулём записей, то есть «непустой» для того, кто считает символы, и пустой для
// того, кто читает записи. Считает записи один и тот же разбор.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
