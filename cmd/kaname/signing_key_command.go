// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// signing_key_command.go — жизненный цикл ключа подписи, достижимый
// ОПЕРАТОРОМ (#314).
//
//	kaname signing-key compromise -kid=KID -decided-by=КТО   реакция на утечку
//	kaname signing-key retire     -kid=KID -decided-by=КТО   вывод из обращения
//
// # Почему команда процесса, а не вызов службы
//
// Реакция на утечку ключа подписи нужна именно тогда, когда поверхности,
// которым служба доверяет, под вопросом. Команда идёт тем же путём, каким идёт
// служба: та же настройка, тот же страж посадки до первого соединения с базой,
// та же ключница с проверкой ключа обёртки — и меняет ТУ ЖЕ строку, которую
// читают публикатор и подписант каждой реплики. Своей копии набора у реплик нет,
// поэтому снятый ключ уходит из ответа публикатора со следующим запросом.
//
// Одно отличие от старта службы НЕСУЩЕЕ: команда подписывающего до глагола не
// заводит. Иначе повтор после частичного исхода утечки лечил бы подпись раньше
// глагола, и глагол отвечал бы «уже сделано», не назвав замены, а отказ по
// ключу менял бы набор.
//
// # Предел
//
// Вся команда — связь с базой, чтение набора, переход и порождение замены —
// идёт под одним своим пределом (signingKeyCommandTimeout). Предел запроса у
// пула ограничивает запрос лишь при живой связи с сервером; зависшая сеть
// иначе держала бы реакцию на утечку до сигнала без единого кода возврата.
//
// Право на действие — обладание настройкой службы: адресом и удостоверением её
// базы и ключом обёртки. Это то же, что даёт право поднять саму службу, и
// меньшего здесь не выражается — и не должно.
//
// # Коды возврата
//
//	0  сделано — или уже было сделано (повтор команды не отказ); у утечки
//	   также — замена этим вызовом не легла, но подписывающий прочитан после
//	   отказа (`signer=<kid>`): служба подписывает;
//	1  отказ по существу — ключа нет, переход не допускается, либо ЧАСТИЧНЫЙ
//	   исход утечки: ключ снят, замена не заведена и подписывающего нет — это
//	   прочитано после отказа замены (повтор довершает);
//	3  вердикта нет — вызов не разобран, посадка не принята, база или
//	   ключница недоступны, истёк предел команды; у утечки также — ключ снят,
//	   а подписывает ли служба, не установлено (`outcome=signer-unknown`,
//	   повтор прочитает и при нужде довершит).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Коды возврата команды.
const (
	signingKeyExitDone    = 0
	signingKeyExitRefused = 1
	signingKeyExitNotRun  = 3
)

// signingKeyCommandName — имя подкоманды процесса.
const signingKeyCommandName = "signing-key"

// signingKeyCommandTimeout — предел ВСЕЙ команды.
//
// Работы у команды не больше, чем у одного прохода обслуживания
// (signingKeyPassTimeout): одна связь, чтение набора, переход и, если подпись
// переходит, порождение ключа с его записью. Минута много больше этого — и с
// порождением ключа RSA — и короче того, что оператор в разгар утечки готов
// ждать, не зная исхода.
const signingKeyCommandTimeout = time.Minute

// signingKeyCommandLimitExpired — причина отмены, когда кончился предел САМОЙ
// команды. Отдельная причина, а не общий срок контекста: отказ хранилища на
// отменённом запросе приезжает кодом состояния сервера и о сроке не говорит,
// а оператор обязан узнать, что кончилось ожидание команды, а не что база
// отказала.
type signingKeyCommandLimitExpired struct{ limit time.Duration }

func (e signingKeyCommandLimitExpired) Error() string {
	return fmt.Sprintf("предел команды %s истёк", e.limit)
}

const signingKeyUsage = "kaname signing-key {compromise|retire} -kid=KID -decided-by=КТО\n" +
	"  compromise — ключ утёк: покидает набор НЕМЕДЛЕННО, подписанные им токены отвергаются;\n" +
	"               если он подписывал, подпись переходит к новому ключу\n" +
	"  retire     — вывод из обращения: ключ перестаёт подписывать и остаётся в наборе на отсрочку\n" +
	"Коды возврата: 0 сделано · 1 отказ по существу · 3 не исполнялось"

// runSigningKeyCommand исполняет подкоманду и возвращает код возврата.
//
// Разбор вызова идёт ДО любого соединения: неверно названное действие не
// должно стоить открытия базы, а отказ разбора — «не исполнялось», а не
// «отказ по ключу».
func runSigningKeyCommand(ctx context.Context, cfg config.Config, args []string, out io.Writer, logger *slog.Logger) int {
	return runSigningKeyCommandWithin(ctx, signingKeyCommandTimeout, cfg, args, out, logger)
}

// runSigningKeyCommandWithin — та же команда с пределом на ВХОДЕ.
//
// Предел вынесен в вызов по той же причине, что часы у buildTokenSigningAt:
// проба зависшего хранилища с минутным пределом ждала бы минуту. Производственный
// вызов один — runSigningKeyCommand, и он подаёт объявленный предел.
func runSigningKeyCommandWithin(
	ctx context.Context,
	limit time.Duration,
	cfg config.Config,
	args []string,
	out io.Writer,
	logger *slog.Logger,
) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(out, signingKeyUsage)
		return signingKeyExitNotRun
	}
	action := args[0]
	if action != "compromise" && action != "retire" {
		_, _ = fmt.Fprintf(out, "неизвестное действие %q\n%s\n", action, signingKeyUsage)
		return signingKeyExitNotRun
	}
	fs := flag.NewFlagSet("kaname "+signingKeyCommandName+" "+action, flag.ContinueOnError)
	fs.SetOutput(out)
	rawKID := fs.String("kid", "", "идентификатор ключа — тот, что стоит в заголовке токена и в наборе")
	decidedBy := fs.String("decided-by", "", "кто принял решение: действие такой цены не бывает анонимным")
	if err := fs.Parse(args[1:]); err != nil {
		return signingKeyExitNotRun
	}
	if fs.NArg() > 0 {
		_, _ = fmt.Fprintf(out, "лишние аргументы: %v\n%s\n", fs.Args(), signingKeyUsage)
		return signingKeyExitNotRun
	}
	kid := domain.KeyID(strings.TrimSpace(*rawKID))
	if kid == "" {
		_, _ = fmt.Fprintf(out, "не назван ключ (-kid)\n%s\n", signingKeyUsage)
		return signingKeyExitNotRun
	}
	if err := kid.Validate(); err != nil {
		_, _ = fmt.Fprintf(out, "-kid: %v\n", err)
		return signingKeyExitNotRun
	}
	if strings.TrimSpace(*decidedBy) == "" {
		_, _ = fmt.Fprintf(out, "не назван принявший решение (-decided-by)\n%s\n", signingKeyUsage)
		return signingKeyExitNotRun
	}
	if !cfg.AuthN.TokenSigning.Enabled {
		_, _ = fmt.Fprintln(out, "своя чеканка выключена (authn.token-signing.enabled=false): ключницы нет, действовать не над чем")
		return signingKeyExitNotRun
	}

	// Тот же страж посадки, что у `serve`, и ДО первого соединения: команда,
	// открывшая базу в обход него, прошла бы там, где служба не поднялась бы.
	if _, err := describePosture(cfg, logger); err != nil {
		_, _ = fmt.Fprintf(out, "посадка процесса: %v\n", err)
		return signingKeyExitNotRun
	}
	// Предел — после разбора и стража, ДО первого соединения: всё, что может
	// зависнуть, идёт под ним.
	ctx, cancel := context.WithTimeoutCause(ctx, limit, signingKeyCommandLimitExpired{limit: limit})
	defer cancel()

	pool, err := coredb.NewPool(ctx, cfg.DSN())
	if err != nil {
		_, _ = fmt.Fprintf(out, "база: %v\n", underCommandLimit(ctx, err))
		return signingKeyExitNotRun
	}
	defer pool.Close()
	// Ключница — ТЕМ ЖЕ построением, что у службы, и с той же проверкой, что
	// предъявленный ключ обёртки открывает записанное: замена, порождённая с
	// чужим ключом обёртки, была бы нечитаема каждой репликой. Подписывающего
	// команда здесь НЕ заводит — это дело глагола (шапка файла).
	ks, err := buildKeystoreAt(pool, cfg, time.Now, logger)
	if err == nil {
		err = ks.VerifyWrappingKey(ctx)
	}
	if err != nil {
		_, _ = fmt.Fprintln(out, signingKeyCommandKeystoreRefusal(cfg.AuthN, underCommandLimit(ctx, err)))
		return signingKeyExitNotRun
	}

	var outcome signingkeys.LifecycleOutcome
	switch action {
	case "compromise":
		outcome, err = ks.Compromise(ctx, kid, *decidedBy)
	default:
		outcome, err = ks.Retire(ctx, kid, *decidedBy)
	}
	return reportSigningKeyOutcome(out, action, *decidedBy, outcome, underCommandLimit(ctx, err))
}

// underCommandLimit приписывает к отказу, что кончился предел САМОЙ команды,
// — когда кончился именно он. Иные отказы и успех проходят как есть.
func underCommandLimit(ctx context.Context, err error) error {
	if err == nil {
		return nil
	}
	var expired signingKeyCommandLimitExpired
	if errors.As(context.Cause(ctx), &expired) {
		return fmt.Errorf("%w: %w", expired, err)
	}
	return err
}

// signingKeyCommandKeystoreRefusal — текст отказа ключницы для ОПЕРАТОРА
// команды.
//
// Свой, а не signingKeyStartupRefusal: тот говорит, что служба отказывается
// стартовать, а здесь не стартует ничего — не исполняется команда. Имя ручки и
// переменной берётся из той же настройки: чинить оператору то же самое.
func signingKeyCommandKeystoreRefusal(authn config.AuthNConfig, err error) string {
	if errors.Is(err, signingkeys.ErrWrappingKeyMismatch) {
		return fmt.Sprintf("ключница: ручка authn.jwks-encryption-key-hex (ENV %s) не открывает уже записанные "+
			"подписные ключи — команда не исполнялась: замена, порождённая этим ключом обёртки, была бы "+
			"нечитаема каждой репликой службы. Команде нужна та же настройка, что у службы: %v",
			authn.JWKSEncryptionKeyEnvName(), err)
	}
	return fmt.Sprintf("ключница: %v", err)
}

// reportSigningKeyOutcome печатает исход строкой «ключ=значение» и выбирает код.
//
// Отказ хранилища отделён от отказа по существу: «база не ответила» не
// сообщает о ключе ничего, и читать его как «переход не допускается» значило
// бы подменить третий исход вторым.
func reportSigningKeyOutcome(out io.Writer, action, decidedBy string, o signingkeys.LifecycleOutcome, err error) int {
	line := fmt.Sprintf("%s %s kid=%s decided_by=%q", signingKeyCommandName, action, o.KID, decidedBy)
	if o.Replacement != "" {
		line += " replacement=" + string(o.Replacement)
	}
	if o.Signer != "" {
		// Замена этим вызовом не легла, а подписывающий прочитан после отказа:
		// оператор узнаёт, каким ключом служба подписывает.
		line += " signer=" + string(o.Signer)
	}
	switch {
	case err == nil && o.AlreadyDone:
		_, _ = fmt.Fprintln(out, line+" outcome=already-done")
		return signingKeyExitDone
	case err == nil:
		_, _ = fmt.Fprintln(out, line+" outcome=done")
		return signingKeyExitDone
	case errors.Is(err, signingkeys.ErrNoSignerAfterCompromise):
		_, _ = fmt.Fprintf(out, "%s outcome=partial reason=%q\n"+
			"ключ снят из набора, но замена не заведена — служба не подписывает; повторите команду\n", line, err.Error())
		return signingKeyExitRefused
	case errors.Is(err, signingkeys.ErrSignerUnknownAfterCompromise):
		// Снятие состоялось, о подписи вердикта нет: «служба не подписывает»
		// здесь не установлено и потому не печатается.
		_, _ = fmt.Fprintf(out, "%s outcome=signer-unknown reason=%q\n"+
			"ключ снят из набора, а подписывает ли служба, не установлено; повторите команду — "+
			"повтор прочитает подписывающего и при нужде заведёт замену\n", line, err.Error())
		return signingKeyExitNotRun
	case errors.Is(err, iamerr.ErrNotFound), errors.Is(err, iamerr.ErrFailedPrecondition):
		_, _ = fmt.Fprintf(out, "%s outcome=refused reason=%q\n", line, err.Error())
		return signingKeyExitRefused
	default:
		_, _ = fmt.Fprintf(out, "%s outcome=not-run reason=%q\n", line, err.Error())
		return signingKeyExitNotRun
	}
}
