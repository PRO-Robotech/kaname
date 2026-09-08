// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// jobs.go — секция фоновых заданий сервиса (задача #1264).
//
// # Почему СЕКЦИЯ, а не константы
//
// Первая редакция приёмки объявляла обе величины константами и обосновывала это
// замером: ни один профиль развёртывания не задаёт ни одного интервала фоновой
// работы, значит ручка была бы без читателя. Неверен и вывод, и сам замер.
//
// Вывод: читатель у такой ручки ЕСТЬ — это код, берущий значение; профиль же
// просто пользуется умолчанием, и место умолчаний для того и заведено. «Ручкой
// без читателя» называется ключ, которого не читает НИКТО, а не ключ, который
// никто не переопределил.
//
// Решает ближайший ПРЕЦЕДЕНТ того же класса — платформа, удаляющая РЕСУРС
// АРЕНДАТОРА по времени. Он в дереве один: сметатель целей nlb
// (`services/nlb/internal/apps/kacho/config/config.go`, секция `jobs.target-drain`
// с умолчанием и стражем старта, отвергающим неположительный интервал). Здесь
// заводится такая же секция.
//
// # Что при этом остаётся долгом сервиса и в объём НЕ берётся
//
// Прочие фоновые петли iam держат интервалы константами либо переменными
// окружения в композиционном корне, и ни одна не проверяется стражем старта. Это
// долг сервиса, а не довод против секции: работа заводит секцию с ОДНОЙ записью
// и чужие петли не трогает.
package config

import (
	"fmt"
	"time"

	"go.uber.org/multierr"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
)

// JobsConfig — фоновые задания.
type JobsConfig struct {
	ExpiredCredentialReclaim ExpiredCredentialReclaimConfig `mapstructure:"expired-credential-reclaim"`
	// CatalogSnapshot — обновление снимка каталога модуля (задача #1816).
	CatalogSnapshot CatalogSnapshotConfig `mapstructure:"catalog-snapshot"`
}

// CatalogSnapshotConfig — обновление снимка каталога модуля в процессе.
//
// # Что за снимок
//
// Каталожный факт — какие пары «модуль.ресурс» грантуемы и какие глаголы
// объявлены — читается из строк `kaname.catalog_*` и держится в памяти:
// спрашивают его на горячих путях (создание и правка роли, пересчёт проекции,
// сборка кортежей), а сам он мал и меняется реже всего в схеме. Запрос к базе на
// каждом обращении оплачивался бы запросом арендатора.
//
// # Почему величина ЗДЕСЬ, а не константой в корне
//
// Период обновления И ЕСТЬ верхняя граница отставания снимка от базы: столько
// снятый ресурс продолжает считаться живым. Вшитая величина есть решение,
// принятое за оператора и ему не предъявленное.
type CatalogSnapshotConfig struct {
	// RefreshInterval — как часто снимок перечитывает живое множество.
	//
	// Ноль здесь НЕ означает «выключено»: выключенного обновления у снимка не
	// бывает — снимок без обновления отстаёт бессрочно, а строки каталога
	// снимаются в работающем процессе. Непозитивная величина отвергается стражем
	// старта, а не понимается как выключатель.
	RefreshInterval time.Duration `mapstructure:"refresh-interval"`
}

// Validate — страж старта секции.
//
// Отказ в старте, а не тихое подтягивание к умолчанию: подтягивание оставило бы
// оператора в уверенности, что действует написанная им величина, тогда как
// действует другая.
func (c CatalogSnapshotConfig) Validate() error {
	if c.RefreshInterval <= 0 {
		return fmt.Errorf(
			"jobs.catalog-snapshot.refresh-interval is %s — must be positive: "+
				"a non-positive interval is not 'disabled', it is a snapshot that lags "+
				"forever while answering as if it were current (kacho#1816)", c.RefreshInterval)
	}
	return nil
}

// ExpiredCredentialReclaimConfig — снятие истёкших удостоверений.
type ExpiredCredentialReclaimConfig struct {
	// Enabled — ВЫКЛЮЧАТЕЛЬ ЯВНЫЙ, а не «ноль значит выключено».
	//
	// Ноль двусмыслен — «не задано» или «выключено», — и различие между ними у
	// величин уже стоило продукту отдельного разбора. В форме прецедента
	// нулевой интервал означает УМОЛЧАНИЕ, то есть очевидная попытка выключить
	// уборщик его бы включила.
	Enabled bool `mapstructure:"enabled"`

	// Interval — как часто идёт прогон.
	//
	// Час: погрешность около четырёх процентов от суточной отсрочки. Соседний
	// уборщик секретов работает раз в минуту, потому что его предмет измеряется
	// минутами; здесь предмет измеряется сутками.
	Interval time.Duration `mapstructure:"interval"`

	// Grace — ВЕРХНЯЯ отсрочка снятия. Действующая отсрочка строки связана с её
	// собственным сроком и никогда не превышает эту.
	//
	// Ручка существует для эксплуатации, а безопасную область очерчивает СТРАЖ,
	// а не осторожность того, кто её правит: величина ниже вычисляемой нижней
	// границы отвергается при старте.
	Grace time.Duration `mapstructure:"grace"`

	// BatchSize — строк на таблицу за прогон. Партия ограничивает длительность
	// транзакции: первый прогон после выкатки снимает накопленное за всю жизнь
	// кластера, и одним оператором этого делать нельзя.
	BatchSize int `mapstructure:"batch-size"`

	// DryRun — показ без снятия.
	//
	// Необратимое действие, впервые встречающееся с боевым кластером, обязано
	// иметь дешёвый способ спросить «что ты снесёшь».
	DryRun bool `mapstructure:"dry-run"`
}

// MinGrace — вычисляемая нижняя граница отсрочки при ДЕЙСТВУЮЩЕМ сроке докерного
// токена.
//
// Срок берётся из живой конфигурации, а не константой: он конфигурируем, и страж
// обязан считать границу по действующему значению. Иначе поднятый срок молча
// вывел бы отсрочку из-под её же основания.
func (c ExpiredCredentialReclaimConfig) MinGrace(registryTokenTTL time.Duration) time.Duration {
	return tokenpolicy.MinExpiredCredentialReclaimDelay(registryTokenTTL)
}

// Validate — страж старта секции.
//
// Отказ в старте, а не подтягивание величины до безопасной: тихая поправка
// оставила бы оператора в уверенности, что действует то, что он написал.
func (c ExpiredCredentialReclaimConfig) Validate(registryTokenTTL time.Duration) error {
	if !c.Enabled {
		// Выключенный уборщик проверять нечего — но молчать о нём нельзя:
		// молча выключенная уборка неотличима от работающей, у которой нечего
		// снимать. Об этом говорит композиционный корень при старте.
		return nil
	}
	var errs error
	if c.Interval <= 0 {
		errs = multierr.Append(errs, fmt.Errorf(
			"jobs.expired-credential-reclaim.interval is %s — must be positive: "+
				"a non-positive interval is not 'disabled', it is a loop that never runs "+
				"while reporting itself as enabled", c.Interval))
	}
	if c.BatchSize <= 0 {
		errs = multierr.Append(errs, fmt.Errorf(
			"jobs.expired-credential-reclaim.batch-size is %d — must be positive: "+
				"the batch bounds the transaction, and the first pass after a rollout "+
				"removes what the cluster accumulated over its whole life", c.BatchSize))
	}
	if floor := c.MinGrace(registryTokenTTL); c.Grace < floor {
		errs = multierr.Append(errs, fmt.Errorf(
			"jobs.expired-credential-reclaim.grace is %s, below the computed floor %s "+
				"(clock skew %s + registry token ttl %s + removal slack %s) — "+
				"below the floor the tokens minted by the row being removed are still alive, "+
				"so the sweep would cut live access",
			c.Grace, floor, tokenpolicy.ClockSkew, registryTokenTTL, tokenpolicy.RemovalSlack))
	}
	return errs
}
