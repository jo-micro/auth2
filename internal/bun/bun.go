package bun

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-migrate/migrate"
	migratePostgres "github.com/golang-migrate/migrate/database/postgres"
	"github.com/jackc/pgx"
	"github.com/jackc/pgx/log/logrusadapter"
	"github.com/jackc/pgx/stdlib"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/pgdialect"
	"github.com/uptrace/bun/extra/bundebug"

	iLogger "jochum.dev/jo-micro/auth2/internal/logger"

	"github.com/urfave/cli/v2"
)

var initialized = false
var SQLDB *sql.DB
var Bun *bun.DB

func Flags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:    "database-url",
			Usage:   "bun Database URL",
			EnvVars: []string{"DATABASE_URL"},
		},
		&cli.BoolFlag{
			Name:        "database-debug",
			Usage:       "Set it to the debug the database queries",
			EnvVars:     []string{"DATABASE_DEBUG"},
			DefaultText: "false",
			Value:       false,
		},
		&cli.StringFlag{
			Name:    "migrations-table",
			Value:   "schema_migrations",
			Usage:   "Table to store migrations info",
			EnvVars: []string{"MIGRATIONS_TABLE"},
		},
		&cli.StringFlag{
			Name:    "migrations-dir",
			Value:   "/migrations",
			Usage:   "Folder which contains migrations",
			EnvVars: []string{"MIGRATIONS_DIR"},
		},
	}
}

func Intialized() bool {
	return initialized
}

func Start(cli *cli.Context) error {
	if initialized {
		return nil
	}

	if strings.HasPrefix(cli.String("database-uri"), "postgres://") {
		config, err := pgx.ParseURI(cli.String("database-url"))
		if err != nil {
			return err
		}

		config.PreferSimpleProtocol = true

		if iLogger.Intialized() {
			config.Logger = logrusadapter.NewLogger(iLogger.Logrus())
		}

		SQLDB = stdlib.OpenDB(config)
		driver, err := migratePostgres.WithInstance(SQLDB, &migratePostgres.Config{MigrationsTable: cli.String("migrations-table")})
		if err != nil {
			return err
		}

		m, err := migrate.NewWithDatabaseInstance(
			fmt.Sprintf("file://%s/postgres", cli.String("migrations-dir")),
			"postgres", driver)
		if err != nil {
			return err
		}
		if err := m.Up(); err != migrate.ErrNoChange && err != nil {
			return err
		}

		Bun = bun.NewDB(SQLDB, pgdialect.New())
		if Bun == nil {
			return errors.New("failed to create bun")
		}

		if cli.Bool("database-debug") {
			// Print all queries to stdout.
			Bun.AddQueryHook(bundebug.NewQueryHook(bundebug.WithVerbose(true)))
		}
	}

	initialized = true
	return nil
}

func Stop() error {
	if err := SQLDB.Close(); err != nil {
		return err
	}

	if err := Bun.Close(); err != nil {
		return err
	}

	return nil
}
