"""Run Alembic migrations without needing an ``alembic.ini`` next to the installed package."""

from __future__ import annotations

import sys
from importlib.resources import files

from alembic import command
from alembic.config import Config


def alembic_config(database_url: str) -> Config:
    # Bind stdout at call time so `sentinel db current` output can be redirected.
    config = Config(stdout=sys.stdout)
    config.set_main_option("script_location", str(files("script_sentinel") / "migrations"))
    # ConfigParser interpolation treats '%' specially, e.g. in URL-encoded passwords.
    config.set_main_option("sqlalchemy.url", database_url.replace("%", "%%"))
    return config


def upgrade(database_url: str, revision: str = "head") -> None:
    command.upgrade(alembic_config(database_url), revision)


def downgrade(database_url: str, revision: str) -> None:
    command.downgrade(alembic_config(database_url), revision)


def current(database_url: str) -> None:
    command.current(alembic_config(database_url), verbose=False)
