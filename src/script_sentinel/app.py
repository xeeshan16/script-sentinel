"""The FastAPI application."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from script_sentinel import __version__
from script_sentinel.api import sites as sites_api
from script_sentinel.config import Settings
from script_sentinel.db import make_engine, make_sessionmaker
from script_sentinel.sites import ConflictError, NotFoundError, SiteError, ValidationError

_STATUS: dict[type[SiteError], int] = {
    NotFoundError: status.HTTP_404_NOT_FOUND,
    ConflictError: status.HTTP_409_CONFLICT,
    ValidationError: status.HTTP_422_UNPROCESSABLE_CONTENT,
}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = make_engine(settings.database_url, pool_pre_ping=True)
        app.state.engine = engine
        app.state.sessionmaker = make_sessionmaker(engine)
        try:
            yield
        finally:
            await engine.dispose()

    app = FastAPI(
        title="script-sentinel",
        version=__version__,
        summary="Integrity monitoring for the third-party scripts your pages load.",
        lifespan=lifespan,
    )
    app.state.settings = settings

    @app.exception_handler(SiteError)
    async def _site_error(_request: Request, exc: SiteError) -> JSONResponse:
        code = next(c for t, c in _STATUS.items() if isinstance(exc, t))
        return JSONResponse(status_code=code, content={"detail": str(exc)})

    @app.get("/healthz", tags=["health"])
    async def healthz() -> dict[str, str]:
        """Liveness: the process is up."""
        return {"status": "ok"}

    @app.get("/readyz", tags=["health"])
    async def readyz(request: Request) -> JSONResponse:
        """Readiness: the database answers."""
        try:
            async with request.app.state.engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
        except Exception as exc:
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"status": "unavailable", "database": type(exc).__name__},
            )
        return JSONResponse({"status": "ok", "database": "ok"})

    app.include_router(sites_api.router)
    return app
