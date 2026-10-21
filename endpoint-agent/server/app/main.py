"""Point d'entrée FastAPI — endpoint-agent server."""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

from . import config
from .cve_matching import refresh_fleet
from .db import SessionLocal, init_db
from .routes import (
    activity,
    agent_package,
    agents,
    commands,
    compliance,
    enrollment,
    enrollment_tokens,
    groups,
    installers,
    inventory,
    maintenance,
    patch,
    renew,
    shell,
    suspicious_activity,
    vulnerabilities,
)

logger = logging.getLogger(__name__)

# uvicorn n'expose pas nativement le certificat client mTLS aux routes FastAPI (le dict ASGI
# `scope` ne contient jamais de clé "transport", vérifié en conditions réelles au jalon 3
# avant tout code métier). Ce monkeypatch, motif documenté publiquement pour ce problème
# précis, glisse le transport brut dans le scope — security.get_current_agent() (jalon 3)
# peut ensuite en extraire le certificat pair vérifié via
# `transport.get_extra_info("ssl_object").getpeercert()`. Cible HttpToolsProtocol (pas
# H11Protocol) car uvicorn[standard] utilise httptools par défaut quand il est installé —
# confirmé en inspectant `uvicorn.config.HTTP_PROTOCOLS`/`auto`.
_original_on_url = HttpToolsProtocol.on_url


def _patched_on_url(self, url):
    _original_on_url(self, url)
    self.scope["transport"] = self.transport


HttpToolsProtocol.on_url = _patched_on_url


async def _cve_refresh_loop() -> None:
    """Rafraîchit toute la flotte toutes les CVE_REFRESH_INTERVAL_HOURS heures — cycle
    automatique demandé par Nicolas (le rafraîchissement manuel par agent a été retiré le
    2026-09-09, jamais câblé côté dashboard). Se déclenche une première fois tout de suite
    au démarrage, puis boucle."""
    while True:
        db = SessionLocal()
        try:
            await refresh_fleet(db)
        except Exception:
            logger.exception(
                "Échec du rafraîchissement CVE automatique, nouvelle tentative au prochain cycle."
            )
        finally:
            db.close()
        await asyncio.sleep(config.CVE_REFRESH_INTERVAL_HOURS * 3600)


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    task = asyncio.create_task(_cve_refresh_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


# `docs_url`/`redoc_url`/`openapi_url` désactivés (audit sécurité du 2026-09-17, finding #10) —
# ce serveur est un back-office serveur→serveur (mTLS agent + secret partagé Pandore), jamais
# consommé par un navigateur : exposer le schéma OpenAPI complet ne servait qu'à divulguer toute
# la surface d'API sans authentification. Réactivables ponctuellement en dev en repassant les
# valeurs par défaut si besoin d'explorer l'API.
app = FastAPI(
    title="Endpoint Agent Server",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.include_router(enrollment.router)
app.include_router(enrollment_tokens.router)
app.include_router(inventory.router)
app.include_router(renew.router)
app.include_router(commands.router)
app.include_router(agents.router)
app.include_router(vulnerabilities.router)
app.include_router(shell.router)
app.include_router(compliance.router)
app.include_router(maintenance.router)
app.include_router(groups.router)
app.include_router(installers.router)
app.include_router(activity.router)
app.include_router(agent_package.router)
app.include_router(suspicious_activity.router)
app.include_router(patch.router)


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}
