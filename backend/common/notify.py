"""
Envoi d'email de notification — brique de base pour les alertes Vanitas (agent silencieux,
nouvelle vulnérabilité critique, nouvel échec de conformité — voir vanitas/alert_state.py et
les boucles _vanitas_agent_health_loop/_vanitas_diff_alert_loop dans api_server.py).

Aucune brique de notification n'existait nulle part dans ce projet avant ce jour (grep
smtp|webhook|teams|email|notify sur tout le repo : zéro résultat pertinent). SMTP choisi par
Nicolas comme canal, mais explicitement PAS configuré pour l'instant ("je ne vais pas le
configurer pour le moment") — `send_email` doit donc dégrader proprement (log + no-op) tant
qu'aucun SMTP n'est renseigné dans `.env`, jamais lever ni faire échouer la boucle de fond
appelante. `smtplib`/`email` (bibliothèque standard) suffisent, aucune dépendance ajoutée.
"""
import logging
import smtplib
from email.message import EmailMessage

from common.config import SMTP_FROM, SMTP_HOST, SMTP_PASSWORD, SMTP_PORT, SMTP_TO, SMTP_USE_TLS, SMTP_USERNAME

logger = logging.getLogger(__name__)


def send_email(subject: str, body: str) -> bool:
    """Envoie un email de notification. Renvoie `True` si envoyé, `False` sinon (SMTP non
    configuré OU échec réseau/auth) — ne lève JAMAIS : une notification manquée ne doit pas
    faire planter la boucle de fond qui l'a déclenchée, seulement être journalisée."""
    if not SMTP_HOST or not SMTP_TO:
        # `warning` (pas `info`) : même convention que `_vanitas_purge_loop` (api_server.py)
        # pour "capacité dégradée en no-op faute de configuration" — visible avec la config de
        # logging par défaut d'uvicorn (root logger à WARNING), contrairement à `info`.
        logger.warning(
            "Notification email ignorée (SMTP non configuré — SMTP_HOST/SMTP_TO absents de .env) : %s",
            subject,
        )
        return False

    # `subject` peut intégrer un hostname d'agent Vanitas (ex. alerte "poste silencieux") —
    # neutralise tout \r/\n avant de le poser en en-tête (revue de sécurité du 2026-09-09) :
    # défense en profondeur contre une injection d'en-tête email, même si un hostname Windows
    # valide ne peut structurellement pas en contenir.
    safe_subject = subject.replace("\r", " ").replace("\n", " ")

    message = EmailMessage()
    message["Subject"] = safe_subject
    message["From"] = SMTP_FROM or (SMTP_USERNAME or "vanitas@localhost")
    message["To"] = SMTP_TO
    message.set_content(body)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
            if SMTP_USE_TLS:
                server.starttls()
            if SMTP_USERNAME and SMTP_PASSWORD:
                server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(message)
        return True
    except Exception:
        logger.exception("Échec de l'envoi de la notification email : %s", subject)
        return False
