# Migrations de schéma (Alembic) — serveur Vanitas

Mis en place le 2026-09-12. **Source unique de vérité pour le schéma de la base** — remplace
l'ancien `Base.metadata.create_all()` de bootstrap ET les scripts `scripts/migrate_add_*.py`
faits main (conservés à titre historique, déjà appliqués, plus utilisés).

`app/db.py::init_db()` exécute `alembic upgrade head` au démarrage du serveur : une base neuve
est créée intégralement par la migration de base, une base existante déjà à jour est un no-op.

## Ajouter une migration (changement de modèle)

Après avoir modifié `app/models.py` :

```bash
cd endpoint-agent/server
.venv/Scripts/python.exe -m alembic revision --autogenerate -m "description courte"
```

Puis **relire le fichier généré** dans `alembic/versions/` (autogenerate n'est pas infaillible,
surtout sur SQLite) avant de l'appliquer. Il s'applique tout seul au prochain démarrage du
serveur (`init_db`), ou manuellement :

```bash
.venv/Scripts/python.exe -m alembic upgrade head
```

## Points spécifiques à ce projet

- **`ALEMBIC_DATABASE_URL`** (env.py) — override optionnel de l'URL de base, pour l'outillage
  et les tests (générer/tester une migration contre une base jetable sans toucher la prod).
  Absent : la base réelle (`app.db.DATABASE_URL`) est utilisée.
- **`render_as_batch=True`** (env.py) — indispensable sur SQLite (pas d'`ALTER TABLE` complexe
  natif ; Alembic recrée la table en mode batch).
- **Type `UTCDateTime`** — colonnes personnalisées de `app/models.py` ; le template
  (`script.py.mako`) importe déjà `app.models` pour que les migrations générées le résolvent.
- **Colonnes physiques héritées non mappées** (`agents.group_id`, `device_groups.pattern`,
  jamais `DROP`ées) : un futur `--autogenerate` proposera de les supprimer — c'est un nettoyage
  légitime, à confirmer explicitement lors de la relecture du fichier généré.
