"""Logique de résolution des groupes (2026-09-12) — `group_membership.py` porte le cœur
non-trivial de la fonctionnalité groupes (règles dynamiques, imbrication, contrôle de cycle) et
n'avait aucun test. On couvre : validation des règles, statique vs dynamique, combinateurs
all/any, union récursive via sous-groupes, et prévention de cycle."""
import json

import pytest

from app import models
from app.group_membership import (
    agents_matching_rules,
    normalize_rules,
    resolve_group_agents,
    would_create_cycle,
)


def _agent(db, hostname, **kw):
    a = models.Agent(hostname=hostname, **kw)
    db.add(a)
    db.commit()
    db.refresh(a)
    return a


def _group(db, name, rules=None):
    g = models.DeviceGroup(name=name, rules=json.dumps(rules) if rules else None)
    db.add(g)
    db.commit()
    db.refresh(g)
    return g


class TestNormalizeRules:
    def test_none_or_empty_means_static(self):
        assert normalize_rules(None) is None
        assert normalize_rules({"conditions": []}) is None

    def test_valid_rule_roundtrips(self):
        r = normalize_rules(
            {"combinator": "any", "conditions": [{"field": "hostname", "operator": "glob", "value": "*-wks*"}]}
        )
        assert r == {
            "combinator": "any",
            "conditions": [{"field": "hostname", "operator": "glob", "value": "*-wks*"}],
        }

    def test_value_is_trimmed(self):
        r = normalize_rules({"conditions": [{"field": "os", "operator": "contains", "value": "  Windows  "}]})
        assert r["conditions"][0]["value"] == "Windows"

    @pytest.mark.parametrize(
        "bad",
        [
            {"conditions": [{"field": "inconnu", "operator": "glob", "value": "x"}]},
            {"conditions": [{"field": "hostname", "operator": "inconnu", "value": "x"}]},
            {"combinator": "peut-etre", "conditions": [{"field": "hostname", "operator": "glob", "value": "x"}]},
            {"conditions": [{"field": "hostname", "operator": "glob", "value": "   "}]},
        ],
    )
    def test_invalid_raises(self, bad):
        with pytest.raises(ValueError):
            normalize_rules(bad)


class TestCycleDetection:
    def test_self_is_cycle(self, db):
        g = _group(db, "a")
        assert would_create_cycle(db, g.id, g.id) is True

    def test_direct_back_edge(self, db):
        a, b = _group(db, "a"), _group(db, "b")
        db.add(models.DeviceGroupLink(parent_group_id=a.id, child_group_id=b.id))
        db.commit()
        # imbriquer a DANS b fermerait a -> b -> a
        assert would_create_cycle(db, b.id, a.id) is True

    def test_transitive_back_edge(self, db):
        a, b, c = _group(db, "a"), _group(db, "b"), _group(db, "c")
        db.add(models.DeviceGroupLink(parent_group_id=a.id, child_group_id=b.id))
        db.add(models.DeviceGroupLink(parent_group_id=b.id, child_group_id=c.id))
        db.commit()
        # imbriquer a DANS c fermerait a -> b -> c -> a
        assert would_create_cycle(db, c.id, a.id) is True

    def test_no_cycle(self, db):
        a, b = _group(db, "a"), _group(db, "b")
        assert would_create_cycle(db, a.id, b.id) is False


class TestResolveMembers:
    def test_static_membership(self, db):
        a = _agent(db, "PC1")
        g = _group(db, "grp")
        db.add(models.AgentGroupMembership(agent_id=a.id, group_id=g.id))
        db.commit()
        assert [m.id for m in resolve_group_agents(db, g)] == [a.id]

    def test_dynamic_glob_matches_by_hostname(self, db):
        w1 = _agent(db, "org-wks-01")
        w2 = _agent(db, "org-wks-02")
        _agent(db, "org-srv-01")  # ne matche pas
        g = _group(
            db, "wks", rules={"combinator": "all", "conditions": [{"field": "hostname", "operator": "glob", "value": "*-wks-*"}]}
        )
        assert {m.id for m in resolve_group_agents(db, g)} == {w1.id, w2.id}

    def test_dynamic_ignores_static_memberships(self, db):
        # un groupe dynamique ne lit JAMAIS AgentGroupMembership (une adhésion manuelle dessus
        # serait silencieusement sans effet — d'où le refus explicite côté route)
        a = _agent(db, "srv-01")
        g = _group(
            db, "wks", rules={"combinator": "all", "conditions": [{"field": "hostname", "operator": "glob", "value": "*-wks-*"}]}
        )
        db.add(models.AgentGroupMembership(agent_id=a.id, group_id=g.id))
        db.commit()
        assert resolve_group_agents(db, g) == []

    def test_nested_child_group_union(self, db):
        a, b = _agent(db, "PC1"), _agent(db, "PC2")
        child, parent = _group(db, "child"), _group(db, "parent")
        db.add(models.AgentGroupMembership(agent_id=a.id, group_id=child.id))
        db.add(models.AgentGroupMembership(agent_id=b.id, group_id=parent.id))
        db.add(models.DeviceGroupLink(parent_group_id=parent.id, child_group_id=child.id))
        db.commit()
        # membres du parent = ses propres membres + ceux résolus de l'enfant
        assert {m.id for m in resolve_group_agents(db, parent)} == {a.id, b.id}


class TestCombinator:
    def test_all_requires_every_condition(self, db):
        _agent(db, "org-wks-01", agent_version="1.0.0")
        rules = {
            "combinator": "all",
            "conditions": [
                {"field": "hostname", "operator": "contains", "value": "wks"},
                {"field": "agent_version", "operator": "equals", "value": "2.0.0"},
            ],
        }
        assert agents_matching_rules(db, rules) == []

    def test_any_needs_one_condition(self, db):
        a = _agent(db, "org-wks-01", agent_version="1.0.0")
        rules = {
            "combinator": "any",
            "conditions": [
                {"field": "hostname", "operator": "contains", "value": "wks"},
                {"field": "agent_version", "operator": "equals", "value": "2.0.0"},
            ],
        }
        assert [m.id for m in agents_matching_rules(db, rules)] == [a.id]
