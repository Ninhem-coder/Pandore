/**
 * Barrel des hooks de données (découpage 2026-09-12) — l'ancien fichier monolithique de
 * ~1340 lignes a été scindé en modules par domaine, re-exportés ici pour que TOUS les imports
 * existants (`import { useX } from "../hooks/useDashboardData.js"`, une trentaine de fichiers)
 * continuent de fonctionner sans changement. Ajouter un hook : le mettre dans le module de son
 * domaine, il est automatiquement re-exporté par le `export *` ci-dessous.
 *
 * - `shared.js`         — internes partagés : `isErrorPayload`, `listPayloadError`, `useKeyedFetch`.
 * - `dashboardData.js`  — socle Defender/Intune de la Vue d'ensemble (`useDashboardData`,
 *                         `useComplianceDetail`, `useSecureScore`, `useDefenderAlerts`,
 *                         `useOverviewSignals`, `useHistoryTrend`).
 * - `vulnerabilities.js`— CVE / inventaires / ANSSI.
 * - `apps.js`           — "Application déployée" Intune.
 * - `vanitas.js`        — tous les hooks Vanitas.
 */
export * from "./shared.js";
export * from "./dashboardData.js";
export * from "./vulnerabilities.js";
export * from "./apps.js";
export * from "./vanitas.js";
