"use client";

import { useEffect, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api";

interface AnomalyLogEntry {
  id: number;
  timestamp: string | null;
  cip: string | null;
  login: string | null;
  url: string | null;
  urlcat: string | null;
  threatname: string | null;
}

interface Anomaly {
  id: number;
  rule_name: string;
  mitre_tag: string | null;
  confidence_score: number | null;
  explanation: string | null;
  severity: string | null;
  status: string;
  detected_at: string | null;
  log_entry: AnomalyLogEntry;
}

interface AnomalyTableProps {
  logId: number;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300",
  medium: "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300",
  low: "bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300",
};

function severityBadgeClass(severity: string | null): string {
  return SEVERITY_STYLES[(severity ?? "").toLowerCase()] ?? SEVERITY_STYLES.low;
}

export default function AnomalyTable({ logId }: AnomalyTableProps) {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Parent remounts this component (via `key={logId}`) whenever the selected
  // log changes, so state (including `loading`) already starts fresh — this
  // effect only needs to run once per mount.
  useEffect(() => {
    let cancelled = false;
    apiFetch<Anomaly[]>(`/api/logs/${logId}/anomalies`)
      .then((data) => {
        if (!cancelled) {
          setAnomalies(data);
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Failed to load anomalies.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [logId]);

  return (
    <div className="rounded-xl border border-zinc-200 bg-white p-4 dark:border-zinc-800 dark:bg-zinc-950">
      <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">Detected anomalies</h2>

      {loading && <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">Loading…</p>}
      {error && <p className="mt-2 text-sm text-red-600 dark:text-red-400">{error}</p>}
      {!loading && !error && anomalies.length === 0 && (
        <p className="mt-2 text-sm text-zinc-500 dark:text-zinc-400">No anomalies detected for this log.</p>
      )}

      {!loading && !error && anomalies.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table className="w-full min-w-[720px] text-left text-sm">
            <thead>
              <tr className="border-b border-zinc-200 text-xs uppercase tracking-wide text-zinc-400 dark:border-zinc-800">
                <th className="py-2 pr-3 font-medium">Severity</th>
                <th className="py-2 pr-3 font-medium">Rule</th>
                <th className="py-2 pr-3 font-medium">MITRE</th>
                <th className="py-2 pr-3 font-medium">Confidence</th>
                <th className="py-2 pr-3 font-medium">Source</th>
                <th className="py-2 font-medium">Explanation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-zinc-100 dark:divide-zinc-800">
              {anomalies.map((a) => (
                <tr key={a.id}>
                  <td className="py-2 pr-3 align-top">
                    <span
                      className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${severityBadgeClass(a.severity)}`}
                    >
                      {a.severity ?? "unknown"}
                    </span>
                  </td>
                  <td className="py-2 pr-3 align-top font-medium text-zinc-800 dark:text-zinc-200">
                    {a.rule_name.replace(/_/g, " ")}
                  </td>
                  <td className="py-2 pr-3 align-top text-zinc-500 dark:text-zinc-400">{a.mitre_tag ?? "—"}</td>
                  <td className="py-2 pr-3 align-top tabular-nums text-zinc-700 dark:text-zinc-300">
                    {a.confidence_score != null ? `${Math.round(a.confidence_score * 100)}%` : "—"}
                  </td>
                  <td className="py-2 pr-3 align-top text-zinc-500 dark:text-zinc-400">
                    {a.log_entry?.cip ?? "—"}
                    {a.log_entry?.login ? ` · ${a.log_entry.login}` : ""}
                  </td>
                  <td className="py-2 align-top text-zinc-600 dark:text-zinc-400">{a.explanation ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
