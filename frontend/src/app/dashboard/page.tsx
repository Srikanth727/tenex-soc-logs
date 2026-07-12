"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useHasMounted, useIsAuthenticated } from "@/lib/auth";
import { apiFetch } from "@/lib/api";
import Navbar from "@/components/Navbar";
import Upload from "@/components/Upload";
import LogList from "@/components/LogList";
import Timeline from "@/components/Timeline";
import ChainList from "@/components/ChainList";
import AnomalyTable from "@/components/AnomalyTable";
import SeverityChart from "@/components/SeverityChart";
import ThreatTypeChart from "@/components/ThreatTypeChart";

export interface LogFileSummary {
  id: number;
  filename: string;
  status: string;
  uploaded_at: string | null;
  line_count: number;
}

interface DashboardAnomaly {
  rule_name: string;
  severity: string | null;
  mitre_tag: string | null;
}

// Unfiltered anomaly data shared by SeverityChart/ThreatTypeChart, independent
// of AnomalyTable's own (severity/status-filtered) fetch — the charts always
// summarize the whole log file, not the analyst's current triage filter.
function useAllAnomalies(logId: number | null) {
  const [anomalies, setAnomalies] = useState<DashboardAnomaly[]>([]);

  useEffect(() => {
    if (logId == null) {
      return; // charts aren't rendered without a selected log; nothing to fetch or clear
    }
    let cancelled = false;
    apiFetch<DashboardAnomaly[]>(`/api/logs/${logId}/anomalies`)
      .then((data) => {
        if (!cancelled) setAnomalies(data);
      })
      .catch(() => {
        if (!cancelled) setAnomalies([]);
      });
    return () => {
      cancelled = true;
    };
  }, [logId]);

  return anomalies;
}

export default function DashboardPage() {
  const router = useRouter();
  const hasMounted = useHasMounted();
  const authenticated = useIsAuthenticated();
  const [selectedLogId, setSelectedLogId] = useState<number | null>(null);
  const [refreshSignal, setRefreshSignal] = useState(0);
  const allAnomalies = useAllAnomalies(selectedLogId);

  useEffect(() => {
    if (hasMounted && !authenticated) {
      router.replace("/");
    }
  }, [hasMounted, authenticated, router]);

  const handleUploaded = useCallback((log: LogFileSummary) => {
    setSelectedLogId(log.id);
    setRefreshSignal((n) => n + 1);
  }, []);

  // Mirrors the login page's guard: server rendering can't know whether a
  // valid session exists, so useIsAuthenticated() reports its SSR/hydration
  // snapshot (false) for one render even when a valid token exists — without
  // waiting for hasMounted, that transient false fires the redirect above
  // before the real client value lands, bouncing to "/" and back.
  if (!hasMounted || !authenticated) {
    return null;
  }

  return (
    <div className="flex min-h-screen w-full flex-col overflow-x-hidden bg-zinc-50 dark:bg-black">
      <Navbar />
      <main className="grid w-full flex-1 grid-cols-1 gap-6 p-6 lg:grid-cols-[360px_1fr]">
        <div className="flex min-w-0 flex-col gap-6">
          <Upload onUploaded={handleUploaded} />
          <LogList key={refreshSignal} selectedLogId={selectedLogId} onSelect={setSelectedLogId} />
        </div>
        <div className="flex min-w-0 flex-col gap-6">
          {selectedLogId ? (
            <>
              {/* Default (stretch) alignment: both cells fill the row's full
                  height, and Timeline's bars area grows into that height via
                  plain CSS flex stretch (see Timeline.tsx) — no gap below it
                  before ThreatTypeChart starts. */}
              <div className="grid min-w-0 grid-cols-1 gap-6 lg:grid-cols-3">
                <div className="min-w-0 lg:col-span-2">
                  <Timeline key={`timeline-${selectedLogId}`} logId={selectedLogId} />
                </div>
                <div className="min-w-0">
                  <SeverityChart key={`severity-${selectedLogId}`} anomalies={allAnomalies} />
                </div>
              </div>
              <ThreatTypeChart key={`threats-${selectedLogId}`} anomalies={allAnomalies} />
              <AnomalyTable key={`anomalies-${selectedLogId}`} logId={selectedLogId} />
              <ChainList key={`chains-${selectedLogId}`} logId={selectedLogId} />
            </>
          ) : (
            <div className="flex flex-1 items-center justify-center rounded-xl border border-dashed border-zinc-300 p-12 text-center text-sm text-zinc-500 dark:border-zinc-700 dark:text-zinc-400">
              Upload a log file or select one from the list to view its timeline and detected anomalies.
            </div>
          )}
        </div>
      </main>
    </div>
  );
}
