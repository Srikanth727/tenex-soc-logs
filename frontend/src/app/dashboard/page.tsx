"use client";

import { useCallback, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useIsAuthenticated } from "@/lib/auth";
import Navbar from "@/components/Navbar";
import Upload from "@/components/Upload";
import LogList from "@/components/LogList";
import Timeline from "@/components/Timeline";
import AnomalyTable from "@/components/AnomalyTable";

export interface LogFileSummary {
  id: number;
  filename: string;
  status: string;
  uploaded_at: string | null;
  line_count: number;
}

export default function DashboardPage() {
  const router = useRouter();
  const authenticated = useIsAuthenticated();
  const [selectedLogId, setSelectedLogId] = useState<number | null>(null);
  const [refreshSignal, setRefreshSignal] = useState(0);

  useEffect(() => {
    if (!authenticated) {
      router.replace("/");
    }
  }, [authenticated, router]);

  const handleUploaded = useCallback((log: LogFileSummary) => {
    setSelectedLogId(log.id);
    setRefreshSignal((n) => n + 1);
  }, []);

  if (!authenticated) {
    return null;
  }

  return (
    <div className="flex min-h-screen flex-col bg-zinc-50 dark:bg-black">
      <Navbar />
      <main className="grid flex-1 grid-cols-1 gap-6 p-6 lg:grid-cols-[360px_1fr]">
        <div className="flex flex-col gap-6">
          <Upload onUploaded={handleUploaded} />
          <LogList key={refreshSignal} selectedLogId={selectedLogId} onSelect={setSelectedLogId} />
        </div>
        <div className="flex flex-col gap-6">
          {selectedLogId ? (
            <>
              <Timeline key={`timeline-${selectedLogId}`} logId={selectedLogId} />
              <AnomalyTable key={`anomalies-${selectedLogId}`} logId={selectedLogId} />
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
