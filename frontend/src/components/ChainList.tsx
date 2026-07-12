"use client";

import { useEffect, useState } from "react";
import { ApiError, apiFetch } from "@/lib/api";
import { SEVERITY_BG_CLASS, isKnownSeverity } from "@/lib/severityColors";
import { mitreChainTitle } from "@/lib/mitre";

interface ChainEvent {
  rule: string;
  mitre_tag: string | null;
  confidence: number | null;
  severity: string | null;
  occurred_at: string | null;
  explanation: string | null;
}

interface Chain {
  entity_type: "ip" | "user";
  entity_value: string;
  anomalies_count: number;
  anomalies: ChainEvent[];
  highest_severity: string | null;
  chain_synthesis: string;
}

interface ChainListProps {
  logId: number;
}

const SEVERITY_ACCENT: Record<string, string> = {
  critical: "border-l-red-500 bg-red-50/60 dark:bg-red-950/20",
  high: "border-l-orange-500 bg-orange-50/60 dark:bg-orange-950/20",
  medium: "border-l-yellow-500 bg-yellow-50/60 dark:bg-yellow-950/20",
  low: "border-l-green-500 bg-green-50/60 dark:bg-green-950/20",
};
const UNKNOWN_ACCENT = "border-l-zinc-400 bg-zinc-50/60 dark:bg-zinc-900/40";

function accentClass(severity: string | null): string {
  return SEVERITY_ACCENT[(severity ?? "").toLowerCase()] ?? UNKNOWN_ACCENT;
}

function dotClass(severity: string | null): string {
  return isKnownSeverity(severity) ? SEVERITY_BG_CLASS[severity] : "bg-zinc-400 dark:bg-zinc-600";
}

// {date, time, period} split so a range spanning the same AM/PM can print it
// once at the end ("07:00:00–07:01:10 AM") instead of on both sides.
function formatClock(timestamp: string | null): { date: string; time: string; period: string } {
  if (!timestamp) return { date: "", time: "unknown", period: "" };
  const d = new Date(timestamp);
  const date = d.toLocaleDateString([], { month: "short", day: "numeric" });
  const parts = d
    .toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: true })
    .split(" ");
  return { date, time: parts[0], period: parts[1] ?? "" };
}

// Chains built from anomalies spread across days (chains.py groups by IP/user
// regardless of when they occurred) sort correctly by real timestamp, but a
// time-only display like "05:11 AM" right after "07:55 AM" looks out of
// order unless the date is shown too — this flags when that context matters.
function spansMultipleDays(events: ChainEvent[]): boolean {
  const dates = new Set(events.map((e) => formatClock(e.occurred_at).date));
  return dates.size > 1;
}

function formatTimeRange(events: ChainEvent[], showDates: boolean): string {
  if (events.length === 0) return "";
  const first = formatClock(events[0].occurred_at);
  const last = formatClock(events[events.length - 1].occurred_at);
  const firstLabel = showDates ? `${first.date}, ${first.time}` : first.time;
  const lastLabel = showDates ? `${last.date}, ${last.time}` : last.time;
  if (firstLabel === lastLabel) return `${firstLabel} ${first.period}`.trim();
  if (!showDates && first.period === last.period) return `${firstLabel}–${lastLabel} ${last.period}`.trim();
  return `${firstLabel} ${first.period}–${lastLabel} ${last.period}`.trim();
}

interface EventGroup {
  rule: string;
  mitre_tag: string | null;
  severity: string | null;
  events: ChainEvent[];
}

// Collapse consecutive anomalies sharing the same rule + technique into one
// group, so a mechanical run (e.g. 25 near-identical brute-force hits)
// renders as one summary row instead of ballooning the card.
function groupConsecutive(events: ChainEvent[]): EventGroup[] {
  const groups: EventGroup[] = [];
  for (const e of events) {
    const last = groups[groups.length - 1];
    if (last && last.rule === e.rule && last.mitre_tag === e.mitre_tag) {
      last.events.push(e);
    } else {
      groups.push({ rule: e.rule, mitre_tag: e.mitre_tag, severity: e.severity, events: [e] });
    }
  }
  return groups;
}

function averageConfidence(events: ChainEvent[]): number | null {
  const values = events.map((e) => e.confidence).filter((c): c is number => c != null);
  if (values.length === 0) return null;
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}

// Most frequent MITRE technique in the chain represents it in the header —
// an IP-grouped chain can mix rule types, but is usually dominated by one.
function primaryMitreTag(events: ChainEvent[]): string | null {
  const counts = new Map<string, number>();
  for (const e of events) {
    if (!e.mitre_tag) continue;
    counts.set(e.mitre_tag, (counts.get(e.mitre_tag) ?? 0) + 1);
  }
  let best: string | null = null;
  let bestCount = 0;
  for (const [tag, count] of counts) {
    if (count > bestCount) {
      best = tag;
      bestCount = count;
    }
  }
  return best;
}

// Same idea as primaryMitreTag, but the rule_name for the card's one-line
// collapsed summary (a chain mixing rule types still needs a single label).
function primaryRuleName(events: ChainEvent[]): string {
  const counts = new Map<string, number>();
  for (const e of events) {
    counts.set(e.rule, (counts.get(e.rule) ?? 0) + 1);
  }
  let best = events[0]?.rule ?? "";
  let bestCount = 0;
  for (const [rule, count] of counts) {
    if (count > bestCount) {
      best = rule;
      bestCount = count;
    }
  }
  return best;
}

// Compact horizontal strip with dots placed proportionally to real elapsed
// time (not evenly spaced) — tight clustering visually reinforces a
// mechanical, non-human cadence the narrative text describes.
function ProportionalTimeline({ events }: { events: ChainEvent[] }) {
  const times = events
    .map((e) => (e.occurred_at ? new Date(e.occurred_at).getTime() : null))
    .filter((t): t is number => t != null);

  if (times.length === 0) return null;

  const minT = Math.min(...times);
  const maxT = Math.max(...times);
  const span = maxT - minT;

  return (
    <div className="relative mt-2 h-5 w-full">
      <div className="absolute left-0 right-0 top-1/2 h-px -translate-y-1/2 bg-zinc-300 dark:bg-zinc-700" />
      {events.map((e, i) => {
        const t = e.occurred_at ? new Date(e.occurred_at).getTime() : null;
        const pct = t == null ? 0 : span === 0 ? 50 : ((t - minT) / span) * 100;
        return (
          <div
            key={i}
            className="group absolute top-1/2 -translate-x-1/2 -translate-y-1/2"
            style={{ left: `${pct}%` }}
          >
            <div
              className={`h-[9px] w-[9px] rounded-full shadow-sm ring-2 ring-white dark:ring-zinc-950 ${dotClass(e.severity)}`}
            />
            <div className="pointer-events-none absolute bottom-full left-1/2 z-10 mb-1.5 hidden -translate-x-1/2 whitespace-nowrap rounded-md bg-zinc-900 px-2 py-1 text-[11px] text-white shadow-lg group-hover:block dark:bg-zinc-100 dark:text-zinc-900">
              {e.rule.replace(/_/g, " ")} &middot; {formatClock(e.occurred_at).date}, {formatClock(e.occurred_at).time}{" "}
              {formatClock(e.occurred_at).period}
            </div>
          </div>
        );
      })}
    </div>
  );
}

function EventGroupRow({ group, showDates }: { group: EventGroup; showDates: boolean }) {
  const [expanded, setExpanded] = useState(false);
  const avgConfidence = averageConfidence(group.events);

  if (group.events.length === 1) {
    const e = group.events[0];
    const clock = formatClock(e.occurred_at);
    return (
      <li className="relative text-sm">
        <span
          className={`absolute -left-[23px] top-1.5 h-[9px] w-[9px] rounded-full shadow-sm ${dotClass(e.severity)}`}
        />
        <span className="font-medium text-zinc-800 dark:text-zinc-200">{e.rule.replace(/_/g, " ")}</span>{" "}
        <span className="text-zinc-500 dark:text-zinc-400">
          &middot; {e.mitre_tag ?? "—"} &middot; {showDates ? `${clock.date}, ` : ""}
          {clock.time} {clock.period} &middot; {e.confidence != null ? `${Math.round(e.confidence * 100)}%` : "—"}
        </span>
      </li>
    );
  }

  return (
    <li className="relative text-sm">
      <span
        className={`absolute -left-[23px] top-1.5 h-[9px] w-[9px] rounded-full shadow-sm ${dotClass(group.severity)}`}
      />
      <span className="font-medium text-zinc-800 dark:text-zinc-200">
        {group.rule.replace(/_/g, " ")} &times;{group.events.length}
      </span>{" "}
      <span className="text-zinc-500 dark:text-zinc-400">
        &middot; {group.mitre_tag ?? "—"} &middot; {formatTimeRange(group.events, showDates)} &middot;{" "}
        {avgConfidence != null ? `${Math.round(avgConfidence * 100)}%` : "—"}
      </span>{" "}
      <button
        onClick={() => setExpanded((v) => !v)}
        className="text-xs font-medium text-blue-600 hover:underline dark:text-blue-400"
      >
        {expanded ? "Hide events" : `Show all ${group.events.length} events`}
      </button>

      {expanded && (
        <ol className="mt-2 flex flex-col gap-1.5 border-l-2 border-zinc-200 pl-4 dark:border-zinc-800">
          {group.events.map((e, i) => {
            const clock = formatClock(e.occurred_at);
            return (
              <li key={i} className="relative text-xs text-zinc-500 dark:text-zinc-400">
                <span className="absolute -left-[19px] top-1 h-1.5 w-1.5 rounded-full bg-zinc-300 dark:bg-zinc-700" />
                {showDates ? `${clock.date}, ` : ""}
                {clock.time} {clock.period} &middot; {e.confidence != null ? `${Math.round(e.confidence * 100)}%` : "—"}
              </li>
            );
          })}
        </ol>
      )}
    </li>
  );
}

function ChainCard({ chain }: { chain: Chain }) {
  const [expanded, setExpanded] = useState(true);
  // Individual event rows are always collapsed on first render — every
  // chain, regardless of whether its groupConsecutive() runs happen to be
  // long (one "×15" row) or short (many alternating size-1 rows), starts
  // with just the one-line summary below and expands only on click.
  const [eventsExpanded, setEventsExpanded] = useState(false);
  const groups = groupConsecutive(chain.anomalies);
  const primaryTag = primaryMitreTag(chain.anomalies);
  const primaryRule = primaryRuleName(chain.anomalies);
  const avgConfidence = averageConfidence(chain.anomalies);
  // build_attack_chains groups by IP/user regardless of when events happened,
  // so a chain can legitimately span several days (see chain_synthesis) —
  // once it does, every timestamp needs a date or the list looks shuffled.
  const showDates = spansMultipleDays(chain.anomalies);

  return (
    <div
      className={`rounded-lg border border-l-4 border-zinc-200 dark:border-zinc-800 ${accentClass(chain.highest_severity)}`}
    >
      <button onClick={() => setExpanded((v) => !v)} className="flex w-full items-start justify-between gap-3 p-4 text-left">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">
            {mitreChainTitle(primaryTag)}
            {primaryTag && <span className="ml-1 font-normal text-zinc-400 dark:text-zinc-500">({primaryTag})</span>}
          </p>
          <p className="mt-0.5 text-xs text-zinc-500 dark:text-zinc-400">
            {chain.entity_type === "ip" ? "Source IP" : "User account"}: {chain.entity_value}
            {" · "}
            {chain.anomalies_count} events{" · "}
            {formatTimeRange(chain.anomalies, showDates)}
          </p>
          <ProportionalTimeline events={chain.anomalies} />
        </div>
        <span className="mt-0.5 shrink-0 text-zinc-400">{expanded ? "▾" : "▸"}</span>
      </button>

      {expanded && (
        <div className="px-4 pb-4">
          <p className="text-sm">
            <span className="font-medium text-zinc-800 dark:text-zinc-200">
              {primaryRule.replace(/_/g, " ")} &times;{chain.anomalies_count}
            </span>{" "}
            <span className="text-zinc-500 dark:text-zinc-400">
              &middot; {primaryTag ?? "—"} &middot; {formatTimeRange(chain.anomalies, showDates)} &middot;{" "}
              {avgConfidence != null ? `${Math.round(avgConfidence * 100)}%` : "—"}
            </span>{" "}
            <button
              onClick={() => setEventsExpanded((v) => !v)}
              className="text-xs font-medium text-blue-600 hover:underline dark:text-blue-400"
            >
              {eventsExpanded ? "Hide events" : `Show all ${chain.anomalies_count} events`}
            </button>
          </p>

          {eventsExpanded && (
            <ol className="mt-2 flex flex-col gap-2 border-l-2 border-zinc-300 pl-4 dark:border-zinc-700">
              {groups.map((group, i) => (
                <EventGroupRow key={i} group={group} showDates={showDates} />
              ))}
            </ol>
          )}

          <p className="mt-3 text-sm italic text-zinc-600 dark:text-zinc-400">{chain.chain_synthesis}</p>
        </div>
      )}
    </div>
  );
}

export default function ChainList({ logId }: ChainListProps) {
  const [chains, setChains] = useState<Chain[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Parent remounts this component (via `key={logId}`) whenever the selected
  // log changes, so state (including `loading`) already starts fresh — this
  // effect only needs to run once per mount.
  useEffect(() => {
    let cancelled = false;
    apiFetch<Chain[]>(`/api/logs/${logId}/chains`)
      .then((data) => {
        if (!cancelled) {
          setChains(data);
          setError(null);
        }
      })
      .catch((err) => {
        if (!cancelled) setError(err instanceof ApiError ? err.message : "Failed to load attack chains.");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [logId]);

  // Nothing to show once resolved with zero chains -- the flat AnomalyTable
  // below already covers this data, so ChainList stays fully out of the way.
  if (!loading && !error && chains.length === 0) {
    return null;
  }

  return (
    <div className="flex flex-col gap-3">
      <h2 className="text-sm font-semibold text-zinc-900 dark:text-zinc-50">
        Attack chains{!loading && !error ? ` (${chains.length})` : ""}
      </h2>

      {loading && (
        <div className="rounded-xl border border-zinc-200 bg-white p-4 text-sm text-zinc-500 dark:border-zinc-800 dark:bg-zinc-950 dark:text-zinc-400">
          Correlating anomalies into attack chains&hellip;
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-zinc-200 bg-white p-4 text-sm text-red-600 dark:border-zinc-800 dark:bg-zinc-950 dark:text-red-400">
          {error}
        </div>
      )}

      {!loading && !error && chains.map((chain) => <ChainCard key={`${chain.entity_type}-${chain.entity_value}`} chain={chain} />)}
    </div>
  );
}
