import { useCallback, useEffect, useRef, useState } from "react";

import clsx from "clsx";
import { Activity, CheckCircle2, AlertTriangle, Wrench, Gauge } from "lucide-react";

import { ApiError } from "../../lib/api";
import { forensicApi } from "../../lib/forensicApi";
import type { PipelineHealEvent } from "../../lib/types/forensic";

interface PipelineHealPanelProps {
  jobId: string;
  active?: boolean;
}

function agentIcon(agent: string) {
  if (agent === "repair") return <Wrench className="h-3.5 w-3.5" />;
  if (agent === "performance") return <Gauge className="h-3.5 w-3.5" />;
  if (agent === "huddle") return <Activity className="h-3.5 w-3.5 text-orange-600" />;
  return <Activity className="h-3.5 w-3.5" />;
}

function statusClass(status: string) {
  if (status === "resolved") return "text-emerald-700 bg-emerald-50";
  if (status === "failed") return "text-red-700 bg-red-50";
  if (status === "repairing") return "text-amber-800 bg-amber-50";
  return "text-ink-700 bg-slate-50";
}

export function PipelineHealPanel({ jobId, active = true }: PipelineHealPanelProps) {
  const [events, setEvents] = useState<PipelineHealEvent[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [gone, setGone] = useState(false);
  const goneRef = useRef(false);

  const load = useCallback(async () => {
    if (!jobId || goneRef.current) return;
    setLoading(true);
    try {
      const res = await forensicApi.listPipelineHealEvents(jobId, { limit: 20 });
      setEvents(res.events || []);
      setError(null);
    } catch (e: unknown) {
      if (e instanceof ApiError && e.status === 404) {
        goneRef.current = true;
        setGone(true);
        setError(null);
        return;
      }
      setError(e instanceof Error ? e.message : "Could not load heal events");
    } finally {
      setLoading(false);
    }
  }, [jobId]);

  useEffect(() => {
    goneRef.current = false;
    setGone(false);
  }, [jobId]);

  useEffect(() => {
    if (gone) return;
    void load();
  }, [load, gone]);

  useEffect(() => {
    if (!active || gone) return undefined;
    const id = window.setInterval(() => void load(), 30_000);
    return () => window.clearInterval(id);
  }, [active, load, gone]);

  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-semibold text-ink-900">
          <AlertTriangle className="h-4 w-4 text-amber-600" />
          Self-healing issues & remedies
        </div>
        <span className="text-[11px] tabular-nums text-ink-500">
          {loading ? "Refreshing…" : `${events.length} event${events.length === 1 ? "" : "s"}`}
        </span>
      </div>

      {error ? <p className="mb-2 text-[11px] text-amber-800">{error}</p> : null}

      {!events.length && !loading ? (
        <p className="text-[11px] text-ink-500">
          No huddle events yet. Observe, Repair, and Performance will confer here and keep every lane moving without parking the job.
        </p>
      ) : (
        <div className="max-h-56 overflow-auto">
          <table className="w-full text-left text-[11px]">
            <thead className="table-head sticky top-0 text-ink-700">
              <tr>
                <th className="py-1 pr-2 font-medium">When</th>
                <th className="py-1 pr-2 font-medium">Agent</th>
                <th className="py-1 pr-2 font-medium">Issue</th>
                <th className="py-1 pr-2 font-medium">Remedy</th>
                <th className="py-1 font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {events.map((ev) => (
                <tr key={ev.id} className="border-t border-slate-100 align-top">
                  <td className="py-1.5 pr-2 whitespace-nowrap text-ink-500">
                    {ev.created_at ? new Date(ev.created_at).toLocaleTimeString() : "—"}
                  </td>
                  <td className="py-1.5 pr-2">
                    <span className="inline-flex items-center gap-1 font-medium text-ink-800">
                      {agentIcon(ev.agent)}
                      {ev.agent}
                    </span>
                  </td>
                  <td className="py-1.5 pr-2 text-ink-800">
                    <div className="font-medium">{ev.issue_code}</div>
                    {ev.issue_detail ? (
                      <div className="mt-0.5 line-clamp-2 text-ink-500">{ev.issue_detail}</div>
                    ) : null}
                  </td>
                  <td className="py-1.5 pr-2 text-ink-700">
                    {ev.remedy_code ? (
                      <>
                        <div className="font-medium">{ev.remedy_code}</div>
                        {ev.remedy_detail ? (
                          <div className="mt-0.5 line-clamp-2 text-ink-500">{ev.remedy_detail}</div>
                        ) : null}
                      </>
                    ) : (
                      "—"
                    )}
                  </td>
                  <td className="py-1.5">
                    <span
                      className={clsx(
                        "inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-semibold capitalize",
                        statusClass(ev.status)
                      )}
                    >
                      {ev.status === "resolved" ? <CheckCircle2 className="h-3 w-3" /> : null}
                      {ev.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
