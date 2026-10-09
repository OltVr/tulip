import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  CheckIcon,
  ClipboardCopyIcon,
  DownloadIcon,
  EyeIcon,
  RefreshIcon,
  XIcon,
} from "@heroicons/react/outline";

import {
  useGetIngestionHealthQuery,
  useGetTriageQuery,
  useLazyGetAttackFarmExportQuery,
} from "../api";
import {
  AttackFarmExport,
  TriageClassification,
  TriageGroup,
} from "../types";


const badgeStyles: Record<TriageClassification, string> = {
  attack: "bg-rose-100 text-rose-800 border-rose-200",
  unknown: "bg-amber-100 text-amber-800 border-amber-200",
  checker: "bg-teal-100 text-teal-800 border-teal-200",
};

const filterStyles: Record<"all" | TriageClassification, string> = {
  all: "border-slate-800 bg-slate-900 text-white ring-slate-300",
  attack: "border-rose-600 bg-rose-600 text-white ring-rose-200",
  unknown: "border-amber-500 bg-amber-500 text-slate-900 ring-amber-200",
  checker: "border-teal-600 bg-teal-600 text-white ring-teal-200",
};

const labels: Record<TriageClassification, string> = {
  attack: "Likely attack",
  unknown: "Needs review",
  checker: "Likely checker",
};

function ageLabel(seconds: number | null) {
  if (seconds == null) return "no traffic captured";
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s ago`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m ago`;
  return `${Math.round(seconds / 3600)}h ago`;
}

function ExportPanel({
  value,
  onClose,
}: {
  value: AttackFarmExport;
  onClose: () => void;
}) {
  const [code, setCode] = useState(value.code);
  const [panel, setPanel] = useState<"code" | "setup">("code");
  const [copied, setCopied] = useState<string | null>(null);
  const edited = code !== value.code;

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const copyText = async (text: string, label: string) => {
    await navigator.clipboard.writeText(text);
    setCopied(label);
    window.setTimeout(() => setCopied((current) => current === label ? null : current), 1600);
  };

  const download = () => {
    const url = URL.createObjectURL(new Blob([code], { type: "text/x-python" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = value.filename;
    link.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-slate-900/60 p-4 backdrop-blur-sm"
      onMouseDown={(event) => event.target === event.currentTarget && onClose()}
      role="presentation"
    >
      <section
        aria-labelledby="export-title"
        aria-modal="true"
        className="flex max-h-[calc(100vh-2rem)] w-full max-w-6xl flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-2xl"
        role="dialog"
      >
        <header className="flex items-center gap-4 border-b border-slate-200 px-5 py-4">
          <div className="min-w-0">
            <div className="mb-1 flex items-center gap-2">
              <span className="rounded-md bg-rose-100 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-rose-700">
                Replay builder
              </span>
              {edited && <span className="text-xs font-medium text-amber-700">Edited locally</span>}
            </div>
            <h2 id="export-title" className="truncate text-xl font-bold text-slate-900">{value.filename}</h2>
            <p className="text-sm text-slate-500">
              {value.service} · {value.protocol.toUpperCase()} port {value.port} · {value.runtime}
            </p>
          </div>
          <button className="rose-icon-button ml-auto" onClick={onClose} title="Close (Esc)" type="button">
            <XIcon className="h-5 w-5" />
            <span className="sr-only">Close export</span>
          </button>
        </header>

        <div className="flex border-b border-slate-200 bg-slate-50 px-5 pt-2" role="tablist" aria-label="Export sections">
          {(["code", "setup"] as const).map((name) => (
            <button
              aria-selected={panel === name}
              className={`border-b-2 px-4 py-2 text-sm font-semibold capitalize transition-colors ${
                panel === name
                  ? "border-rose-600 text-rose-700"
                  : "border-transparent text-slate-500 hover:text-slate-900"
              }`}
              key={name}
              onClick={() => setPanel(name)}
              role="tab"
              type="button"
            >
              {name === "code" ? "Generated code" : "Setup & variables"}
            </button>
          ))}
        </div>

        {panel === "code" ? (
          <div className="flex min-h-0 flex-1 flex-col">
            {value.candidates.length > 0 && (
              <div className="border-b border-slate-200 bg-amber-50/60 px-5 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <div className="mr-2">
                    <p className="text-xs font-bold text-slate-800">Dynamic values</p>
                    <p className="text-[11px] text-slate-500">Click to copy; promote only checker-provided values.</p>
                  </div>
                  {value.candidates.map((candidate) => (
                    <button
                      className={`max-w-sm truncate rounded-lg border px-2.5 py-1.5 text-left font-mono text-xs transition-colors focus-visible:ring-2 focus-visible:ring-rose-500 ${
                        candidate.recommended_attack_info
                          ? "border-emerald-300 bg-emerald-50 text-emerald-900 hover:bg-emerald-100"
                          : "border-amber-300 bg-white text-amber-900 hover:bg-amber-100"
                      }`}
                      key={`${candidate.kind}-${candidate.value}`}
                      onClick={() => copyText(candidate.value, candidate.value)}
                      title={`Copy ${candidate.value}`}
                      type="button"
                    >
                      {copied === candidate.value ? "Copied · " : candidate.recommended_attack_info ? "Likely attack-info · " : "Review · "}
                      {candidate.value}
                    </button>
                  ))}
                </div>
              </div>
            )}
            <label className="sr-only" htmlFor="generated-exploit">Generated exploit code</label>
            <textarea
              className="min-h-[360px] flex-1 resize-none border-0 bg-slate-900 p-5 font-mono text-xs leading-relaxed text-slate-100 focus:ring-0"
              id="generated-exploit"
              onChange={(event) => setCode(event.target.value)}
              spellCheck={false}
              value={code}
            />
          </div>
        ) : (
          <div className="min-h-0 flex-1 overflow-y-auto p-5">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-4">
                <div className="font-bold text-emerald-900">Competition mode</div>
                <p className="mt-1 text-sm text-emerald-800">
                  Resolves teams and valid flag IDs from attack.json. NOP is skipped by default.
                </p>
                <button
                  className="mt-3 flex w-full items-center justify-between rounded-lg border border-emerald-200 bg-white px-3 py-2 text-left font-mono text-xs text-emerald-900 hover:border-emerald-400"
                  onClick={() => copyText(`pip install ecsc2026ad ${value.protocol === "tcp" ? "pwntools" : "requests"}`, "install")}
                  type="button"
                >
                  <span>pip install ecsc2026ad {value.protocol === "tcp" ? "pwntools" : "requests"}</span>
                  {copied === "install" ? <CheckIcon className="h-4 w-4" /> : <ClipboardCopyIcon className="h-4 w-4" />}
                </button>
              </div>
              <div className="rounded-xl border border-blue-200 bg-blue-50 p-4">
                <div className="font-bold text-blue-900">Single-target mode</div>
                <p className="mt-1 text-sm text-blue-800">
                  Compatible with AttackFarm through TARGET_HOST, XFARM_HOST, or TARGET_IP.
                </p>
                <button
                  className="mt-3 flex w-full items-center justify-between rounded-lg border border-blue-200 bg-white px-3 py-2 text-left font-mono text-xs text-blue-900 hover:border-blue-400"
                  onClick={() => copyText(`python ${value.filename} --host 10.60.2.2`, "single")}
                  type="button"
                >
                  <span>python {value.filename} --host 10.60.2.2</span>
                  {copied === "single" ? <CheckIcon className="h-4 w-4" /> : <ClipboardCopyIcon className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div className="mt-5 grid gap-5 lg:grid-cols-2">
              <div>
                <h3 className="text-sm font-bold text-slate-900">Runtime overrides</h3>
                <div className="mt-2 divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white">
                  {value.variables.map((variable) => (
                    <div className="flex items-start justify-between gap-4 px-3 py-2" key={variable.name}>
                      <code className="text-xs font-semibold text-slate-800">{variable.name}</code>
                      <span className="text-right text-xs text-slate-500">{variable.purpose}</span>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <h3 className="text-sm font-bold text-slate-900">Per-target context</h3>
                <div className="mt-2 divide-y divide-slate-100 rounded-xl border border-slate-200 bg-white">
                  {value.context_fields.map((field) => (
                    <div className="flex items-start justify-between gap-4 px-3 py-2" key={field.name}>
                      <code className="text-xs font-semibold text-slate-800">{field.name}</code>
                      <span className="text-right text-xs text-slate-500">{field.purpose}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

        <footer className="flex flex-wrap items-center gap-2 border-t border-slate-200 bg-white px-5 py-3">
          <span className="mr-auto text-xs text-slate-500">
            {panel === "code" ? `${code.split("\n").length} lines · ${edited ? "modified" : "generated by Rose"}` : "Use --dry-run before farming"}
          </span>
          {edited && (
            <button className="rose-button-ghost" onClick={() => setCode(value.code)} type="button">
              Reset changes
            </button>
          )}
          <button className="rose-button-secondary" onClick={() => copyText(code, "code")} type="button">
            {copied === "code" ? <CheckIcon className="h-4 w-4 text-emerald-600" /> : <ClipboardCopyIcon className="h-4 w-4" />}
            {copied === "code" ? "Copied" : "Copy code"}
          </button>
          <button className="rose-button-primary" onClick={download} type="button">
            <DownloadIcon className="h-4 w-4" />
            Download
          </button>
        </footer>
      </section>
    </div>
  );
}

function GroupCard({
  group,
  exporting,
  regexCopied,
  onCopyRegex,
  onExport,
}: {
  group: TriageGroup;
  exporting: boolean;
  regexCopied: boolean;
  onCopyRegex: (group: TriageGroup) => void;
  onExport: (id: string) => void;
}) {
  return (
    <article className="flex flex-col gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm transition-shadow hover:shadow-md">
      <div className="flex flex-wrap items-center gap-2">
        <span className={`rounded-full border px-2.5 py-1 text-xs font-bold ${badgeStyles[group.classification]}`}>
          {labels[group.classification]} · {group.confidence}%
        </span>
        <span className={`rounded-full px-2 py-1 text-[10px] font-semibold uppercase tracking-wide ${
          group.source.startsWith("live") ? "bg-violet-100 text-violet-700" : "bg-slate-100 text-slate-500"
        }`}>
          {group.source}
        </span>
        <span className="ml-auto whitespace-nowrap text-xs text-slate-500">
          {group.count} flow{group.count === 1 ? "" : "s"}
        </span>
      </div>

      <div>
        <div className="font-bold text-slate-900">
          {group.service} <span className="font-normal text-slate-400">:{group.port_dst}</span>
        </div>
        <code className="mt-1 block break-all rounded-lg bg-slate-50 px-2 py-1.5 text-sm text-slate-700">
          {group.method && <span className="font-bold text-blue-700">{group.method} </span>}
          {group.path || group.request_preview || "No client payload"}
        </code>
      </div>

      <div className="grid grid-cols-3 gap-3 rounded-lg border border-slate-100 bg-slate-50/60 p-2 text-xs text-slate-500">
        <div>Status <strong className="block text-slate-800">{group.status ?? "—"}</strong></div>
        <div>Request <strong className="block text-slate-800">{group.request_bytes} B</strong></div>
        <div>Response <strong className="block text-slate-800">{group.response_bytes} B</strong></div>
      </div>

      <ul className="list-disc pl-4 text-xs text-slate-600">
        {group.reasons.map((reason) => <li key={reason}>{reason}</li>)}
      </ul>

      {group.firegex && (
        <div className="rounded-xl border border-rose-200 bg-rose-50 p-3">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="text-sm font-bold text-rose-900">Firegex block rule</span>
            <span className="rounded bg-white px-2 py-0.5 text-[10px] text-rose-800 ring-1 ring-rose-200">mode {group.firegex.mode}</span>
            <span className="rounded bg-white px-2 py-0.5 text-[10px] text-rose-800 ring-1 ring-rose-200">
              {group.firegex.case_sensitive ? "case-sensitive" : "case-insensitive"}
            </span>
            <button
              className="ml-auto inline-flex min-h-[30px] items-center gap-1.5 rounded-md border border-rose-200 bg-white px-2.5 text-xs font-semibold text-rose-700 hover:border-rose-300 hover:bg-rose-100 focus-visible:ring-2 focus-visible:ring-rose-500"
              onClick={() => onCopyRegex(group)}
              type="button"
            >
              {regexCopied ? <CheckIcon className="h-3.5 w-3.5" /> : <ClipboardCopyIcon className="h-3.5 w-3.5" />}
              {regexCopied ? "Copied" : "Copy rule"}
            </button>
          </div>
          <code className="block select-all break-all rounded-lg bg-slate-900 p-2.5 text-xs leading-relaxed text-rose-100">
            {group.firegex.pattern}
          </code>
          <p className="mt-2 text-[11px] text-rose-800">{group.firegex.warning}</p>
        </div>
      )}

      <div className="mt-auto flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3">
        <code className="mr-auto text-[10px] text-slate-400" title="Traffic fingerprint">#{group.fingerprint}</code>
        <Link className="rose-button-secondary" to={`/flow/${group.representative_flow_id}`}>
          <EyeIcon className="h-4 w-4" />
          Inspect evidence
        </Link>
        <button
          className={group.classification === "attack" ? "rose-button-primary" : "rose-button-dark"}
          disabled={exporting}
          onClick={() => onExport(group.representative_flow_id)}
          type="button"
        >
          {exporting && <RefreshIcon className="h-4 w-4 animate-spin" />}
          {exporting ? "Building…" : "Generate replay"}
        </button>
      </div>
    </article>
  );
}

export function TriageView() {
  const [filter, setFilter] = useState<"all" | TriageClassification>("all");
  const [exportValue, setExportValue] = useState<AttackFarmExport | null>(null);
  const [exportingId, setExportingId] = useState<string | null>(null);
  const [copiedRegex, setCopiedRegex] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { data: health, refetch: refetchHealth, isFetching: isHealthFetching } = useGetIngestionHealthQuery(undefined, { pollingInterval: 10000 });
  const { data: groups = [], isFetching, refetch } = useGetTriageQuery(1000, { pollingInterval: 15000 });
  const [loadExport] = useLazyGetAttackFarmExportQuery();

  const counts = useMemo(() => ({
    attack: groups.filter((group) => group.classification === "attack").length,
    unknown: groups.filter((group) => group.classification === "unknown").length,
    checker: groups.filter((group) => group.classification === "checker").length,
  }), [groups]);
  const liveGroupCount = useMemo(
    () => groups.filter((group) => group.source.startsWith("live")).length,
    [groups],
  );
  const visibleGroups = filter === "all" ? groups : groups.filter((group) => group.classification === filter);

  const openExport = async (id: string) => {
    setError(null);
    setExportingId(id);
    try {
      setExportValue(await loadExport(id).unwrap());
    } catch {
      setError("Rose could not generate this replay. Inspect the flow and try again.");
    } finally {
      setExportingId(null);
    }
  };

  const copyRegex = async (group: TriageGroup) => {
    if (!group.firegex) return;
    try {
      await navigator.clipboard.writeText(group.firegex.pattern);
      setCopiedRegex(group.fingerprint);
      window.setTimeout(() => setCopiedRegex((current) => current === group.fingerprint ? null : current), 1600);
    } catch {
      setError("Clipboard access failed. Select the rule text and copy it manually.");
    }
  };

  const refresh = () => {
    setError(null);
    refetch();
    refetchHealth();
  };

  return (
    <div className="min-h-full bg-gradient-to-br from-slate-50 via-white to-rose-50 p-6">
      {exportValue && <ExportPanel value={exportValue} onClose={() => setExportValue(null)} />}

      {error && (
        <div className="mb-4 flex items-center gap-3 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800" role="alert">
          <span className="font-bold">Action failed</span>
          <span>{error}</span>
          <button className="rose-icon-button ml-auto" onClick={() => setError(null)} type="button">
            <XIcon className="h-4 w-4" />
            <span className="sr-only">Dismiss error</span>
          </button>
        </div>
      )}

      <div className={`mb-4 flex items-center gap-3 rounded-xl border p-3 ${
        health?.status === "healthy" ? "border-emerald-200 bg-emerald-50" : "border-red-300 bg-red-50"
      }`}>
        <span className={`h-2.5 w-2.5 rounded-full ${health?.status === "healthy" ? "bg-emerald-500" : "bg-red-500"}`} />
        <div>
          <div className="text-sm font-bold capitalize text-slate-900">Capture {health?.status ?? "checking"}</div>
          <div className="text-xs text-slate-600">
            Last flow {ageLabel(health?.age_seconds ?? null)} · {health?.flows_last_minute ?? 0} flows/min
            {health?.capture_delay_ticks != null && ` · ${health.capture_delay_ticks} ticks behind`}
          </div>
        </div>
        <button className="rose-button-secondary ml-auto" disabled={isHealthFetching || isFetching} onClick={refresh} type="button">
          <RefreshIcon className={`h-4 w-4 ${(isHealthFetching || isFetching) ? "animate-spin" : ""}`} />
          Refresh traffic
        </button>
      </div>

      <div className="mb-5 flex items-center gap-4 rounded-2xl bg-slate-900 p-5 text-white shadow-lg">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-rose-500/15 ring-1 ring-rose-400/20">
          <img aria-hidden="true" className="rose-logo-on-dark h-10 w-10" src="/rose-mark.png" />
        </div>
        <div>
          <div className="text-[10px] font-bold uppercase tracking-[0.24em] text-rose-300">Rose defender console</div>
          <h1 className="text-2xl font-bold">Traffic intelligence</h1>
          <p className="text-sm text-slate-300">Decide faster: classify, inspect evidence, then generate a reproducible replay.</p>
        </div>
        <div className="ml-auto hidden gap-6 text-right lg:flex">
          <div>
            <div className="text-2xl font-bold">{counts.attack}</div>
            <div className="text-xs text-slate-400">attack groups</div>
          </div>
          <div>
            <div className="text-2xl font-bold">{liveGroupCount}</div>
            <div className="text-xs text-slate-400">live groups</div>
          </div>
        </div>
      </div>

      <div className="mb-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4" role="group" aria-label="Traffic classification filter">
        {(["all", "attack", "unknown", "checker"] as const).map((name) => {
          const count = name === "all" ? groups.length : counts[name];
          const active = filter === name;
          return (
            <button
              aria-pressed={active}
              className={`group rounded-xl border p-3 text-left shadow-sm transition-all focus-visible:ring-2 focus-visible:ring-rose-500 focus-visible:ring-offset-2 ${
                active ? `${filterStyles[name]} ring-2 ring-offset-2` : "border-slate-200 bg-white text-slate-900 hover:-translate-y-0.5 hover:border-slate-300 hover:shadow-md"
              }`}
              key={name}
              onClick={() => setFilter(name)}
              type="button"
            >
              <div className={`text-[10px] font-bold uppercase tracking-wider ${active ? "opacity-80" : "text-slate-500"}`}>
                {name === "all" ? "All traffic groups" : labels[name]}
              </div>
              <div className="mt-1 flex items-end justify-between">
                <span className="text-2xl font-bold">{count}</span>
                <span className={`text-xs font-semibold ${active ? "opacity-80" : "text-slate-400 group-hover:text-slate-600"}`}>
                  {active ? "Showing" : "View"}
                </span>
              </div>
            </button>
          );
        })}
      </div>

      {visibleGroups.length > 0 ? (
        <div className="grid gap-4 xl:grid-cols-2">
          {visibleGroups.map((group) => (
            <GroupCard
              exporting={exportingId === group.representative_flow_id}
              group={group}
              key={group.fingerprint}
              onCopyRegex={copyRegex}
              onExport={openExport}
              regexCopied={copiedRegex === group.fingerprint}
            />
          ))}
        </div>
      ) : (
        <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-10 text-center">
          <div className="text-lg font-bold text-slate-800">No groups in this view</div>
          <p className="mt-1 text-sm text-slate-500">Choose another classification or refresh the capture.</p>
          <button className="rose-button-secondary mt-4" onClick={() => setFilter("all")} type="button">Show all groups</button>
        </div>
      )}
    </div>
  );
}
