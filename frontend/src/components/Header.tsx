import { Suspense } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import {
  ChartBarIcon,
  ClockIcon,
  QuestionMarkCircleIcon,
  SearchIcon,
  SwitchHorizontalIcon,
} from "@heroicons/react/outline";
import {
  Link,
  useNavigate,
  useParams,
  useSearchParams,
} from "react-router-dom";

import {
  END_FILTER_KEY,
  FIRST_DIFF_KEY,
  REPR_ID_KEY,
  SECOND_DIFF_KEY,
  SERVICE_FILTER_KEY,
  SERVICE_REFETCH_INTERVAL_MS,
  START_FILTER_KEY,
  TEXT_FILTER_KEY,
} from "../const";
import { useGetServicesQuery } from "../api";
import { getTickStuff } from "../tick";


function ServiceSelection() {
  const { data: services } = useGetServicesQuery(undefined, {
    pollingInterval: SERVICE_REFETCH_INTERVAL_MS,
  });
  const [searchParams, setSearchParams] = useSearchParams();
  const selected = searchParams.get(SERVICE_FILTER_KEY) ?? "";

  return (
    <select
      aria-label="Filter by service"
      className="header-service-select"
      onChange={(event) => {
        const next = new URLSearchParams(searchParams);
        if (event.target.value) next.set(SERVICE_FILTER_KEY, event.target.value);
        else next.delete(SERVICE_FILTER_KEY);
        setSearchParams(next);
      }}
      value={selected}
    >
      <option value="">All services</option>
      {(services ?? []).map((service) => (
        <option key={service.name} value={service.name}>{service.name}</option>
      ))}
    </select>
  );
}

function TextSearch() {
  const [searchParams, setSearchParams] = useSearchParams();

  useHotkeys("s", (event) => {
    const element = document.getElementById("search") as HTMLInputElement;
    element?.focus();
    element?.select();
    event.preventDefault();
  });

  return (
    <div className="relative min-w-0 flex-1">
      <SearchIcon className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
      <input
        aria-label="Search captured traffic"
        className="header-search-input"
        id="search"
        onChange={(event) => {
          const next = new URLSearchParams(searchParams);
          if (event.target.value) next.set(TEXT_FILTER_KEY, event.target.value);
          else next.delete(TEXT_FILTER_KEY);
          setSearchParams(next);
        }}
        placeholder="Search payload regex…"
        type="text"
        value={searchParams.get(TEXT_FILTER_KEY) || ""}
      />
      <kbd className="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 rounded border border-slate-600 bg-slate-900 px-1.5 py-0.5 text-[9px] font-bold text-slate-500">S</kbd>
    </div>
  );
}

function TickRange() {
  const { startTickParam, endTickParam, setTimeParam, setToLastnTicks } = getTickStuff();

  return (
    <div className="header-control-group" aria-label="Tick range">
      <ClockIcon className="h-4 w-4 shrink-0 text-slate-400" />
      <span className="hidden text-[10px] font-bold uppercase tracking-wider text-slate-500 xl:inline">Ticks</span>
      <input
        aria-label="Start tick"
        className="header-range-input"
        id="startdateselection"
        onChange={(event) => setTimeParam(event.target.value === "" ? null : parseInt(event.target.value), START_FILTER_KEY)}
        placeholder="From"
        type="number"
        value={startTickParam}
      />
      <span className="text-xs text-slate-600">—</span>
      <input
        aria-label="End tick"
        className="header-range-input"
        id="enddateselection"
        onChange={(event) => setTimeParam(event.target.value === "" ? null : parseInt(event.target.value), END_FILTER_KEY)}
        placeholder="To"
        type="number"
        value={endTickParam}
      />
      <button
        className="header-latest-button"
        onClick={() => setToLastnTicks(5)}
        title="Jump to the latest five ticks (A)"
        type="button"
      >
        Latest 5
      </button>
    </div>
  );
}

function ComparisonControls() {
  const params = useParams();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const reprId = searchParams.get(REPR_ID_KEY);
  const currentFlow = params.id ? (reprId ? `${params.id}:${reprId}` : params.id) : null;
  const first = searchParams.get(FIRST_DIFF_KEY);
  const second = searchParams.get(SECOND_DIFF_KEY);
  const visible = Boolean(currentFlow || first || second);

  const setSlot = (key: string, currentValue: string | null) => {
    if (!currentFlow) return;
    const next = new URLSearchParams(searchParams);
    if (currentValue === currentFlow) next.delete(key);
    else next.set(key, currentFlow);
    setSearchParams(next);
  };

  const runComparison = () => {
    if (!first || !second) return;
    const baseId = params.id ?? first.split(":", 1)[0];
    navigate(`/diff/${baseId}?${searchParams}`, { replace: true });
  };

  useHotkeys("f", () => setSlot(FIRST_DIFF_KEY, first));
  useHotkeys("e", () => setSlot(SECOND_DIFF_KEY, second));
  useHotkeys("d", runComparison);

  if (!visible) return null;

  const shortId = (value: string | null) => value ? value.split(":", 1)[0].slice(0, 8) : "Set";

  return (
    <div className="header-control-group ml-auto" aria-label="Flow comparison">
      <SwitchHorizontalIcon className="h-4 w-4 text-slate-400" />
      <span className="hidden text-[10px] font-bold uppercase tracking-wider text-slate-500 2xl:inline">Compare</span>
      <button
        className={`header-slot-button ${first ? "header-slot-button-active" : ""}`}
        disabled={!currentFlow}
        onClick={() => setSlot(FIRST_DIFF_KEY, first)}
        title={first === currentFlow ? "Clear slot A" : "Set current flow as slot A (F)"}
        type="button"
      >
        <span>A</span>{shortId(first)}
      </button>
      <button
        className={`header-slot-button ${second ? "header-slot-button-active" : ""}`}
        disabled={!currentFlow}
        onClick={() => setSlot(SECOND_DIFF_KEY, second)}
        title={second === currentFlow ? "Clear slot B" : "Set current flow as slot B (E)"}
        type="button"
      >
        <span>B</span>{shortId(second)}
      </button>
      <button
        className="header-compare-button"
        disabled={!first || !second}
        onClick={runComparison}
        title="Compare selected flows (D)"
        type="button"
      >
        Compare
      </button>
    </div>
  );
}

export function Header() {
  const { currentTick, setToLastnTicks, setTimeParam } = getTickStuff();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  useHotkeys("g", () => navigate(`/corrie?${searchParams}`, { replace: true }));
  useHotkeys("a", () => setToLastnTicks(5));
  useHotkeys("c", () => {
    setTimeParam(null, START_FILTER_KEY);
    setTimeParam(null, END_FILTER_KEY);
  });

  return (
    <>
      <Link className="header-brand" title="Traffic intelligence" to={`/?${searchParams}`}>
        <span className="header-brand-mark">
          <img aria-hidden="true" className="rose-logo-on-dark h-8 w-8" src="/rose-mark.png" />
        </span>
        <span className="leading-none">
          <span className="block font-black tracking-wide text-white">ROSE</span>
          <span className="block text-[8px] font-bold uppercase tracking-[0.22em] text-rose-300">Defender</span>
        </span>
      </Link>

      <div className="header-search-group">
        <TextSearch />
        <Suspense><ServiceSelection /></Suspense>
      </div>

      <TickRange />

      <nav className="flex items-center gap-1" aria-label="Primary navigation">
        <Link className="header-nav-button" title="Graph view (G)" to={`/corrie?${searchParams}`}>
          <ChartBarIcon className="h-4 w-4" />
          <span className="hidden xl:inline">Graph</span>
        </Link>
        <Link className="header-nav-button" to={`/help?${searchParams}`}>
          <QuestionMarkCircleIcon className="h-4 w-4" />
          <span className="hidden xl:inline">Guide</span>
        </Link>
      </nav>

      <ComparisonControls />

      <div className="header-tick" title="Current competition tick">
        <span>Tick</span>
        <strong>{currentTick}</strong>
      </div>
    </>
  );
}
