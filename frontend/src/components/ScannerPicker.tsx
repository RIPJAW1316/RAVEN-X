import {
  Activity, BookOpenCheck, Check, CheckCheck, ClipboardList, FileClock, Fingerprint,
  Layers, LayoutGrid, ListChecks, Network, ScanLine, Search, ShieldCheck, SlidersHorizontal,
  X, type LucideIcon,
} from "lucide-react";
import { useId, useState } from "react";
import { DEFAULT_SCANNER_IDS, KNOWN_SCANNERS, SCANNER_DOMAINS } from "../lib/scanners";
import "./scan-library.css";

type Domain = (typeof SCANNER_DOMAINS)[number];
type CatalogCheck = (typeof KNOWN_SCANNERS)[number];
type Template = {
  name: string;
  description: string;
  icon: LucideIcon;
  tone: string;
  checks: CatalogCheck[];
};

const domainDesign: Record<Domain, Omit<Template, "name" | "checks">> = {
  "Network & remote access": { icon: Network, tone: "blue", description: "Firewall, SMB, DNS and remote access settings." },
  "Identity & access": { icon: Fingerprint, tone: "amber", description: "Local accounts, sign-in and credential policies." },
  "Endpoint protection": { icon: ShieldCheck, tone: "green", description: "Defender, disk encryption and Secure Boot." },
  "Updates & servicing": { icon: FileClock, tone: "violet", description: "Update services, hotfix history and pending restarts." },
  "System hardening": { icon: SlidersHorizontal, tone: "coral", description: "Startup scripts, AutoRun and system file signatures." },
  "Audit & logging": { icon: ClipboardList, tone: "teal", description: "Logon auditing, PowerShell logging and security events." },
};

const domains: Template[] = SCANNER_DOMAINS.map((name) => ({
  name, ...domainDesign[name], checks: KNOWN_SCANNERS.filter((scanner) => scanner.domain === name),
}));
const quickIds = new Set(["windows.firewall", "windows.uac", "windows.smb", "windows.bitlocker"]);
const presets: Template[] = [
  { name: "Quick scan", description: "Firewall, UAC, SMB and BitLocker.", icon: Activity, tone: "blue",
    checks: KNOWN_SCANNERS.filter((check) => quickIds.has(check.scanner_id)) },
  { name: "Windows baseline", description: "Core checks across all six security domains.", icon: BookOpenCheck, tone: "green",
    checks: KNOWN_SCANNERS.filter((check) => DEFAULT_SCANNER_IDS.includes(check.scanner_id)) },
  { name: "Full Windows scan", description: "Every Windows check in the catalog.", icon: ScanLine, tone: "amber",
    checks: KNOWN_SCANNERS },
];
const templates = [...presets, ...domains];

function TemplateCard({ template, active, onSelect }: {
  template: Template;
  active: boolean;
  onSelect: (checks: string[]) => void;
}) {
  const descriptionId = useId();
  const Icon = template.icon;
  return (
    <button type="button" className={`scan-card scan-tone-${template.tone}`}
      aria-label={template.name} aria-describedby={`${descriptionId}-count ${descriptionId}`} aria-pressed={active}
      onClick={() => onSelect(template.checks.map((check) => check.scanner_id))}>
      <span className="scan-card-top">
        <span className="scan-icon"><Icon size={18} strokeWidth={1.85} aria-hidden="true" /></span>
        <span className="scan-card-count" id={`${descriptionId}-count`}>{active && <Check size={13} aria-hidden="true" />}{template.checks.length} checks</span>
      </span>
      <strong>{template.name}</strong>
      <span className="scan-card-description" id={descriptionId}>{template.description}</span>
    </button>
  );
}

export function ScannerPicker({ selected, onChange }: { selected: string[]; onChange: (ids: string[]) => void }) {
  const [view, setView] = useState<"templates" | "checks">("templates");
  const [query, setQuery] = useState("");
  const [domainFilter, setDomainFilter] = useState("");
  const active = new Set(selected);
  const activeTemplate = templates.find(({ checks }) =>
    checks.length === active.size && checks.every(({ scanner_id }) => active.has(scanner_id)));
  const term = query.trim().toLowerCase();
  function matches(...values: string[]) {
    return values.some((value) => value.toLowerCase().includes(term));
  }
  function matchesCheck(check: CatalogCheck) {
    return matches(check.name, check.scanner_id, check.description, check.domain);
  }
  function cards(title: string, group: Template[]) {
    const visible = group.filter((item) => matches(item.name, item.description) || item.checks.some(matchesCheck));
    if (!visible.length) return null;
    return (
      <section className="scan-section" aria-label={title}>
        <h4>{title}</h4>
        <div className="scan-card-grid">
          {visible.map((item) => <TemplateCard key={item.name} template={item}
            active={item === activeTemplate} onSelect={onChange} />)}
        </div>
      </section>
    );
  }
  const presetCards = view === "templates" && cards("General assessments", presets);
  const domainCards = view === "templates" && cards("Security domains", domains);
  const groups = domains.filter((domain) => !domainFilter || domain.name === domainFilter)
    .map((domain) => ({ ...domain, checks: domain.checks.filter(matchesCheck) }))
    .filter((domain) => domain.checks.length > 0);
  const empty = view === "templates" ? !presetCards && !domainCards : !groups.length;

  function toggleChecks(checks: CatalogCheck[], add: boolean) {
    const next = new Set(active);
    for (const check of checks) {
      if (add) next.add(check.scanner_id);
      else next.delete(check.scanner_id);
    }
    onChange([...next]);
  }

  return (
    <section className="scan-library" aria-label="Scan library">
      <div className="scan-library-heading">
        <div>
          <h3>Scan library</h3>
          <p>Choose a template to set the scope, or build your own from individual checks.</p>
        </div>
        <span className="scan-current" role="status">
          <Layers size={15} aria-hidden="true" />
          {activeTemplate?.name ?? (selected.length ? "Custom selection" : "No selection")}
          <span className="scan-current-count">{selected.length} of {KNOWN_SCANNERS.length} selected</span>
        </span>
      </div>
      <div className="scan-tools">
        <div className="scan-views" role="group" aria-label="Library view">
          <button type="button" aria-pressed={view === "templates"} onClick={() => setView("templates")}>
            <LayoutGrid size={15} aria-hidden="true" />Templates
          </button>
          <button type="button" aria-pressed={view === "checks"} onClick={() => setView("checks")}>
            <ListChecks size={16} aria-hidden="true" />Individual checks
          </button>
        </div>
        <label className="scan-search">
          <Search size={16} aria-hidden="true" />
          <input type="search" aria-label="Search scan library" value={query} placeholder="Search the library…"
            onChange={(event) => setQuery(event.target.value)} />
        </label>
      </div>
      {view === "checks" && (
        <label className="scan-filter">Security domain
          <select aria-label="Security domain" value={domainFilter} onChange={(event) => setDomainFilter(event.target.value)}>
            <option value="">All domains</option>
            {SCANNER_DOMAINS.map((name) => <option key={name}>{name}</option>)}
          </select>
        </label>
      )}
      {presetCards}
      {domainCards}
      {view === "checks" && groups.map(({ name, checks, icon: Icon, tone }) => {
        const all = checks.every(({ scanner_id }) => active.has(scanner_id));
        return (
          <fieldset className={`scan-check-group scan-tone-${tone}`} key={name}>
            <legend><Icon size={16} aria-hidden="true" />{name}</legend>
            <div className="scan-group-tools">
              <span>{checks.length} {checks.length === 1 ? "check" : "checks"}{term ? " matching" : ""}</span>
              <button type="button" className="link" onClick={() => toggleChecks(checks, !all)}>
                {all ? "Deselect" : "Select"} {term ? "matching" : "all"}
              </button>
            </div>
            <div className="scan-check-list">
              {checks.map((check) => (
                <label key={check.scanner_id} className="scan-check">
                  <input type="checkbox" checked={active.has(check.scanner_id)}
                    aria-label={check.name} aria-describedby={`hint-${check.scanner_id}`}
                    onChange={(event) => toggleChecks([check], event.target.checked)} />
                  <span><strong>{check.name}</strong><small id={`hint-${check.scanner_id}`}>{check.description}</small></span>
                </label>
              ))}
            </div>
          </fieldset>
        );
      })}
      {empty && <div className="scan-empty">
        <Search size={24} aria-hidden="true" />
        <strong>No {view === "templates" ? "templates" : "checks"} match your search</strong>
        <button className="link" type="button" onClick={() => { setQuery(""); setDomainFilter(""); }}>Reset filters</button>
      </div>}
      <div className="scan-library-foot">
        <small><CheckCheck size={15} aria-hidden="true" />Expanded checks require a matching Windows agent.</small>
        <button type="button" className="ghost small" disabled={!selected.length} onClick={() => onChange([])}>
          <X size={13} aria-hidden="true" />Clear selection
        </button>
      </div>
    </section>
  );
}
