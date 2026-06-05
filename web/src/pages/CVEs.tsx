import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Check, Clipboard, ShieldAlert } from "lucide-react";
import { Link } from "react-router-dom";
import { listCVEs, type CVEMatch } from "../api/client";
import { useSessionContext } from "../session";
import { sortLabel, useSortableRows } from "../sort";

type FixFilter = "" | "fixable" | "unfixable";
type ExploitFilter = "" | "exploitable" | "no-known-exploit";

export function CVEs() {
  const { selectedSessionID } = useSessionContext();
  const [packageFilter, setPackageFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [fixFilter, setFixFilter] = useState<FixFilter>("");
  const [exploitFilter, setExploitFilter] = useState<ExploitFilter>("");
  const [copiedID, setCopiedID] = useState("");
  const cvesQuery = useQuery({ queryKey: ["cves", selectedSessionID], queryFn: () => listCVEs(selectedSessionID), enabled: selectedSessionID !== "" });
  const cves = cvesQuery.data ?? [];
  const packages = useMemo(() => uniqueSorted(cves.map(packageLabel).filter(Boolean)), [cves]);
  const sources = useMemo(() => uniqueSorted(cves.map((cve) => cve.source).filter(Boolean)), [cves]);
  const filteredCVEs = useMemo(() => filterCVEs(cves, { packageFilter, sourceFilter, fixFilter, exploitFilter }), [cves, exploitFilter, fixFilter, packageFilter, sourceFilter]);
  type CVESortKey = "cve" | "cvss" | "severity" | "source" | "package" | "fixed" | "exploit" | "description";
  const accessors = useMemo<Record<CVESortKey, (cve: CVEMatch) => string | number | boolean>>(() => ({
    cve: (cve: CVEMatch) => cve.cve_id,
    cvss: (cve: CVEMatch) => cve.cvss_v3_score,
    severity: (cve: CVEMatch) => severityRank(cveSeverity(cve.cvss_v3_score)),
    source: (cve: CVEMatch) => cve.source,
    package: (cve: CVEMatch) => packageLabel(cve),
    fixed: (cve: CVEMatch) => cve.fixed_version || "",
    exploit: (cve: CVEMatch) => cve.exploit_available,
    description: (cve: CVEMatch) => cve.description,
  }), []);
  const { sortedRows, sort, toggleSort } = useSortableRows<CVEMatch, CVESortKey>(filteredCVEs, { key: "cvss", direction: "desc" }, accessors);
  const hasFilters = Boolean(packageFilter || sourceFilter || fixFilter || exploitFilter);

  async function copyRowText(value: string, id: string) {
    if (navigator.clipboard) {
      try {
        await navigator.clipboard.writeText(value);
      } catch {
        // Clipboard permissions can be unavailable in hardened browser contexts.
      }
    }
    setCopiedID(id);
  }

  return (
    <section className="page wide-page">
      <header className="page-header">
        <div>
          <h1>CVE Intelligence</h1>
          <p>Correlated CVE intelligence, exploit signals, patch status, package versions, and references.</p>
        </div>
      </header>
      {cves.length === 0 ? (
        <section className="panel empty-state-panel">
          <h2>No CVEs Correlated</h2>
          <p>CVE rows appear when scanner evidence, source package metadata, or technology fingerprints include package and version context. Run fingerprinting, source audit, or CVE-enabled profiles to enrich this view.</p>
          <Link className="primary link-button" to="/scan">Build CVE-Aware Scan</Link>
        </section>
      ) : null}
      {cves.length > 0 ? (
        <section className="filter-bar cve-filter-bar" aria-label="CVE filters">
          <label className="compact-control">
            Package
            <select value={packageFilter} onChange={(event) => setPackageFilter(event.target.value)}>
              <option value="">All</option>
              {packages.map((item) => <option key={item} value={item}>{item}</option>)}
            </select>
          </label>
          <label className="compact-control">
            Source
            <select value={sourceFilter} onChange={(event) => setSourceFilter(event.target.value)}>
              <option value="">All</option>
              {sources.map((item) => <option key={item} value={item}>{cveSourceLabel(item)}</option>)}
            </select>
          </label>
          <label className="compact-control">
            Fixability
            <select value={fixFilter} onChange={(event) => setFixFilter(event.target.value as FixFilter)}>
              <option value="">All</option>
              <option value="fixable">Fixable</option>
              <option value="unfixable">No fixed version</option>
            </select>
          </label>
          <label className="compact-control">
            Exploitability
            <select value={exploitFilter} onChange={(event) => setExploitFilter(event.target.value as ExploitFilter)}>
              <option value="">All</option>
              <option value="exploitable">Known exploit</option>
              <option value="no-known-exploit">No known exploit</option>
            </select>
          </label>
          {hasFilters ? <button className="secondary compact-button" type="button" onClick={() => {
            setPackageFilter("");
            setSourceFilter("");
            setFixFilter("");
            setExploitFilter("");
          }}>Clear Filters</button> : null}
        </section>
      ) : null}
      <section className="panel">
        <div className="table-wrap">
          <table className="cve-table">
            <thead><tr>
              <SortableHeader label="CVE" active={sort.key === "cve"} direction={sort.direction} onClick={() => toggleSort("cve")} />
              <SortableHeader label="Severity" active={sort.key === "severity"} direction={sort.direction} onClick={() => toggleSort("severity")} />
              <SortableHeader label="CVSS" active={sort.key === "cvss"} direction={sort.direction} onClick={() => toggleSort("cvss")} />
              <SortableHeader label="Source" active={sort.key === "source"} direction={sort.direction} onClick={() => toggleSort("source")} />
              <SortableHeader label="Package" active={sort.key === "package"} direction={sort.direction} onClick={() => toggleSort("package")} />
              <SortableHeader label="Fixed" active={sort.key === "fixed"} direction={sort.direction} onClick={() => toggleSort("fixed")} />
              <SortableHeader label="Exploit" active={sort.key === "exploit"} direction={sort.direction} onClick={() => toggleSort("exploit")} />
              <SortableHeader label="Description" active={sort.key === "description"} direction={sort.direction} onClick={() => toggleSort("description")} />
              <th>References</th>
            </tr></thead>
            <tbody>
              {sortedRows.map((cve) => {
                const severity = cveSeverity(cve.cvss_v3_score);
                const copyCVEID = `cve:${cve.id}`;
                const copyVectorID = `vector:${cve.id}`;
                return (
                  <tr key={cve.id}>
                    <td>
                      <div className="cve-id-cell">
                        <strong>{cve.cve_id}</strong>
                        <button className="icon-button inline-copy-button" type="button" onClick={() => void copyRowText(cve.cve_id, copyCVEID)} aria-label={`Copy ${cve.cve_id}`}>
                          {copiedID === copyCVEID ? <Check size={14} /> : <Clipboard size={14} />}
                        </button>
                      </div>
                      <small>{cve.finding_id || cve.technology_id || ""}</small>
                    </td>
                    <td><span className={`severity ${severity}`}>{severity}</span></td>
                    <td>
                      <strong>{cve.cvss_v3_score.toFixed(1)}</strong>
                      {cve.cvss_v3_vector ? (
                        <button className="secondary compact-button vector-copy-button" type="button" onClick={() => void copyRowText(cve.cvss_v3_vector ?? "", copyVectorID)}>
                          {copiedID === copyVectorID ? <Check size={14} /> : <Clipboard size={14} />}Vector
                        </button>
                      ) : null}
                    </td>
                    <td><span className={`cve-source ${cveSourceKind(cve.source)}`}>{cveSourceLabel(cve.source)}</span></td>
                    <td>
                      <strong>{packageLabel(cve) || "Unknown package"}</strong>
                      <small>{cve.affected_version ? `Affected ${cve.affected_version}` : cve.package_version ? `Detected ${cve.package_version}` : "No version recorded"}</small>
                    </td>
                    <td>{cve.fixed_version ? <code>{cve.fixed_version}</code> : <span className="muted-line">No fixed version</span>}</td>
                    <td>{cve.exploit_available ? <span className="exploit-badge"><ShieldAlert size={13} />Known</span> : <span className="muted-line">No known exploit</span>}</td>
                    <td>{cve.description}</td>
                    <td>{(cve.references ?? []).slice(0, 3).map((ref) => <a key={ref} href={ref}>{compactReference(ref)}</a>)}</td>
                  </tr>
                );
              })}
              {cves.length === 0 ? <tr><td colSpan={9}>No CVEs correlated for the selected session.</td></tr> : null}
              {cves.length > 0 && sortedRows.length === 0 ? <tr><td colSpan={9}>No CVEs match the current filters.</td></tr> : null}
            </tbody>
          </table>
        </div>
      </section>
    </section>
  );
}

function SortableHeader({ label, active, direction, onClick }: { label: string; active: boolean; direction: "asc" | "desc"; onClick: () => void }) {
  return <th><button className="table-sort" type="button" onClick={onClick}>{label}{sortLabel(active, direction)}</button></th>;
}

type CVEFilters = {
  packageFilter: string;
  sourceFilter: string;
  fixFilter: FixFilter;
  exploitFilter: ExploitFilter;
};

export function filterCVEs(cves: CVEMatch[], filters: CVEFilters) {
  return cves.filter((cve) => {
    if (filters.packageFilter && packageLabel(cve) !== filters.packageFilter) return false;
    if (filters.sourceFilter && cve.source !== filters.sourceFilter) return false;
    if (filters.fixFilter === "fixable" && !cve.fixed_version && !cve.patch_available) return false;
    if (filters.fixFilter === "unfixable" && (cve.fixed_version || cve.patch_available)) return false;
    if (filters.exploitFilter === "exploitable" && !cve.exploit_available) return false;
    if (filters.exploitFilter === "no-known-exploit" && cve.exploit_available) return false;
    return true;
  });
}

export function cveSeverity(score: number) {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "info";
}

export function packageLabel(cve: Pick<CVEMatch, "package_name" | "package_version">) {
  return [cve.package_name, cve.package_version].filter(Boolean).join("@");
}

export function cveSourceKind(source: string) {
  const normalized = source.toLowerCase();
  if (normalized.includes("audit") || normalized.includes("source") || normalized.includes("dependency") || normalized.includes("grype") || normalized.includes("npm")) return "dependency";
  if (normalized.includes("osint")) return "osint";
  return "dynamic";
}

export function cveSourceLabel(source: string) {
  const kind = cveSourceKind(source);
  if (kind === "dependency") return "Dependency audit";
  if (kind === "osint") return "OSINT";
  return "Dynamic";
}

function severityRank(severity: string) {
  return { info: 1, low: 2, medium: 3, high: 4, critical: 5 }[severity] ?? 0;
}

function uniqueSorted(values: string[]) {
  return [...new Set(values)].sort((left, right) => left.localeCompare(right));
}

function compactReference(value: string) {
  try {
    const url = new URL(value);
    return url.hostname.replace(/^www\./, "");
  } catch {
    return value;
  }
}
