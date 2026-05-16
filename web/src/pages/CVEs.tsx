import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import { listCVEs, type CVEMatch } from "../api/client";
import { useSessionContext } from "../session";
import { sortLabel, useSortableRows } from "../sort";

export function CVEs() {
  const { selectedSessionID } = useSessionContext();
  const cvesQuery = useQuery({ queryKey: ["cves", selectedSessionID], queryFn: () => listCVEs(selectedSessionID), enabled: selectedSessionID !== "" });
  const cves = cvesQuery.data ?? [];
  type CVESortKey = "cve" | "cvss" | "source" | "patch" | "exploit" | "description";
  const accessors = useMemo<Record<CVESortKey, (cve: CVEMatch) => string | number | boolean>>(() => ({
    cve: (cve: CVEMatch) => cve.cve_id,
    cvss: (cve: CVEMatch) => cve.cvss_v3_score,
    source: (cve: CVEMatch) => cve.source,
    patch: (cve: CVEMatch) => cve.patch_available,
    exploit: (cve: CVEMatch) => cve.exploit_available,
    description: (cve: CVEMatch) => cve.description,
  }), []);
  const { sortedRows, sort, toggleSort } = useSortableRows<CVEMatch, CVESortKey>(cves, { key: "cvss", direction: "desc" }, accessors);
  return (
    <section className="page wide-page">
      <header className="page-header">
        <div>
          <h1>CVE Intelligence</h1>
          <p>Correlated CVE intelligence, exploit signals, patch status, and references.</p>
        </div>
      </header>
      <section className="panel">
        <div className="table-wrap">
          <table>
            <thead><tr>
              <SortableHeader label="CVE" active={sort.key === "cve"} direction={sort.direction} onClick={() => toggleSort("cve")} />
              <SortableHeader label="CVSS" active={sort.key === "cvss"} direction={sort.direction} onClick={() => toggleSort("cvss")} />
              <SortableHeader label="Source" active={sort.key === "source"} direction={sort.direction} onClick={() => toggleSort("source")} />
              <SortableHeader label="Patch" active={sort.key === "patch"} direction={sort.direction} onClick={() => toggleSort("patch")} />
              <SortableHeader label="Exploit" active={sort.key === "exploit"} direction={sort.direction} onClick={() => toggleSort("exploit")} />
              <SortableHeader label="Description" active={sort.key === "description"} direction={sort.direction} onClick={() => toggleSort("description")} />
              <th>References</th>
            </tr></thead>
            <tbody>
              {sortedRows.map((cve) => (
                <tr key={cve.id}>
                  <td><strong>{cve.cve_id}</strong><small>{cve.finding_id || cve.technology_id || ""}</small></td>
                  <td>{cve.cvss_v3_score.toFixed(1)}</td>
                  <td>{cve.source}</td>
                  <td>{cve.patch_available ? "yes" : "no"}</td>
                  <td>{cve.exploit_available ? "yes" : "no"}</td>
                  <td>{cve.description}</td>
                  <td>{(cve.references ?? []).slice(0, 3).map((ref) => <a key={ref} href={ref}>{ref}</a>)}</td>
                </tr>
              ))}
              {cves.length === 0 ? <tr><td colSpan={7}>No CVEs correlated for the selected session.</td></tr> : null}
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
