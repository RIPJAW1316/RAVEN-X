import { useCallback, useState, type FormEvent } from "react";
import { Check, KeyRound, Laptop, Plus, ShieldCheck, ShieldOff } from "lucide-react";
import { enrollment, fleet } from "../api/endpoints";
import { AsyncSection, Badge, Confirm, Empty, ErrorState, Field, Modal, PageHeading, Panel } from "../components/ui";
import { useApi, useMutation, usePolling } from "../hooks/useApi";
import { formatDateTime, shortId } from "../lib/format";
import type { EnrollmentToken, IssuedEnrollmentToken } from "../types/api";

export function Enrollment({ organizationId, navigate }: {
  organizationId: string;
  navigate: (section: string, ...params: string[]) => void;
}) {
  const tokens = useApi((signal) => enrollment.list(organizationId, signal), [organizationId]);
  usePolling(tokens.reload, 10000, true);
  const pending = useApi((signal) => fleet.query(organizationId, { status: ["new"], limit: 100 }, signal), [organizationId]);
  usePolling(pending.reload, 10000, !pending.error);
  const [issueOpen, setIssueOpen] = useState(false);
  const [label, setLabel] = useState("");
  const [ttl, setTtl] = useState(60);
  const [issued, setIssued] = useState<IssuedEnrollmentToken | null>(null);
  const [revoking, setRevoking] = useState<EnrollmentToken | null>(null);
  const issue = useMutation((name: string, minutes: number) => enrollment.issue(organizationId, name, minutes));
  const revoke = useMutation((id: string) => enrollment.revokeToken(organizationId, id));

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const result = await issue.run(label.trim(), ttl);
    if (result) {
      setIssued(result);
      setIssueOpen(false);
      setLabel("");
      tokens.reload();
    }
  };
  const revokeSelected = async () => {
    if (!revoking) return;
    if (await revoke.run(revoking.enrollment_id)) {
      setRevoking(null);
      tokens.reload();
    }
  };

  return <>
    <PageHeading eyebrow="Endpoint trust" title="Enrollment & approval"
      description="Bring a Windows machine into your fleet, then verify its identity before granting assessment access."
      actions={<button type="button" className="primary" onClick={() => { issue.reset(); setIssueOpen(true); }}><Plus size={16} /> Issue token</button>} />
    <div className="onboarding-steps" aria-label="Enrollment steps">
      <div><KeyRound size={21} /><span><strong>01 · Issue</strong><small>One machine. One short-lived token.</small></span></div>
      <div><Laptop size={21} /><span><strong>02 · Connect</strong><small>Agent verifies your server certificate.</small></span></div>
      <div><ShieldCheck size={21} /><span><strong>03 · Approve</strong><small>Confirm the machine, then permit scans.</small></span></div>
    </div>

    <Panel title="Awaiting your approval" icon={<ShieldCheck size={15} />}>
      <AsyncSection loading={pending.loading} error={pending.error} data={pending.data} onRetry={pending.reload}>
        {(data) => data.items.length === 0 ? <Empty title="No machines awaiting approval"
          detail="An agent appears here after redeeming its token. Registration permits heartbeat only; approval permits assessment work." /> :
          <div className="table-scroll"><table className="data-table"><thead><tr><th>Machine</th><th>Platform</th><th>Connection</th><th>Trust decision</th></tr></thead>
            <tbody>{data.items.map((endpoint) => <tr key={endpoint.endpoint_id}>
              <td><button type="button" className="link" onClick={() => navigate("fleet", endpoint.endpoint_id)}>{endpoint.hostname}</button><small className="block mono">{shortId(endpoint.endpoint_id)}</small></td>
              <td>{endpoint.platform} {endpoint.platform_version}</td><td><Badge tone={endpoint.presence_state === "online" ? "ok" : "neutral"}>{endpoint.presence_state}</Badge></td>
              <td><EndpointTrustControls organizationId={organizationId} endpointId={endpoint.endpoint_id} hostname={endpoint.hostname} status="new" onChanged={pending.reload} /></td>
            </tr>)}</tbody></table></div>}
      </AsyncSection>
    </Panel>

    <Panel title="Single-use enrollment tokens" icon={<KeyRound size={15} />}>
      {revoke.error && <ErrorState error={revoke.error} />}
      <AsyncSection loading={tokens.loading} error={tokens.error} data={tokens.data} onRetry={tokens.reload}
        empty={<Empty title="No enrollment tokens" detail="Issue a token for the Dell or HP notebook. The secret is displayed once and expires automatically." />}>
        {(items) => <div className="table-scroll"><table className="data-table"><thead><tr><th>Label / ID</th><th>Status</th><th>Expires</th><th>Action</th></tr></thead>
          <tbody>{items.map((token) => <tr key={token.enrollment_id}>
            <td>{token.label || "Windows endpoint"}<small className="block mono">{shortId(token.enrollment_id)}</small></td>
            <td><Badge tone={token.status === "pending" ? "warn" : "neutral"}>{token.status}</Badge></td>
            <td>{formatDateTime(token.expires_at)}</td>
            <td>{token.status === "pending" && <button type="button" className="ghost small" onClick={() => { revoke.reset(); setRevoking(token); }}>Revoke token</button>}</td>
          </tr>)}</tbody></table></div>}
      </AsyncSection>
      <p className="panel-note">Tokens grant registration in this organization. They do not approve an endpoint. Revoking a token does not revoke a machine that already redeemed it.</p>
    </Panel>

    <Modal open={issueOpen} title="Issue an enrollment token" onClose={() => { if (!issue.busy) setIssueOpen(false); }}>
      <form onSubmit={submit} className="form-stack">
        <Field label="Machine label" hint="A label for your records; the machine still reports its own identity."><input value={label} onChange={(event) => setLabel(event.target.value)} maxLength={80} placeholder="Dell Vostro · pilot" /></Field>
        <Field label="Expires in minutes" hint="Single use. Between 1 minute and 24 hours."><input type="number" value={ttl} min={1} max={1440} required onChange={(event) => setTtl(Number(event.target.value))} /></Field>
        {issue.error && <ErrorState error={issue.error} />}
        <div className="modal-actions"><button type="button" className="ghost" disabled={issue.busy} onClick={() => setIssueOpen(false)}>Cancel</button><button type="submit" className="primary" disabled={issue.busy}>{issue.busy ? "Issuing…" : "Issue single-use token"}</button></div>
      </form>
    </Modal>
    <Modal open={issued !== null} title="Save this token now" onClose={() => setIssued(null)}>
      {issued && <div className="form-stack">
        <div className="secret-notice"><KeyRound size={18} /><p>This secret is displayed once. Paste it at the agent’s hidden enrollment prompt. Closing this dialog removes it from this screen.</p></div>
        <Field label="Enrollment ID"><input className="mono" readOnly value={issued.enrollment_id} /></Field>
        <Field label="One-time token"><textarea className="mono secret-value" readOnly rows={3} value={issued.enrollment_token} autoComplete="off" spellCheck={false} /></Field>
        <p className="panel-note">Expires {formatDateTime(issued.expires_at)}. Use the verified CA certificate and the server’s HTTPS address from the deployment runbook. Verify the hostname on the physical machine before approving it.</p>
        <button type="button" className="primary" onClick={() => setIssued(null)}><Check size={15} /> I have saved the token</button>
      </div>}
    </Modal>
    <Confirm open={revoking !== null} title="Revoke this token?" message="This prevents further registration with the unused token. Already enrolled machines are unaffected." confirmLabel="Revoke token" destructive busy={revoke.busy} onConfirm={revokeSelected} onCancel={() => { if (!revoke.busy) setRevoking(null); }} />
  </>;
}

export function EndpointTrustControls({ organizationId, endpointId, hostname, status, onChanged }: {
  organizationId: string; endpointId: string; hostname: string; status: string; onChanged: () => void;
}) {
  const [action, setAction] = useState<"approve" | "revoke" | null>(null);
  const mutation = useMutation((decision: "approve" | "revoke") => decision === "approve"
    ? enrollment.approve(organizationId, endpointId) : enrollment.revokeEndpoint(organizationId, endpointId));
  const confirm = useCallback(async () => {
    if (action && await mutation.run(action)) { setAction(null); onChanged(); }
  }, [action, mutation, onChanged]);
  if (status === "revoked") return <Badge tone="critical">Revoked</Badge>;
  return <>
    <span className="row-actions">
      {status === "new" && <button type="button" className="primary small" onClick={() => { mutation.reset(); setAction("approve"); }}><ShieldCheck size={14} /> Approve</button>}
      <button type="button" className="ghost small" onClick={() => { mutation.reset(); setAction("revoke"); }}><ShieldOff size={14} /> Revoke</button>
    </span>
    {mutation.error && <ErrorState error={mutation.error} />}
    <Confirm open={action !== null} title={action === "approve" ? `Approve ${hostname}?` : `Revoke ${hostname}?`}
      message={action === "approve" ? `Confirm ${hostname} and endpoint ID ${endpointId} on the physical machine. Approval allows the agent to receive read-only assessment work; an online heartbeat alone does not prove identity.` : `Endpoint ID ${endpointId}. The agent will lose access immediately on its next request, and new assessments will be blocked. This does not remove historical evidence.`}
      confirmLabel={action === "approve" ? "Approve machine" : "Revoke access"} destructive={action === "revoke"} busy={mutation.busy} onConfirm={confirm} onCancel={() => { if (!mutation.busy) setAction(null); }} />
  </>;
}
