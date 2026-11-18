"use client";

import { CopyIcon, ScrollTextIcon } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

import { OutcomeBadge } from "@/components/common/badges";
import { PageHeader } from "@/components/common/page-header";
import { SimpleSelect } from "@/components/common/simple-select";
import { EmptyState, ErrorState, ListSkeleton, LoadMore } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { AuditLog, AuditOutcome } from "@/lib/api/types";
import { fmtDateTime, fmtRelative, shortId } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys, usePaged } from "@/lib/queries";

const ANY = "any";
const RESOURCE_TYPES = [
  ["organization", "Organization"],
  ["member", "Members"],
  ["permission_override", "Permission overrides"],
  ["project", "Projects"],
  ["project_member", "Project members"],
  ["task", "Tasks"],
  ["document", "Documents"],
] as const;
const VERBS = [
  ["create", "Created"],
  ["update", "Updated"],
  ["delete", "Deleted"],
] as const;

function Detail({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="grid grid-cols-3 gap-2 py-2 text-sm">
      <dt className="text-muted-foreground">{label}</dt>
      <dd className={mono ? "col-span-2 font-mono text-xs break-all" : "col-span-2 break-words"}>{children ?? "—"}</dd>
    </div>
  );
}

function AuditDetail({ log, onOpenChange }: { log: AuditLog | null; onOpenChange: (o: boolean) => void }) {
  const { userName } = useOrg();
  return (
    <Sheet open={!!log} onOpenChange={onOpenChange}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
        {log && (
          <>
            <SheetHeader>
              <SheetTitle className="font-mono text-base">{log.action}</SheetTitle>
              <SheetDescription>{fmtDateTime(log.occurred_at)}</SheetDescription>
            </SheetHeader>
            <dl className="divide-y px-4">
              <Detail label="Outcome">
                <OutcomeBadge outcome={log.outcome} />
              </Detail>
              <Detail label="Actor">{log.actor_user_id ? userName(log.actor_user_id) : "System"}</Detail>
              <Detail label="Resource">{log.resource_type}</Detail>
              <Detail label="Resource ID" mono>
                {log.resource_id}
              </Detail>
              <Detail label="Request ID" mono>
                {log.request_id}
              </Detail>
              <Detail label="IP address" mono>
                {log.ip_address}
              </Detail>
              <Detail label="User agent" mono>
                {log.user_agent}
              </Detail>
            </dl>
            <div className="px-4 pb-6">
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-sm font-medium">Metadata</h3>
                <Button
                  variant="ghost"
                  size="xs"
                  onClick={() => navigator.clipboard.writeText(JSON.stringify(log, null, 2)).then(() => toast.success("Copied"))}
                >
                  <CopyIcon /> Copy event
                </Button>
              </div>
              <pre className="max-h-96 overflow-auto rounded-lg bg-muted p-3 font-mono text-xs">{JSON.stringify(log.metadata, null, 2)}</pre>
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}

export function AuditPage() {
  const { api, orgId, userName } = useOrg();
  const [resource, setResource] = useState<string>(ANY);
  const [verb, setVerb] = useState<string>(ANY);
  const [outcome, setOutcome] = useState<AuditOutcome | typeof ANY>(ANY);
  const [selected, setSelected] = useState<AuditLog | null>(null);

  // The API's action filter is a prefix: "task" matches task.*, "task.update" exactly.
  const action = resource === ANY ? undefined : verb === ANY ? resource : `${resource}.${verb}`;
  const filters = { action, outcome: outcome === ANY ? undefined : outcome };
  const q = usePaged(keys.audit(orgId, filters), (p) => api.auditLogs({ ...p, ...filters }));
  const rows = q.items;

  return (
    <>
      <PageHeader
        title="Audit log"
        description="Every change in this organization, written by the database itself. Append-only; nobody can edit or delete entries."
      />
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <SimpleSelect
          aria-label="Resource"
          className="w-52"
          value={resource}
          onChange={(v) => {
            setResource(v);
            if (v === ANY) setVerb(ANY);
          }}
          options={[{ value: ANY, label: "All resources" }, ...RESOURCE_TYPES.map(([v, l]) => ({ value: v, label: l }))]}
        />
        <SimpleSelect
          aria-label="Action"
          className="w-36"
          value={verb}
          onChange={setVerb}
          disabled={resource === ANY}
          options={[{ value: ANY, label: "Any action" }, ...VERBS.map(([v, l]) => ({ value: v, label: l }))]}
        />
        <SimpleSelect<AuditOutcome | typeof ANY>
          aria-label="Outcome"
          className="w-36"
          value={outcome}
          onChange={setOutcome}
          options={[
            { value: ANY, label: "Any outcome" },
            { value: "success", label: "Success" },
            { value: "denied", label: "Denied" },
            { value: "failure", label: "Failure" },
            { value: "error", label: "Error" },
          ]}
        />
      </div>

      {q.isPending ? (
        <ListSkeleton rows={8} />
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} what="the audit log" />
      ) : rows.length === 0 ? (
        <EmptyState icon={<ScrollTextIcon />} title="No matching events" />
      ) : (
        <div className="overflow-hidden rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/50 hover:bg-muted/50">
                <TableHead>When</TableHead>
                <TableHead>Action</TableHead>
                <TableHead className="hidden md:table-cell">Actor</TableHead>
                <TableHead>Outcome</TableHead>
                <TableHead className="hidden lg:table-cell">Resource</TableHead>
                <TableHead className="hidden xl:table-cell">IP</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.map((l) => (
                <TableRow key={l.id} className="cursor-pointer" onClick={() => setSelected(l)}>
                  <TableCell className="whitespace-nowrap text-muted-foreground" title={fmtDateTime(l.occurred_at)}>
                    {fmtRelative(l.occurred_at)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{l.action}</TableCell>
                  <TableCell className="hidden max-w-48 truncate md:table-cell">
                    {l.actor_user_id ? userName(l.actor_user_id) : "System"}
                  </TableCell>
                  <TableCell>
                    <OutcomeBadge outcome={l.outcome} />
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs text-muted-foreground lg:table-cell">
                    {l.resource_type ? `${l.resource_type}/${l.resource_id ? shortId(l.resource_id) : "—"}` : "—"}
                  </TableCell>
                  <TableCell className="hidden font-mono text-xs text-muted-foreground xl:table-cell">{l.ip_address ?? "—"}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
      <LoadMore {...q} />
      <AuditDetail log={selected} onOpenChange={(o) => !o && setSelected(null)} />
    </>
  );
}
