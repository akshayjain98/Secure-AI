"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { CopyIcon, FileTextIcon, MoreHorizontalIcon, PencilIcon, PlusIcon, Trash2Icon } from "lucide-react";
import Link from "next/link";
import { useState } from "react";
import { toast } from "sonner";

import { VisibilityBadge } from "@/components/common/badges";
import { ConfirmDialog } from "@/components/common/confirm-dialog";
import { SimpleSelect } from "@/components/common/simple-select";
import { EmptyState, ErrorState, ListSkeleton, LoadMore } from "@/components/common/states";
import { EditDocumentDialog, RegisterDocumentDialog } from "@/components/documents/document-dialogs";
import { useProjectNames } from "@/components/projects/use-project-names";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { errorMessage } from "@/lib/api/client";
import { CONTENT_TYPES, type Document, type DocVisibility } from "@/lib/api/types";
import { fmtBytes, fmtDate } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { keys, prefixes, usePaged } from "@/lib/queries";

const ANY = "any";

export function DocumentsPanel({ projectId, showAdd = true }: { projectId?: string; showAdd?: boolean }) {
  const { api, orgId, can, me, userName } = useOrg();
  const qc = useQueryClient();
  const { names } = useProjectNames();
  const [visibility, setVisibility] = useState<DocVisibility | typeof ANY>(ANY);
  const [mine, setMine] = useState(false);
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Document | null>(null);
  const [deleting, setDeleting] = useState<Document | null>(null);

  const filters = { project_id: projectId, visibility: visibility === ANY ? undefined : visibility, mine: mine || undefined };
  const q = usePaged(keys.documents(orgId, filters), (p) => api.documents({ ...p, ...filters }));

  const remove = useMutation({
    mutationFn: (d: Document) => api.deleteDocument(d.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: prefixes.documents(orgId) });
      toast.success("Document deleted");
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  return (
    <>
      <div className="mb-4 flex flex-wrap items-center gap-3">
        <SimpleSelect<DocVisibility | typeof ANY>
          aria-label="Filter by visibility"
          className="w-44"
          value={visibility}
          onChange={setVisibility}
          options={[
            { value: ANY, label: "Any visibility" },
            { value: "private", label: "Private" },
            { value: "project", label: "Project" },
            { value: "organization", label: "Organization" },
          ]}
        />
        <div className="flex items-center gap-2">
          <Switch id="docs-mine" checked={mine} onCheckedChange={setMine} />
          <Label htmlFor="docs-mine">Only mine</Label>
        </div>
        <span className="flex-1" />
        {showAdd && can("document.upload") && (
          <Button onClick={() => setAdding(true)}>
            <PlusIcon /> Add document
          </Button>
        )}
      </div>

      {q.isPending ? (
        <ListSkeleton />
      ) : q.error ? (
        <ErrorState error={q.error} onRetry={() => q.refetch()} what="documents" />
      ) : q.items.length === 0 ? (
        <EmptyState
          icon={<FileTextIcon />}
          title="No documents"
          description={mine || visibility !== ANY ? "Try clearing the filters." : "Documents you're allowed to see will appear here."}
        />
      ) : (
        <div className="overflow-hidden rounded-lg border">
          <Table>
            <TableHeader>
              <TableRow className="bg-muted/50 hover:bg-muted/50">
                <TableHead className="w-[40%]">Title</TableHead>
                <TableHead className="hidden md:table-cell">Type</TableHead>
                <TableHead>Visibility</TableHead>
                {!projectId && <TableHead className="hidden lg:table-cell">Project</TableHead>}
                <TableHead className="hidden lg:table-cell">Owner</TableHead>
                <TableHead className="hidden sm:table-cell">Added</TableHead>
                <TableHead className="w-10" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {q.items.map((d) => {
                const mineDoc = d.owner_id === me.id;
                return (
                  <TableRow key={d.id}>
                    <TableCell className="max-w-0">
                      <div className="flex items-center gap-2">
                        <FileTextIcon className="size-4 shrink-0 text-muted-foreground" />
                        <span className="truncate font-medium">{d.title}</span>
                      </div>
                    </TableCell>
                    <TableCell className="hidden text-muted-foreground md:table-cell">
                      {CONTENT_TYPES[d.content_type]} · {fmtBytes(d.size_bytes)}
                    </TableCell>
                    <TableCell>
                      <VisibilityBadge visibility={d.visibility} />
                    </TableCell>
                    {!projectId && (
                      <TableCell className="hidden max-w-40 truncate text-muted-foreground lg:table-cell">
                        {d.project_id ? (
                          <Link className="hover:text-foreground hover:underline" href={`/orgs/${orgId}/projects/${d.project_id}`}>
                            {names.get(d.project_id) ?? "Project"}
                          </Link>
                        ) : (
                          "—"
                        )}
                      </TableCell>
                    )}
                    <TableCell className="hidden max-w-40 truncate text-muted-foreground lg:table-cell">{userName(d.owner_id)}</TableCell>
                    <TableCell className="hidden text-muted-foreground sm:table-cell">{fmtDate(d.created_at)}</TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger render={<Button variant="ghost" size="icon-sm" aria-label={`Actions for ${d.title}`} />}>
                          <MoreHorizontalIcon />
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end" className="w-48">
                          <DropdownMenuItem
                            onClick={() => navigator.clipboard.writeText(d.sha256).then(() => toast.success("SHA-256 copied"))}
                          >
                            <CopyIcon /> Copy SHA-256
                          </DropdownMenuItem>
                          {mineDoc && can("document.update") && (
                            <DropdownMenuItem onClick={() => setEditing(d)}>
                              <PencilIcon /> Edit details
                            </DropdownMenuItem>
                          )}
                          {mineDoc && can("document.delete") && (
                            <>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem variant="destructive" onClick={() => setDeleting(d)}>
                                <Trash2Icon /> Delete
                              </DropdownMenuItem>
                            </>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
      <LoadMore {...q} />

      <RegisterDocumentDialog open={adding} onOpenChange={setAdding} projectId={projectId} />
      <EditDocumentDialog doc={editing} onOpenChange={(o) => !o && setEditing(null)} />
      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete document?"
        description={`"${deleting?.title}" will be permanently removed.`}
        confirmLabel="Delete"
        destructive
        onConfirm={() => deleting && remove.mutateAsync(deleting)}
      />
    </>
  );
}
