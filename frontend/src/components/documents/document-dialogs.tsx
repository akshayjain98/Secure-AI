"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FileUpIcon, InfoIcon } from "lucide-react";
import { useRef, useState } from "react";
import { toast } from "sonner";

import { ACCEPT, detectContentType, sha256Hex, validateFile } from "@/components/documents/file-meta";
import { useProjectNames } from "@/components/projects/use-project-names";
import { SimpleSelect } from "@/components/common/simple-select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { errorMessage } from "@/lib/api/client";
import { CONTENT_TYPES, type ContentType, type Document, type DocVisibility } from "@/lib/api/types";
import { fmtBytes } from "@/lib/format";
import { useOrg } from "@/lib/org-context";
import { prefixes } from "@/lib/queries";

const NO_PROJECT = "__none__";

const VIS_OPTIONS: { value: DocVisibility; label: string }[] = [
  { value: "private", label: "Private — only you" },
  { value: "project", label: "Project — members of the project" },
  { value: "organization", label: "Organization — everyone with document access" },
];

function useDocFields(initial?: { title: string; visibility: DocVisibility; project_id: string | null }, fixedProject?: string) {
  const [title, setTitle] = useState(initial?.title ?? "");
  const [visibility, setVisibility] = useState<DocVisibility>(initial?.visibility ?? "private");
  const [projectId, setProjectId] = useState<string>(initial?.project_id ?? fixedProject ?? NO_PROJECT);
  const error =
    !title.trim()
      ? "Enter a title"
      : visibility === "project" && projectId === NO_PROJECT
        ? "Project visibility needs a project"
        : null;
  return { title, setTitle, visibility, setVisibility, projectId, setProjectId, error };
}

function SharedFields({ f, fixedProject }: { f: ReturnType<typeof useDocFields>; fixedProject?: string }) {
  const { projects } = useProjectNames();
  return (
    <>
      <Field>
        <FieldLabel htmlFor="doc-title">Title</FieldLabel>
        <Input id="doc-title" value={f.title} maxLength={300} onChange={(e) => f.setTitle(e.target.value)} />
      </Field>
      {!fixedProject && (
        <Field>
          <FieldLabel htmlFor="doc-project">Project</FieldLabel>
          <SimpleSelect
            id="doc-project"
            value={f.projectId}
            onChange={f.setProjectId}
            options={[
              { value: NO_PROJECT, label: "No project" },
              ...projects.filter((p) => p.status === "active" || p.id === f.projectId).map((p) => ({ value: p.id, label: p.name })),
            ]}
          />
        </Field>
      )}
      <Field>
        <FieldLabel htmlFor="doc-vis">Visibility</FieldLabel>
        <SimpleSelect<DocVisibility> id="doc-vis" value={f.visibility} onChange={f.setVisibility} options={VIS_OPTIONS} />
        <FieldDescription>Even organization admins can&apos;t read a private document.</FieldDescription>
      </Field>
    </>
  );
}

export function RegisterDocumentDialog({
  open,
  onOpenChange,
  projectId,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  projectId?: string;
}) {
  const [busy, setBusy] = useState(false);
  // The body mounts fresh on every open, so no state leaks between uses.
  return (
    <Dialog open={open} onOpenChange={(o) => !busy && onOpenChange(o)}>
      <DialogContent className="sm:max-w-lg">
        {open && <RegisterBody projectId={projectId} close={() => onOpenChange(false)} onBusy={setBusy} />}
      </DialogContent>
    </Dialog>
  );
}

function RegisterBody({ projectId, close, onBusy }: { projectId?: string; close: () => void; onBusy: (b: boolean) => void }) {
  const { api, orgId } = useOrg();
  const qc = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<{ file: File; type: ContentType; sha256: string } | null>(null);
  const [hashing, setHashing] = useState(false);
  const [fileError, setFileError] = useState<string | null>(null);
  const f = useDocFields({ title: "", visibility: projectId ? "project" : "private", project_id: projectId ?? null }, projectId);

  async function pick(picked: File | undefined) {
    if (!picked) return;
    setFileError(null);
    const err = validateFile(picked);
    if (err) return setFileError(err);
    setHashing(true);
    try {
      const sha256 = await sha256Hex(picked);
      setFile({ file: picked, type: detectContentType(picked)!, sha256 });
      if (!f.title) f.setTitle(picked.name.replace(/\.[^.]+$/, "").slice(0, 300));
    } catch {
      setFileError("Couldn't read that file");
    } finally {
      setHashing(false);
    }
  }

  const create = useMutation({
    mutationFn: () =>
      api.createDocument({
        title: f.title.trim(),
        content_type: file!.type,
        size_bytes: file!.file.size,
        sha256: file!.sha256,
        visibility: f.visibility,
        project_id: f.projectId === NO_PROJECT ? null : f.projectId,
      }),
    onMutate: () => onBusy(true),
    onSettled: () => onBusy(false),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: prefixes.documents(orgId) });
      toast.success("Document registered");
      close();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });

  return (
    <>
        <DialogHeader>
          <DialogTitle>Add document</DialogTitle>
          <DialogDescription>PDF, text, Markdown or Word, up to 50 MB.</DialogDescription>
        </DialogHeader>
        <FieldGroup className="gap-4">
          <Alert>
            <InfoIcon />
            <AlertDescription>
              File storage arrives in a later phase. For now only metadata is saved; the SHA-256 fingerprint is computed
              locally and the file itself never leaves your browser.
            </AlertDescription>
          </Alert>
          <button
            type="button"
            onClick={() => inputRef.current?.click()}
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault();
              void pick(e.dataTransfer.files[0]);
            }}
            className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-6 text-center text-sm transition-colors hover:bg-muted/50 focus-visible:ring-3 focus-visible:ring-ring/50 focus-visible:outline-none"
          >
            {hashing ? <Spinner className="size-6" /> : <FileUpIcon className="size-6 text-muted-foreground" />}
            {file ? (
              <>
                <span className="font-medium break-all">{file.file.name}</span>
                <span className="text-xs text-muted-foreground">
                  {CONTENT_TYPES[file.type]} · {fmtBytes(file.file.size)}
                </span>
                <span className="max-w-full truncate font-mono text-[10px] text-muted-foreground">sha256 {file.sha256}</span>
              </>
            ) : (
              <span className="text-muted-foreground">
                {hashing ? "Fingerprinting…" : "Drop a file here or click to choose"}
              </span>
            )}
          </button>
          <input ref={inputRef} type="file" accept={ACCEPT} className="hidden" onChange={(e) => pick(e.target.files?.[0])} />
          {fileError && <p className="text-sm text-destructive">{fileError}</p>}
          <SharedFields f={f} fixedProject={projectId} />
        </FieldGroup>
        <DialogFooter>
          <Button variant="outline" onClick={close} disabled={create.isPending}>
            Cancel
          </Button>
          <Button disabled={!file || !!f.error || create.isPending} onClick={() => create.mutate()} title={f.error ?? undefined}>
            {create.isPending && <Spinner />} Save document
          </Button>
        </DialogFooter>
    </>
  );
}

export function EditDocumentDialog({ doc, onOpenChange }: { doc: Document | null; onOpenChange: (o: boolean) => void }) {
  return (
    <Dialog open={!!doc} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">{doc && <EditBody doc={doc} close={() => onOpenChange(false)} />}</DialogContent>
    </Dialog>
  );
}

function EditBody({ doc, close }: { doc: Document; close: () => void }) {
  const { api, orgId } = useOrg();
  const qc = useQueryClient();
  const f = useDocFields({ title: doc.title, visibility: doc.visibility, project_id: doc.project_id });
  const save = useMutation({
    mutationFn: () => {
      const project_id = f.projectId === NO_PROJECT ? null : f.projectId;
      const body: Parameters<typeof api.updateDocument>[1] = {};
      if (f.title.trim() !== doc.title) body.title = f.title.trim();
      if (f.visibility !== doc.visibility) body.visibility = f.visibility;
      if (project_id !== doc.project_id) body.project_id = project_id;
      return Object.keys(body).length ? api.updateDocument(doc.id, body) : Promise.resolve(doc);
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: prefixes.documents(orgId) });
      toast.success("Document updated");
      close();
    },
    onError: (err) => toast.error(errorMessage(err)),
  });
  return (
    <>
      <DialogHeader>
        <DialogTitle>Edit document</DialogTitle>
        <DialogDescription>Only the owner can change a document&apos;s details.</DialogDescription>
      </DialogHeader>
      <FieldGroup className="gap-4">
        <SharedFields f={f} />
      </FieldGroup>
      <DialogFooter>
        <Button variant="outline" onClick={close}>
          Cancel
        </Button>
        <Button disabled={!!f.error || save.isPending} onClick={() => save.mutate()}>
          {save.isPending && <Spinner />} Save
        </Button>
      </DialogFooter>
    </>
  );
}
