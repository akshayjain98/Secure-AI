"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRouter } from "next/navigation";
import { useEffect } from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Field, FieldError, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import type { Project } from "@/lib/api/types";
import { applyServerError } from "@/lib/forms";
import { useOrg } from "@/lib/org-context";
import { keys, prefixes } from "@/lib/queries";

const schema = z.object({
  name: z.string().trim().min(1, "Name the project").max(200),
  description: z.string().max(5000),
});
type Values = z.infer<typeof schema>;

export function ProjectFormDialog({
  open,
  onOpenChange,
  project,
}: {
  open: boolean;
  onOpenChange: (o: boolean) => void;
  project?: Project;
}) {
  const { api, orgId } = useOrg();
  const qc = useQueryClient();
  const router = useRouter();
  const form = useForm<Values>({ resolver: zodResolver(schema), defaultValues: { name: "", description: "" } });
  const { errors, isSubmitting } = form.formState;

  useEffect(() => {
    if (open) form.reset({ name: project?.name ?? "", description: project?.description ?? "" });
  }, [open, project, form]);

  const save = useMutation({
    mutationFn: (v: Values) => {
      const body = { name: v.name.trim(), description: v.description.trim() || null };
      return project ? api.updateProject(project.id, body) : api.createProject(body);
    },
    onSuccess: (saved) => {
      qc.setQueryData(keys.project(orgId, saved.id), saved);
      qc.invalidateQueries({ queryKey: prefixes.projects(orgId) });
      onOpenChange(false);
      if (project) toast.success("Project updated");
      else {
        toast.success("Project created");
        router.push(`/orgs/${orgId}/projects/${saved.id}`);
      }
    },
    onError: (err) => applyServerError(err, form.setError, ["name", "description"]),
  });

  return (
    <Dialog open={open} onOpenChange={(o) => !isSubmitting && onOpenChange(o)}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{project ? "Edit project" : "New project"}</DialogTitle>
          {!project && <DialogDescription>You&apos;ll be the owner. Add members once it&apos;s created.</DialogDescription>}
        </DialogHeader>
        <form id="project-form" onSubmit={form.handleSubmit((v) => save.mutateAsync(v).catch(() => {}))} noValidate>
          <FieldGroup className="gap-4">
            {errors.root && (
              <Alert variant="destructive">
                <AlertDescription>{errors.root.message}</AlertDescription>
              </Alert>
            )}
            <Field data-invalid={!!errors.name}>
              <FieldLabel htmlFor="project-name">Name</FieldLabel>
              <Input id="project-name" autoFocus aria-invalid={!!errors.name} {...form.register("name")} />
              <FieldError errors={[errors.name]} />
            </Field>
            <Field data-invalid={!!errors.description}>
              <FieldLabel htmlFor="project-desc">Description</FieldLabel>
              <Textarea id="project-desc" rows={4} placeholder="What is this project about?" {...form.register("description")} />
              <FieldError errors={[errors.description]} />
            </Field>
          </FieldGroup>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)} disabled={isSubmitting}>
            Cancel
          </Button>
          <Button type="submit" form="project-form" disabled={isSubmitting}>
            {isSubmitting && <Spinner />} {project ? "Save" : "Create project"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
