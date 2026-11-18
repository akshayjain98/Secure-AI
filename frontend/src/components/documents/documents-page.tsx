"use client";

import { PageHeader } from "@/components/common/page-header";
import { DocumentsPanel } from "@/components/documents/documents-panel";

export function DocumentsPage() {
  return (
    <>
      <PageHeader
        title="Documents"
        description="Documents shared with you, your project's documents, and your own private files."
      />
      <DocumentsPanel />
    </>
  );
}
