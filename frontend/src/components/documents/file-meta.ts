import { CONTENT_TYPES, MAX_DOC_SIZE, type ContentType } from "@/lib/api/types";

const BY_EXTENSION: Record<string, ContentType> = {
  pdf: "application/pdf",
  txt: "text/plain",
  md: "text/markdown",
  markdown: "text/markdown",
  docx: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
};

export const ACCEPT = ".pdf,.txt,.md,.markdown,.docx," + Object.keys(CONTENT_TYPES).join(",");

export function detectContentType(file: File): ContentType | null {
  if (file.type in CONTENT_TYPES) return file.type as ContentType;
  const ext = file.name.split(".").pop()?.toLowerCase() ?? "";
  return BY_EXTENSION[ext] ?? null;
}

export async function sha256Hex(file: File): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", await file.arrayBuffer());
  return Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function validateFile(file: File): string | null {
  if (file.size > MAX_DOC_SIZE) return "Files must be 50 MB or smaller";
  if (!detectContentType(file)) return "Only PDF, plain text, Markdown and Word (.docx) files are supported";
  return null;
}
