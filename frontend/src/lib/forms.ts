import type { FieldValues, Path, UseFormSetError } from "react-hook-form";
import { z } from "zod";

import { ApiError, errorMessage } from "@/lib/api/client";

/** Mirrors app/auth/passwords.py. The server re-validates (and may also reject breached passwords). */
export const PASSWORD_MIN = 12;
export const PASSWORD_MAX = 1024;
export const passwordSchema = z
  .string()
  .min(PASSWORD_MIN, `Use at least ${PASSWORD_MIN} characters`)
  .max(PASSWORD_MAX, "Password is too long");

export const emailSchema = z.string().trim().min(3, "Enter your email").max(320).email("Enter a valid email address");

/**
 * Routes server-side validation (422 with field locations) onto form fields,
 * and anything else onto the form's root error.
 */
export function applyServerError<T extends FieldValues>(err: unknown, setError: UseFormSetError<T>, fields: string[] = []) {
  if (err instanceof ApiError) {
    let mapped = false;
    for (const [field, msg] of Object.entries(err.fieldErrors)) {
      if (fields.includes(field)) {
        setError(field as Path<T>, { type: "server", message: msg });
        mapped = true;
      }
    }
    if (mapped) return;
  }
  setError("root" as Path<T>, { type: "server", message: errorMessage(err) });
}
