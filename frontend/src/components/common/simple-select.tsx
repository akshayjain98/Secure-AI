"use client";

import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { cn } from "@/lib/utils";

export interface Option<V extends string> {
  value: V;
  label: React.ReactNode;
  disabled?: boolean;
}

/** Single-value select. `null` value renders the placeholder. */
export function SimpleSelect<V extends string>({
  value,
  onChange,
  options,
  placeholder = "Select…",
  className,
  disabled,
  id,
  size,
  "aria-label": ariaLabel,
}: {
  value: V | null;
  onChange: (v: V) => void;
  options: Option<V>[];
  placeholder?: string;
  className?: string;
  disabled?: boolean;
  id?: string;
  size?: "sm" | "default";
  "aria-label"?: string;
}) {
  return (
    <Select
      value={value}
      onValueChange={(v) => v !== null && onChange(v as V)}
      items={options.map((o) => ({ value: o.value, label: o.label }))}
      disabled={disabled}
    >
      <SelectTrigger id={id} size={size} className={cn("w-full", className)} aria-label={ariaLabel}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value} disabled={o.disabled}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}
