import { ShieldCheckIcon } from "lucide-react";

import { cn } from "@/lib/utils";

export function Logo({ className, compact }: { className?: string; compact?: boolean }) {
  return (
    <span className={cn("inline-flex items-center gap-2 font-heading font-semibold tracking-tight", className)}>
      <span className="flex size-7 items-center justify-center rounded-lg bg-primary text-primary-foreground">
        <ShieldCheckIcon className="size-4" />
      </span>
      {!compact && <span>SecureAI</span>}
    </span>
  );
}
