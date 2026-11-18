import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { initials } from "@/lib/format";
import { cn } from "@/lib/utils";

const PALETTE = [
  "bg-sky-500/15 text-sky-700 dark:text-sky-300",
  "bg-violet-500/15 text-violet-700 dark:text-violet-300",
  "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
  "bg-amber-500/15 text-amber-700 dark:text-amber-300",
  "bg-rose-500/15 text-rose-700 dark:text-rose-300",
  "bg-teal-500/15 text-teal-700 dark:text-teal-300",
];

function hash(s: string) {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return Math.abs(h);
}

export function UserAvatar({
  name,
  seed,
  className,
  size = "default",
}: {
  name: string | null | undefined;
  seed?: string;
  className?: string;
  size?: "sm" | "default" | "lg";
}) {
  const color = PALETTE[hash(seed ?? name ?? "") % PALETTE.length];
  return (
    <Avatar size={size} className={className}>
      <AvatarFallback className={cn("font-medium", color)}>{initials(name)}</AvatarFallback>
    </Avatar>
  );
}
