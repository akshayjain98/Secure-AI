import Link from "next/link";

import { Logo } from "@/components/common/logo";
import { ThemeToggle } from "@/components/app-shell/theme-toggle";

export default function AuthLayout({ children }: LayoutProps<"/">) {
  return (
    <div className="relative flex min-h-svh flex-col bg-muted/40">
      <header className="flex items-center justify-between p-4 sm:p-6">
        <Link href="/" aria-label="SecureAI home">
          <Logo />
        </Link>
        <ThemeToggle />
      </header>
      <main className="flex flex-1 items-start justify-center px-4 pt-6 pb-16 sm:items-center sm:pt-0">
        <div className="w-full max-w-sm">{children}</div>
      </main>
      <footer className="pb-6 text-center text-xs text-muted-foreground">
        Protected by row-level security, Argon2id and rotating sessions.
      </footer>
    </div>
  );
}
