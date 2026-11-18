"use client";

import {
  BuildingIcon,
  CheckIcon,
  ChevronsUpDownIcon,
  InboxIcon,
  LogOutIcon,
  MenuIcon,
  UserCogIcon,
} from "lucide-react";
import Link from "next/link";
import { useParams, usePathname, useRouter } from "next/navigation";
import { useState } from "react";
import { toast } from "sonner";

import { ORG_NAV } from "@/components/app-shell/nav";
import { ThemeToggle } from "@/components/app-shell/theme-toggle";
import { Logo } from "@/components/common/logo";
import { UserAvatar } from "@/components/common/user-avatar";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuGroup,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { useAuth } from "@/lib/auth/session";
import { isUuid, roleName } from "@/lib/format";
import { useInvitations, useMe, useMeInOrg } from "@/lib/queries";
import { cn } from "@/lib/utils";

function OrgSwitcher({ orgId }: { orgId?: string }) {
  const { data: me } = useMe();
  const router = useRouter();
  const current = me?.organizations.find((o) => o.id === orgId);
  return (
    <DropdownMenu>
      <DropdownMenuTrigger
        render={
          <Button variant="outline" className="h-auto w-full justify-between gap-2 px-2.5 py-2 text-left" />
        }
      >
        <span className="flex min-w-0 items-center gap-2">
          <span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-muted">
            <BuildingIcon className="size-4" />
          </span>
          <span className="min-w-0">
            <span className="block truncate text-sm font-medium">{current?.name ?? "Select organization"}</span>
            {current && <span className="block truncate text-xs text-muted-foreground">{current.slug}</span>}
          </span>
        </span>
        <ChevronsUpDownIcon className="text-muted-foreground" />
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" className="w-64">
        <DropdownMenuGroup>
          <DropdownMenuLabel>Organizations</DropdownMenuLabel>
          {me?.organizations.length === 0 && (
            <DropdownMenuItem disabled>You&apos;re not a member of any organization yet</DropdownMenuItem>
          )}
          {me?.organizations.map((o) => (
            <DropdownMenuItem key={o.id} onClick={() => router.push(`/orgs/${o.id}`)}>
              <BuildingIcon />
              <span className="flex-1 truncate">{o.name}</span>
              {o.id === orgId && <CheckIcon />}
            </DropdownMenuItem>
          ))}
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => router.push("/invitations")}>
          <InboxIcon /> Pending invitations
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function OrgNav({ orgId, onNavigate }: { orgId: string; onNavigate?: () => void }) {
  const pathname = usePathname();
  const { data, isPending } = useMeInOrg(orgId);
  const perms = new Set(data?.current_org?.permissions ?? []);

  if (isPending)
    return (
      <div className="space-y-1.5 px-1">
        {Array.from({ length: 6 }, (_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    );

  return (
    <nav className="space-y-0.5" aria-label="Organization">
      {ORG_NAV.filter((n) => !n.requires || perms.has(n.requires)).map((item) => {
        const href = item.href(orgId);
        const active = item.exact ? pathname === href : pathname === href || pathname.startsWith(href + "/");
        return (
          <Link
            key={item.label}
            href={href}
            onClick={onNavigate}
            aria-current={active ? "page" : undefined}
            className={cn(
              "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
              active && "bg-muted font-medium text-foreground",
            )}
          >
            <item.icon className="size-4" />
            {item.label}
          </Link>
        );
      })}
    </nav>
  );
}

function SidebarContent({ orgId, onNavigate }: { orgId?: string; onNavigate?: () => void }) {
  const { data: invitations } = useInvitations();
  const { data: inOrg } = useMeInOrg(orgId ?? "");
  const pending = invitations?.length ?? 0;
  return (
    <div className="flex h-full flex-col gap-4 p-3">
      <Link href="/" className="px-1 pt-1" onClick={onNavigate}>
        <Logo />
      </Link>
      <OrgSwitcher orgId={orgId} />
      {orgId && inOrg?.current_org && (
        <p className="-mt-2 px-1 text-xs text-muted-foreground">
          Signed in as <span className="font-medium text-foreground">{roleName(inOrg.current_org.role)}</span>
        </p>
      )}
      <div className="flex-1 overflow-y-auto">{orgId && <OrgNav orgId={orgId} onNavigate={onNavigate} />}</div>
      <Link
        href="/invitations"
        onClick={onNavigate}
        className="flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm text-muted-foreground hover:bg-muted hover:text-foreground"
      >
        <InboxIcon className="size-4" />
        <span className="flex-1">Invitations</span>
        {pending > 0 && <Badge>{pending}</Badge>}
      </Link>
    </div>
  );
}

function UserMenu() {
  const { data: me } = useMe();
  const { logout } = useAuth();
  const router = useRouter();
  return (
    <DropdownMenu>
      <DropdownMenuTrigger render={<Button variant="ghost" className="h-9 gap-2 px-1.5" aria-label="Account menu" />}>
        <UserAvatar name={me?.display_name} seed={me?.id} size="sm" />
        <span className="hidden max-w-40 truncate text-sm sm:inline">{me?.display_name}</span>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-60">
        <DropdownMenuGroup>
          <DropdownMenuLabel className="font-normal">
            <span className="block truncate text-sm font-medium text-foreground">{me?.display_name}</span>
            <span className="block truncate text-xs text-muted-foreground">{me?.email}</span>
          </DropdownMenuLabel>
        </DropdownMenuGroup>
        <DropdownMenuSeparator />
        <DropdownMenuItem onClick={() => router.push("/account")}>
          <UserCogIcon /> Account &amp; security
        </DropdownMenuItem>
        <DropdownMenuItem onClick={() => router.push("/invitations")}>
          <InboxIcon /> Invitations
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          variant="destructive"
          onClick={async () => {
            try {
              await logout();
            } catch {
              toast.error("Signed out locally, but the server couldn't be reached.");
            }
            router.replace("/login");
          }}
        >
          <LogOutIcon /> Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

export function AppFrame({ children }: { children: React.ReactNode }) {
  const params = useParams<{ orgId?: string }>();
  // A malformed id in the URL is never sent to the API (OrgGate shows "No access").
  const orgId = isUuid(params?.orgId) ? params.orgId : undefined;
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex min-h-svh">
      <aside className="sticky top-0 hidden h-svh w-64 shrink-0 border-r bg-sidebar lg:block">
        <SidebarContent orgId={orgId} />
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-14 items-center gap-2 border-b bg-background/80 px-4 backdrop-blur supports-backdrop-filter:bg-background/60">
          <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
            <SheetTrigger render={<Button variant="ghost" size="icon" className="lg:hidden" aria-label="Open navigation" />}>
              <MenuIcon />
            </SheetTrigger>
            <SheetContent side="left" className="w-72 p-0">
              <SheetTitle className="sr-only">Navigation</SheetTitle>
              <SidebarContent orgId={orgId} onNavigate={() => setMobileOpen(false)} />
            </SheetContent>
          </Sheet>
          <div className="flex-1" />
          <ThemeToggle />
          <UserMenu />
        </header>
        <main className="mx-auto w-full max-w-6xl flex-1 px-4 py-6 sm:px-6 lg:px-8">{children}</main>
      </div>
    </div>
  );
}
