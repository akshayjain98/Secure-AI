"use client";

import { BuildingIcon, ChevronRightIcon, InboxIcon } from "lucide-react";
import Link from "next/link";

import { PageHeader } from "@/components/common/page-header";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/common/states";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { useInvitations, useMe } from "@/lib/queries";

export function OrgPicker() {
  const { data: me, error, isPending, refetch } = useMe();
  const { data: invitations } = useInvitations();

  return (
    <>
      <PageHeader title="Your organizations" description="Choose a workspace to continue." />
      {isPending ? (
        <ListSkeleton rows={3} />
      ) : error ? (
        <ErrorState error={error} onRetry={() => refetch()} what="your organizations" />
      ) : me.organizations.length === 0 ? (
        <EmptyState
          icon={<BuildingIcon />}
          title="You're not in an organization yet"
          description="Organizations are invite-only. Ask an administrator to invite your email address, then accept the invitation here."
          action={
            <Button nativeButton={false} render={<Link href="/invitations" />}>
              <InboxIcon /> View invitations
              {invitations && invitations.length > 0 ? ` (${invitations.length})` : ""}
            </Button>
          }
        />
      ) : (
        <div className="grid gap-3 sm:grid-cols-2">
          {me.organizations.map((o) => (
            <Link key={o.id} href={`/orgs/${o.id}`} className="group">
              <Card className="flex-row items-center gap-3 px-4 transition-colors group-hover:bg-muted/50">
                <span className="flex size-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <BuildingIcon className="size-5" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="truncate font-medium">{o.name}</p>
                  <p className="truncate text-xs text-muted-foreground">{o.slug}</p>
                </div>
                <ChevronRightIcon className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
              </Card>
            </Link>
          ))}
        </div>
      )}
    </>
  );
}
