"use client";

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { BuildingIcon, InboxIcon } from "lucide-react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

import { PageHeader } from "@/components/common/page-header";
import { EmptyState, ErrorState, ListSkeleton } from "@/components/common/states";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Spinner } from "@/components/ui/spinner";
import { errorMessage } from "@/lib/api/client";
import { meApi } from "@/lib/api/endpoints";
import type { Invitation } from "@/lib/api/types";
import { fmtRelative, roleName } from "@/lib/format";
import { keys, useInvitations, useMe } from "@/lib/queries";

function InvitationRow({ inv }: { inv: Invitation }) {
  const qc = useQueryClient();
  const router = useRouter();
  const respond = useMutation({
    mutationFn: (accept: boolean) =>
      accept ? meApi.acceptInvitation(inv.organization_id) : meApi.declineInvitation(inv.organization_id),
    onSuccess: async (_d, accept) => {
      await Promise.all([qc.invalidateQueries({ queryKey: keys.invitations }), qc.invalidateQueries({ queryKey: keys.me })]);
      if (accept) {
        toast.success(`You joined ${inv.organization_name}`);
        router.push(`/orgs/${inv.organization_id}`);
      } else {
        toast.success("Invitation declined");
      }
    },
    onError: (err) => toast.error(errorMessage(err)),
  });
  const busy = respond.isPending;
  return (
    <Card className="flex-col gap-3 px-4 sm:flex-row sm:items-center">
      <span className="hidden size-10 items-center justify-center rounded-lg bg-primary/10 text-primary sm:flex">
        <BuildingIcon className="size-5" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="truncate font-medium">{inv.organization_name}</p>
        <p className="text-xs text-muted-foreground">
          Invited as <Badge variant="secondary">{roleName(inv.role)}</Badge> · {fmtRelative(inv.invited_at)}
        </p>
      </div>
      <div className="flex gap-2">
        <Button variant="outline" disabled={busy} onClick={() => respond.mutate(false)}>
          Decline
        </Button>
        <Button disabled={busy} onClick={() => respond.mutate(true)}>
          {busy && respond.variables && <Spinner />} Accept
        </Button>
      </div>
    </Card>
  );
}

export function InvitationsList() {
  const { data, error, isPending, refetch } = useInvitations();
  const { data: me } = useMe();
  return (
    <>
      <PageHeader
        title="Invitations"
        description={
          me ? (
            <>
              Invitations sent to <span className="font-medium text-foreground">{me.email}</span>.
            </>
          ) : undefined
        }
      />
      {isPending ? (
        <ListSkeleton rows={2} />
      ) : error ? (
        <ErrorState error={error} onRetry={() => refetch()} what="your invitations" />
      ) : data.length === 0 ? (
        <EmptyState icon={<InboxIcon />} title="No pending invitations" description="When someone invites you to an organization, it shows up here." />
      ) : (
        <div className="space-y-3">
          {data.map((inv) => (
            <InvitationRow key={inv.organization_id} inv={inv} />
          ))}
        </div>
      )}
    </>
  );
}
