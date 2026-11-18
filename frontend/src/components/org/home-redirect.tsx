"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { ErrorState, FullPageLoader } from "@/components/common/states";
import { getLastOrg } from "@/lib/last-org";
import { useMe } from "@/lib/queries";

/** "/" resumes the last organization, else the first one, else the org picker. */
export function HomeRedirect() {
  const { data: me, error, refetch } = useMe();
  const router = useRouter();
  useEffect(() => {
    if (!me) return;
    const last = getLastOrg();
    const target = me.organizations.find((o) => o.id === last) ?? me.organizations[0];
    router.replace(target ? `/orgs/${target.id}` : "/orgs");
  }, [me, router]);
  if (error) return <ErrorState error={error} onRetry={() => refetch()} what="your account" />;
  return <FullPageLoader />;
}
