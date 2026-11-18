"use client";

import { AlertTriangleIcon, LockIcon, RefreshCwIcon, SearchXIcon } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Empty, EmptyContent, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { Spinner } from "@/components/ui/spinner";
import { ApiError, errorMessage } from "@/lib/api/client";

export function FullPageLoader({ label = "Loading…" }: { label?: string }) {
  return (
    <div className="flex min-h-svh items-center justify-center gap-2 text-sm text-muted-foreground" role="status">
      <Spinner /> {label}
    </div>
  );
}

export function EmptyState({
  icon,
  title,
  description,
  action,
}: {
  icon?: React.ReactNode;
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <Empty className="border border-dashed">
      <EmptyHeader>
        {icon && <EmptyMedia variant="icon">{icon}</EmptyMedia>}
        <EmptyTitle>{title}</EmptyTitle>
        {description && <EmptyDescription>{description}</EmptyDescription>}
      </EmptyHeader>
      {action && <EmptyContent>{action}</EmptyContent>}
    </Empty>
  );
}

/** Maps an API error to the right empty state: 403 / 404 / everything else. */
export function ErrorState({ error, onRetry, what = "this" }: { error: unknown; onRetry?: () => void; what?: string }) {
  const status = error instanceof ApiError ? error.status : 0;
  const requestId = error instanceof ApiError ? error.requestId : null;
  if (status === 403)
    return (
      <EmptyState
        icon={<LockIcon />}
        title="Access restricted"
        description={`Your role doesn't allow you to view ${what}. Ask an administrator if you need access.`}
      />
    );
  if (status === 404)
    return (
      <EmptyState
        icon={<SearchXIcon />}
        title="Not found"
        description={`We couldn't find ${what}. It may have been deleted, or you may not have access to it.`}
      />
    );
  return (
    <EmptyState
      icon={<AlertTriangleIcon />}
      title="Couldn't load"
      description={
        <>
          {errorMessage(error)}
          {requestId && <span className="mt-1 block font-mono text-xs">Request ID: {requestId}</span>}
        </>
      }
      action={
        onRetry && (
          <Button variant="outline" onClick={onRetry}>
            <RefreshCwIcon /> Try again
          </Button>
        )
      }
    />
  );
}

export function ListSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }, (_, i) => (
        <Skeleton key={i} className="h-12 w-full" />
      ))}
    </div>
  );
}

export function LoadMore({
  hasNextPage,
  isFetchingNextPage,
  fetchNextPage,
}: {
  hasNextPage: boolean;
  isFetchingNextPage: boolean;
  fetchNextPage: () => unknown;
}) {
  if (!hasNextPage) return null;
  return (
    <div className="flex justify-center pt-4">
      <Button variant="outline" onClick={() => fetchNextPage()} disabled={isFetchingNextPage}>
        {isFetchingNextPage && <Spinner />} Load more
      </Button>
    </div>
  );
}
