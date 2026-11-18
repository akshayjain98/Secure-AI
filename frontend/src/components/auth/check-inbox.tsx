import { MailCheckIcon } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";

export function CheckInbox({ title, message, email }: { title: string; message: string; email: string }) {
  return (
    <Card>
      <CardContent className="flex flex-col items-center gap-3 py-6 text-center">
        <span className="flex size-12 items-center justify-center rounded-full bg-primary/10 text-primary">
          <MailCheckIcon className="size-6" />
        </span>
        <h1 className="font-heading text-xl font-semibold">{title}</h1>
        <p className="text-sm text-muted-foreground">{message}</p>
        <p className="text-sm font-medium break-all">{email}</p>
        <p className="text-xs text-muted-foreground">
          The link expires soon. Didn&apos;t get it? Check spam, or try again in a few minutes.
        </p>
        <Button variant="outline" className="mt-2" nativeButton={false} render={<Link href="/login" />}>
          Back to sign in
        </Button>
      </CardContent>
    </Card>
  );
}
