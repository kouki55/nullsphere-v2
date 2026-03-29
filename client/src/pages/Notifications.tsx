import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Bell, Check, CheckCheck } from "lucide-react";

const severityColor: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

const severityBorder: Record<string, string> = {
  critical: "border-l-red-500",
  high: "border-l-orange-500",
  medium: "border-l-yellow-500",
  low: "border-l-blue-500",
};

export default function Notifications() {
  const { data: notifList, refetch } = trpc.notifications.list.useQuery();
  const markRead = trpc.notifications.markRead.useMutation({ onSuccess: () => refetch() });
  const markAllRead = trpc.notifications.markAllRead.useMutation({ onSuccess: () => refetch() });

  const unread = notifList?.filter((n) => !n.isRead).length ?? 0;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Notifications</h1>
          <p className="text-sm text-muted-foreground mt-1">
            重大な脅威検知時のアラート通知管理
          </p>
        </div>
        {unread > 0 && (
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5"
            onClick={() => markAllRead.mutate()}
            disabled={markAllRead.isPending}
          >
            <CheckCheck className="h-3.5 w-3.5" />
            Mark All Read ({unread})
          </Button>
        )}
      </div>

      <Card className="border-border/50 bg-card/80">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Bell className="h-4 w-4 text-primary" />
            Alert History ({notifList?.length ?? 0})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {notifList?.map((n) => (
              <div
                key={n.id}
                className={`p-4 rounded-lg border border-border/30 border-l-2 ${severityBorder[n.severity] ?? ""} ${
                  n.isRead ? "bg-background/20 opacity-60" : "bg-background/40"
                } transition-colors`}
              >
                <div className="flex items-start gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <Badge variant="outline" className={`text-[10px] ns-mono ${severityColor[n.severity]}`}>
                        {n.severity}
                      </Badge>
                      {!n.isRead && (
                        <div className="h-2 w-2 rounded-full bg-primary ns-pulse" />
                      )}
                    </div>
                    <h3 className="text-sm font-medium">{n.title}</h3>
                    <p className="text-sm text-muted-foreground mt-1 leading-relaxed">{n.message}</p>
                    <div className="flex items-center gap-3 mt-2 text-[10px] ns-mono text-muted-foreground">
                      {n.threatId && <span className="text-primary">{n.threatId}</span>}
                      <span>{new Date(n.sentAt).toLocaleString("ja-JP")}</span>
                    </div>
                  </div>
                  {!n.isRead && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0 shrink-0"
                      onClick={() => markRead.mutate({ id: n.id })}
                      disabled={markRead.isPending}
                    >
                      <Check className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
