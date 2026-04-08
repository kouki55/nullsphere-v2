import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { AlertCircle, CheckCircle2, Clock, FileText } from "lucide-react";
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/_core/hooks/useAuth";

const ACTION_LABELS: Record<string, string> = {
  user_promote: "User Promoted",
  user_demote: "User Demoted",
  vm_start: "VM Started",
  vm_stop: "VM Stopped",
  vm_reboot: "VM Rebooted",
  decoy_create: "Decoy Created",
  decoy_delete: "Decoy Deleted",
  decoy_activate: "Decoy Activated",
  decoy_deactivate: "Decoy Deactivated",
  process_isolate: "Process Isolated",
  network_block: "Network Blocked",
  tracing_enable: "Tracing Enabled",
  tracing_disable: "Tracing Disabled",
  threat_resolve: "Threat Resolved",
  threat_block: "Threat Blocked",
  settings_change: "Settings Changed",
  other: "Other",
};

export default function AuditLog() {
  const { user: currentUser } = useAuth();
  const isAdmin = currentUser?.role === "admin";

  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);

  const { data: result, isLoading, error } = trpc.audit.list.useQuery(
    { limit, offset },
    { enabled: isAdmin }
  );

  // 非admin ユーザーのアクセスを制限
  if (!isAdmin) {
    return (
      <div className="space-y-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Audit Log</h1>
          <p className="text-sm text-muted-foreground mt-1">
            管理者操作の監査ログを表示
          </p>
        </div>
        <Card className="border-red-500/30 bg-red-500/10">
          <CardContent className="pt-6">
            <div className="flex gap-3">
              <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-red-400">Access Denied</p>
                <p className="text-sm text-red-400/80 mt-1">
                  This page is only accessible to administrators.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // ローディング状態
  if (isLoading) {
    return (
      <div className="space-y-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Audit Log</h1>
          <p className="text-sm text-muted-foreground mt-1">
            管理者操作の監査ログを表示
          </p>
        </div>
        <Card className="border-border/50 bg-card/80">
          <CardContent className="pt-6">
            <div className="flex items-center justify-center h-32">
              <div className="flex flex-col items-center gap-2">
                <div className="h-6 w-6 border-2 border-primary border-t-transparent rounded-full animate-spin" />
                <span className="text-xs text-muted-foreground ns-mono">LOADING...</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // エラー状態
  if (error) {
    return (
      <div className="space-y-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Audit Log</h1>
          <p className="text-sm text-muted-foreground mt-1">
            管理者操作の監査ログを表示
          </p>
        </div>
        <Card className="border-red-500/30 bg-red-500/10">
          <CardContent className="pt-6">
            <div className="flex gap-3">
              <AlertCircle className="h-5 w-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="font-medium text-red-400">Error Loading Audit Log</p>
                <p className="text-sm text-red-400/80 mt-1">
                  {error.message || "Failed to load audit logs"}
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  const logs = result?.logs ?? [];
  const total = result?.total ?? 0;
  const hasMore = result?.hasMore ?? false;

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Audit Log</h1>
        <p className="text-sm text-muted-foreground mt-1">
          管理者操作の監査ログを表示
        </p>
      </div>

      <Card className="border-border/50 bg-card/80">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <FileText className="h-4 w-4 text-primary" />
            Audit Logs ({total})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="text-[10px] ns-mono">Timestamp</TableHead>
                  <TableHead className="text-[10px] ns-mono">User</TableHead>
                  <TableHead className="text-[10px] ns-mono">Action</TableHead>
                  <TableHead className="text-[10px] ns-mono">Resource</TableHead>
                  <TableHead className="text-[10px] ns-mono">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-center py-8">
                      <p className="text-xs text-muted-foreground">No audit logs found</p>
                    </TableCell>
                  </TableRow>
                ) : (
                  logs.map((log) => (
                    <TableRow key={log.id}>
                      <TableCell className="text-xs ns-mono text-muted-foreground">
                        {new Date(log.timestamp).toLocaleString()}
                      </TableCell>
                      <TableCell className="text-xs">
                        <div className="flex flex-col">
                          <span className="font-medium">{log.userName}</span>
                          <span className="text-[9px] text-muted-foreground">ID: {log.userId}</span>
                        </div>
                      </TableCell>
                      <TableCell className="text-xs">
                        <span className="inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium bg-blue-500/20 text-blue-400 border border-blue-500/30">
                          <Clock className="h-3 w-3" />
                          {ACTION_LABELS[log.action] || log.action}
                        </span>
                      </TableCell>
                      <TableCell className="text-xs">
                        <div className="flex flex-col">
                          <span className="text-muted-foreground">{log.resourceType}</span>
                          <span className="text-[9px] text-muted-foreground">{log.resourceName}</span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className={`inline-flex items-center gap-1 px-2 py-1 rounded text-[10px] font-medium ${
                          log.status === "success"
                            ? "bg-green-500/20 text-green-400 border border-green-500/30"
                            : "bg-red-500/20 text-red-400 border border-red-500/30"
                        }`}>
                          {log.status === "success" ? (
                            <CheckCircle2 className="h-3 w-3" />
                          ) : (
                            <AlertCircle className="h-3 w-3" />
                          )}
                          {log.status === "success" ? "Success" : "Failure"}
                        </div>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>

          {/* ページネーション */}
          {total > 0 && (
            <div className="flex items-center justify-between mt-4 pt-4 border-t border-border/50">
              <p className="text-xs text-muted-foreground">
                Showing {offset + 1} to {Math.min(offset + limit, total)} of {total}
              </p>
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  className="h-6 text-[10px]"
                >
                  Previous
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!hasMore}
                  onClick={() => setOffset(offset + limit)}
                  className="h-6 text-[10px]"
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
