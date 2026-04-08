import { useState, useMemo } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { AlertCircle, Bell, Filter, Plus, Trash2 } from "lucide-react";
import { toast } from "sonner";

const ACTION_TYPES = [
  "user_promote",
  "user_demote",
  "vm_start",
  "vm_stop",
  "vm_reboot",
  "decoy_create",
  "decoy_delete",
  "decoy_activate",
  "decoy_deactivate",
  "process_isolate",
  "network_block",
  "tracing_enable",
  "tracing_disable",
  "threat_resolve",
  "threat_block",
  "settings_change",
  "all",
];

export default function AuditLogEnhanced() {
  const { user } = useAuth();
  const [searchUserId, setSearchUserId] = useState<string>("");
  const [searchAction, setSearchAction] = useState<string>("");
  const [startDate, setStartDate] = useState<string>("");
  const [endDate, setEndDate] = useState<string>("");
  const [limit, setLimit] = useState(50);
  const [offset, setOffset] = useState(0);

  // 権限チェック
  if (!user || user.role !== "admin") {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <AlertCircle className="h-5 w-5 text-red-500" />
              アクセス拒否
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm text-muted-foreground">
              このページにアクセスするには管理者権限が必要です。
            </p>
          </CardContent>
        </Card>
      </div>
    );
  }

  // 監査ログ取得
  const { data: auditData, isLoading } = trpc.audit.list.useQuery({
    limit,
    offset,
    userId: searchUserId ? parseInt(searchUserId) : undefined,
    action: searchAction || undefined,
    startDate: startDate ? new Date(startDate) : undefined,
    endDate: endDate ? new Date(endDate) : undefined,
  });

  // アラート設定取得
  const { data: alerts } = trpc.alert.listAlerts.useQuery();

  // アラート作成
  const createAlertMutation = trpc.alert.createAlert.useMutation({
    onSuccess: () => {
      toast.success("アラートを作成しました");
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  // アラート削除
  const deleteAlertMutation = trpc.alert.deleteAlert.useMutation({
    onSuccess: () => {
      toast.success("アラートを削除しました");
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  const handleCreateAlert = (actionType: string) => {
    createAlertMutation.mutate({
      actionType: actionType as any,
      notificationMethod: "in-app",
    });
  };

  const handleDeleteAlert = (alertId: string) => {
    deleteAlertMutation.mutate({ alertId });
  };

  const handleResetFilters = () => {
    setSearchUserId("");
    setSearchAction("");
    setStartDate("");
    setEndDate("");
    setOffset(0);
  };

  return (
    <div className="space-y-6 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">監査ログ</h1>
          <p className="text-sm text-muted-foreground mt-1">
            管理者操作の履歴を監視・検索
          </p>
        </div>
      </div>

      {/* 検索・フィルタパネル */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Filter className="h-5 w-5" />
            検索・フィルタ
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block">ユーザー ID</label>
              <Input
                type="number"
                placeholder="ユーザー ID"
                value={searchUserId}
                onChange={(e) => {
                  setSearchUserId(e.target.value);
                  setOffset(0);
                }}
              />
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">操作種別</label>
              <Select value={searchAction} onValueChange={(value) => {
                setSearchAction(value);
                setOffset(0);
              }}>
                <SelectTrigger>
                  <SelectValue placeholder="全て" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">全て</SelectItem>
                  {ACTION_TYPES.map((action) => (
                    <SelectItem key={action} value={action}>
                      {action}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">開始日</label>
              <Input
                type="date"
                value={startDate}
                onChange={(e) => {
                  setStartDate(e.target.value);
                  setOffset(0);
                }}
              />
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">終了日</label>
              <Input
                type="date"
                value={endDate}
                onChange={(e) => {
                  setEndDate(e.target.value);
                  setOffset(0);
                }}
              />
            </div>
          </div>

          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={handleResetFilters}
              className="w-full md:w-auto"
            >
              フィルタをリセット
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* アラート設定パネル */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Bell className="h-5 w-5" />
            アラート設定
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <div className="flex flex-wrap gap-2">
              {alerts?.map((alert) => (
                <Badge key={alert.alertId} variant="secondary" className="gap-2">
                  {alert.actionType}
                  <button
                    onClick={() => handleDeleteAlert(alert.alertId)}
                    className="ml-1 hover:text-red-500"
                  >
                    <Trash2 className="h-3 w-3" />
                  </button>
                </Badge>
              ))}
            </div>

            <Dialog>
              <DialogTrigger asChild>
                <Button className="gap-2">
                  <Plus className="h-4 w-4" />
                  アラートを追加
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>新しいアラートを作成</DialogTitle>
                </DialogHeader>
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-2">
                    {ACTION_TYPES.map((action) => (
                      <Button
                        key={action}
                        variant="outline"
                        onClick={() => handleCreateAlert(action)}
                        disabled={alerts?.some((a) => a.actionType === action)}
                        className="text-xs"
                      >
                        {action}
                      </Button>
                    ))}
                  </div>
                </div>
              </DialogContent>
            </Dialog>
          </div>
        </CardContent>
      </Card>

      {/* 監査ログテーブル */}
      <Card>
        <CardHeader>
          <CardTitle>操作履歴</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">
              読み込み中...
            </div>
          ) : auditData?.logs.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              監査ログがありません
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b">
                    <th className="text-left py-2 px-4">日時</th>
                    <th className="text-left py-2 px-4">ユーザー</th>
                    <th className="text-left py-2 px-4">操作</th>
                    <th className="text-left py-2 px-4">リソース</th>
                    <th className="text-left py-2 px-4">結果</th>
                  </tr>
                </thead>
                <tbody>
                  {auditData?.logs.map((log) => (
                    <tr key={log.logId} className="border-b hover:bg-muted/50">
                      <td className="py-2 px-4">
                        {new Date(log.timestamp).toLocaleString("ja-JP")}
                      </td>
                      <td className="py-2 px-4">{log.userName}</td>
                      <td className="py-2 px-4">
                        <Badge variant="outline">{log.action}</Badge>
                      </td>
                      <td className="py-2 px-4">
                        {log.resourceName || log.resourceId || "-"}
                      </td>
                      <td className="py-2 px-4">
                        <Badge
                          variant={log.status === "success" ? "default" : "destructive"}
                        >
                          {log.status}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>

              {/* ページネーション */}
              <div className="flex items-center justify-between mt-4 pt-4 border-t">
                <div className="text-sm text-muted-foreground">
                  全 {auditData?.total} 件中 {offset + 1}-{Math.min(offset + limit, auditData?.total || 0)} 件
                </div>
                <div className="flex gap-2">
                  <Button
                    variant="outline"
                    onClick={() => setOffset(Math.max(0, offset - limit))}
                    disabled={offset === 0}
                  >
                    前へ
                  </Button>
                  <Button
                    variant="outline"
                    onClick={() => setOffset(offset + limit)}
                    disabled={!auditData || offset + limit >= auditData.total}
                  >
                    次へ
                  </Button>
                </div>
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
