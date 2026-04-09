import { useState } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
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
import { AlertCircle, CheckCircle, XCircle, Clock } from "lucide-react";
import { toast } from "sonner";

export default function PermissionRequest() {
  const { user } = useAuth();
  const [requestedRole, setRequestedRole] = useState<"admin" | "analyst" | "operator">("analyst");
  const [reason, setReason] = useState("");
  const [isOpen, setIsOpen] = useState(false);

  // 権限リクエスト一覧取得
  const { data: myRequests, isLoading } = trpc.permissionRequest.listMy.useQuery();

  // 権限リクエスト作成
  const createRequestMutation = trpc.permissionRequest.create.useMutation({
    onSuccess: () => {
      toast.success("権限リクエストを送信しました");
      setRequestedRole("analyst");
      setReason("");
      setIsOpen(false);
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  const handleCreateRequest = () => {
    if (reason.length < 10) {
      toast.error("リクエスト理由は10文字以上必要です");
      return;
    }

    createRequestMutation.mutate({
      requestedRole,
      reason,
    });
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "pending":
        return <Clock className="h-4 w-4 text-yellow-500" />;
      case "approved":
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case "rejected":
        return <XCircle className="h-4 w-4 text-red-500" />;
      default:
        return null;
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case "pending":
        return "審査中";
      case "approved":
        return "承認済み";
      case "rejected":
        return "却下";
      default:
        return status;
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold">権限リクエスト</h1>
        <p className="text-sm text-muted-foreground mt-1">
          管理者権限の昇格をリクエストしてください
        </p>
      </div>

      {/* 現在の権限 */}
      <Card>
        <CardHeader>
          <CardTitle>現在の権限</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">ロール</p>
              <p className="text-lg font-semibold capitalize">{user?.role}</p>
            </div>
            <Badge variant="outline" className="capitalize">
              {user?.role}
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* リクエスト作成 */}
      <Card>
        <CardHeader>
          <CardTitle>新しいリクエストを作成</CardTitle>
        </CardHeader>
        <CardContent>
          <Dialog open={isOpen} onOpenChange={setIsOpen}>
            <DialogTrigger asChild>
              <Button>権限昇格をリクエスト</Button>
            </DialogTrigger>
            <DialogContent>
              <DialogHeader>
                <DialogTitle>権限昇格リクエスト</DialogTitle>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <label className="text-sm font-medium mb-2 block">
                    リクエスト対象ロール
                  </label>
                  <Select value={requestedRole} onValueChange={(value: any) => setRequestedRole(value)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="analyst">Analyst</SelectItem>
                      <SelectItem value="operator">Operator</SelectItem>
                      <SelectItem value="admin">Admin</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div>
                  <label className="text-sm font-medium mb-2 block">
                    リクエスト理由（10文字以上）
                  </label>
                  <Textarea
                    placeholder="権限が必要な理由を説明してください..."
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    className="min-h-24"
                  />
                  <p className="text-xs text-muted-foreground mt-1">
                    {reason.length}/500
                  </p>
                </div>

                <Button
                  onClick={handleCreateRequest}
                  disabled={createRequestMutation.isPending || reason.length < 10}
                  className="w-full"
                >
                  {createRequestMutation.isPending ? "送信中..." : "リクエストを送信"}
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </CardContent>
      </Card>

      {/* リクエスト一覧 */}
      <Card>
        <CardHeader>
          <CardTitle>リクエスト履歴</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">
              読み込み中...
            </div>
          ) : myRequests?.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              リクエストがありません
            </div>
          ) : (
            <div className="space-y-4">
              {myRequests?.map((request) => (
                <div
                  key={request.requestId}
                  className="border rounded-lg p-4 space-y-2"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(request.status)}
                      <div>
                        <p className="font-medium capitalize">
                          {request.requestedRole} リクエスト
                        </p>
                        <p className="text-sm text-muted-foreground">
                          {new Date(request.createdAt).toLocaleString("ja-JP")}
                        </p>
                      </div>
                    </div>
                    <Badge
                      variant={
                        request.status === "approved"
                          ? "default"
                          : request.status === "rejected"
                          ? "destructive"
                          : "secondary"
                      }
                    >
                      {getStatusLabel(request.status)}
                    </Badge>
                  </div>

                  <p className="text-sm text-muted-foreground">
                    {request.reason}
                  </p>

                  {request.status === "rejected" && request.rejectionReason && (
                    <div className="bg-red-50 dark:bg-red-950 border border-red-200 dark:border-red-800 rounded p-2 text-sm">
                      <p className="font-medium text-red-900 dark:text-red-100">
                        却下理由
                      </p>
                      <p className="text-red-800 dark:text-red-200">
                        {request.rejectionReason}
                      </p>
                    </div>
                  )}

                  {request.reviewedAt && (
                    <p className="text-xs text-muted-foreground">
                      {new Date(request.reviewedAt).toLocaleString("ja-JP")} に処理済み
                    </p>
                  )}
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
