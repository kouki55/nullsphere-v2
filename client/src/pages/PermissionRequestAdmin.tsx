import { useState } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Badge } from "@/components/ui/badge";
import { AlertCircle, CheckCircle, XCircle } from "lucide-react";
import { toast } from "sonner";

export default function PermissionRequestAdmin() {
  const { user } = useAuth();
  const [selectedRequest, setSelectedRequest] = useState<any>(null);
  const [rejectionReason, setRejectionReason] = useState("");
  const [isRejectDialogOpen, setIsRejectDialogOpen] = useState(false);

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

  // リクエスト一覧取得
  const { data: allRequests, isLoading, refetch } = trpc.permissionRequest.listAll.useQuery();

  // 承認・却下 Mutation
  const approveMutation = trpc.permissionRequest.approve.useMutation({
    onSuccess: () => {
      toast.success("リクエストを承認しました");
      refetch();
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  const rejectMutation = trpc.permissionRequest.reject.useMutation({
    onSuccess: () => {
      toast.success("リクエストを却下しました");
      setIsRejectDialogOpen(false);
      setRejectionReason("");
      setSelectedRequest(null);
      refetch();
    },
    onError: (error) => {
      toast.error(error.message);
    },
  });

  const handleApprove = (requestId: string) => {
    approveMutation.mutate({ requestId });
  };

  const handleReject = () => {
    if (!selectedRequest || rejectionReason.length < 1) {
      toast.error("却下理由を入力してください");
      return;
    }

    rejectMutation.mutate({
      requestId: selectedRequest.requestId,
      reason: rejectionReason,
    });
  };

  const pendingRequests = allRequests?.filter((r) => r.status === "pending") || [];
  const reviewedRequests = allRequests?.filter((r) => r.status !== "pending") || [];

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold">権限リクエスト管理</h1>
        <p className="text-sm text-muted-foreground mt-1">
          ユーザーの権限昇格リクエストを審査・承認
        </p>
      </div>

      {/* ペンディングリクエスト */}
      <Card>
        <CardHeader>
          <CardTitle>審査待ちリクエスト</CardTitle>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="text-center py-8 text-muted-foreground">
              読み込み中...
            </div>
          ) : pendingRequests.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              審査待ちのリクエストはありません
            </div>
          ) : (
            <div className="space-y-4">
              {pendingRequests.map((request) => (
                <div
                  key={request.requestId}
                  className="border rounded-lg p-4 space-y-3"
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="font-medium">{request.userName}</p>
                      <p className="text-sm text-muted-foreground">
                        {request.userEmail}
                      </p>
                    </div>
                    <Badge variant="secondary" className="capitalize">
                      {request.requestedRole}
                    </Badge>
                  </div>

                  <div className="bg-muted p-3 rounded text-sm">
                    <p className="font-medium mb-1">リクエスト理由</p>
                    <p className="text-muted-foreground">{request.reason}</p>
                  </div>

                  <p className="text-xs text-muted-foreground">
                    リクエスト日時: {new Date(request.createdAt).toLocaleString("ja-JP")}
                  </p>

                  <div className="flex gap-2">
                    <Button
                      onClick={() => handleApprove(request.requestId)}
                      disabled={approveMutation.isPending}
                      className="flex-1"
                    >
                      <CheckCircle className="h-4 w-4 mr-2" />
                      承認
                    </Button>
                    <Button
                      variant="destructive"
                      onClick={() => {
                        setSelectedRequest(request);
                        setIsRejectDialogOpen(true);
                      }}
                      disabled={rejectMutation.isPending}
                      className="flex-1"
                    >
                      <XCircle className="h-4 w-4 mr-2" />
                      却下
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 処理済みリクエスト */}
      <Card>
        <CardHeader>
          <CardTitle>処理済みリクエスト</CardTitle>
        </CardHeader>
        <CardContent>
          {reviewedRequests.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              処理済みのリクエストはありません
            </div>
          ) : (
            <div className="space-y-3">
              {reviewedRequests.map((request) => (
                <div
                  key={request.requestId}
                  className="border rounded-lg p-3 flex items-center justify-between"
                >
                  <div className="flex items-center gap-3 flex-1">
                    {request.status === "approved" ? (
                      <CheckCircle className="h-5 w-5 text-green-500" />
                    ) : (
                      <XCircle className="h-5 w-5 text-red-500" />
                    )}
                    <div className="flex-1">
                      <p className="font-medium text-sm">{request.userName}</p>
                      <p className="text-xs text-muted-foreground">
                        {request.reviewedAt ? new Date(request.reviewedAt).toLocaleString("ja-JP") : "処理待ち"}
                      </p>
                    </div>
                  </div>
                  <Badge
                    variant={request.status === "approved" ? "default" : "destructive"}
                    className="capitalize"
                  >
                    {request.status === "approved" ? "承認済み" : "却下"}
                  </Badge>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* 却下ダイアログ */}
      <Dialog open={isRejectDialogOpen} onOpenChange={setIsRejectDialogOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>リクエストを却下</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-2">
                {selectedRequest?.userName} の {selectedRequest?.requestedRole} リクエストを却下します
              </p>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block">却下理由</label>
              <Textarea
                placeholder="却下理由を入力してください..."
                value={rejectionReason}
                onChange={(e) => setRejectionReason(e.target.value)}
                className="min-h-20"
              />
            </div>

            <div className="flex gap-2">
              <Button
                variant="outline"
                onClick={() => {
                  setIsRejectDialogOpen(false);
                  setRejectionReason("");
                  setSelectedRequest(null);
                }}
                className="flex-1"
              >
                キャンセル
              </Button>
              <Button
                variant="destructive"
                onClick={handleReject}
                disabled={rejectMutation.isPending || rejectionReason.length < 1}
                className="flex-1"
              >
                却下
              </Button>
            </div>
          </div>
        </DialogContent>
      </Dialog>
    </div>
  );
}
