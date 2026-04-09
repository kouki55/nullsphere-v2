import { useState } from "react";
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
import { Badge } from "@/components/ui/badge";
import { AlertCircle, Download, FileText } from "lucide-react";
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
  "permission_request_create",
  "permission_request_approve",
  "permission_request_reject",
];

const EXPORT_FORMATS = [
  { value: "csv", label: "CSV", description: "スプレッドシート互換形式" },
  { value: "json", label: "JSON", description: "構造化データ形式" },
  { value: "jsonl", label: "JSON Lines", description: "大規模データ向け" },
];

export default function AuditLogExport() {
  const { user } = useAuth();
  const [exportFormat, setExportFormat] = useState<"csv" | "json" | "jsonl">("csv");
  const [startDate, setStartDate] = useState<string>("");
  const [endDate, setEndDate] = useState<string>("");
  const [userId, setUserId] = useState<string>("");
  const [action, setAction] = useState<string>("");

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

  // エクスポート API 呼び出し
  const csvExport = trpc.export.auditLogsAsCSV.useQuery(
    {
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      userId: userId ? parseInt(userId) : undefined,
      action: action || undefined,
    },
    { enabled: false }
  );

  const jsonExport = trpc.export.auditLogsAsJSON.useQuery(
    {
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      userId: userId ? parseInt(userId) : undefined,
      action: action || undefined,
    },
    { enabled: false }
  );

  const jsonlExport = trpc.export.auditLogsAsJSONL.useQuery(
    {
      startDate: startDate ? new Date(startDate) : undefined,
      endDate: endDate ? new Date(endDate) : undefined,
      userId: userId ? parseInt(userId) : undefined,
      action: action || undefined,
    },
    { enabled: false }
  );

  const handleExport = async () => {
    try {
      let result;

      if (exportFormat === "csv") {
        const { data } = await csvExport.refetch();
        result = data;
      } else if (exportFormat === "json") {
        const { data } = await jsonExport.refetch();
        result = data;
      } else {
        const { data } = await jsonlExport.refetch();
        result = data;
      }

      if (!result) {
        toast.error("エクスポートに失敗しました");
        return;
      }

      // ファイルをダウンロード
      const blob = new Blob([result.content], { type: result.mimeType });
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = result.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      toast.success(`${result.filename} をダウンロードしました`);
    } catch (error: any) {
      toast.error(error.message || "エクスポートに失敗しました");
    }
  };

  return (
    <div className="space-y-6 p-6">
      <div>
        <h1 className="text-3xl font-bold">監査ログエクスポート</h1>
        <p className="text-sm text-muted-foreground mt-1">
          監査ログを様々な形式でダウンロード
        </p>
      </div>

      {/* エクスポート設定 */}
      <Card>
        <CardHeader>
          <CardTitle>エクスポート設定</CardTitle>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* フォーマット選択 */}
          <div>
            <label className="text-sm font-medium mb-3 block">エクスポート形式</label>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {EXPORT_FORMATS.map((format) => (
                <button
                  key={format.value}
                  onClick={() => setExportFormat(format.value as any)}
                  className={`p-3 rounded-lg border-2 transition-all ${
                    exportFormat === format.value
                      ? "border-primary bg-primary/5"
                      : "border-border hover:border-primary/50"
                  }`}
                >
                  <p className="font-medium text-sm">{format.label}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    {format.description}
                  </p>
                </button>
              ))}
            </div>
          </div>

          {/* フィルタ条件 */}
          <div className="border-t pt-6">
            <h3 className="font-medium mb-4">フィルタ条件（オプション）</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
              <div>
                <label className="text-sm font-medium mb-2 block">開始日</label>
                <Input
                  type="date"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                />
              </div>

              <div>
                <label className="text-sm font-medium mb-2 block">終了日</label>
                <Input
                  type="date"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                />
              </div>

              <div>
                <label className="text-sm font-medium mb-2 block">ユーザー ID</label>
                <Input
                  type="number"
                  placeholder="ユーザー ID"
                  value={userId}
                  onChange={(e) => setUserId(e.target.value)}
                />
              </div>

              <div>
                <label className="text-sm font-medium mb-2 block">操作種別</label>
                <Select value={action} onValueChange={setAction}>
                  <SelectTrigger>
                    <SelectValue placeholder="全て" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">全て</SelectItem>
                    {ACTION_TYPES.map((act) => (
                      <SelectItem key={act} value={act}>
                        {act}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>

          {/* エクスポートボタン */}
          <div className="flex gap-2 pt-4">
            <Button
              onClick={handleExport}
              disabled={
                csvExport.isLoading || jsonExport.isLoading || jsonlExport.isLoading
              }
              className="gap-2"
            >
              <Download className="h-4 w-4" />
              エクスポート
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setStartDate("");
                setEndDate("");
                setUserId("");
                setAction("");
              }}
            >
              リセット
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 形式説明 */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="h-5 w-5" />
            形式について
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <p className="font-medium text-sm mb-1">CSV（カンマ区切り値）</p>
            <p className="text-sm text-muted-foreground">
              Excel や Google Sheets などのスプレッドシートアプリケーションで開くことができます。
              小～中規模のデータセットに最適です。
            </p>
          </div>

          <div>
            <p className="font-medium text-sm mb-1">JSON（JavaScript Object Notation）</p>
            <p className="text-sm text-muted-foreground">
              構造化されたデータ形式で、プログラミング言語で処理しやすいです。
              メタデータとフィルタ条件も含まれます。
            </p>
          </div>

          <div>
            <p className="font-medium text-sm mb-1">JSON Lines（JSONL）</p>
            <p className="text-sm text-muted-foreground">
              1行に1つの JSON オブジェクトを含む形式で、大規模なデータセットに最適です。
              ストリーミング処理やビッグデータツールと互換性があります。
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
