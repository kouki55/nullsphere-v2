import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Brain, Loader2, FileText } from "lucide-react";
import { useState } from "react";
import { Streamdown } from "streamdown";
import { ThreatAnalyticsDashboard } from "@/components/ThreatAnalyticsDashboard";

const severityColor: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

export default function Analysis() {
  const { data: threatList } = trpc.threats.list.useQuery();
  const [selectedThreatId, setSelectedThreatId] = useState<string>("");
  const [analysisResult, setAnalysisResult] = useState<string>("");
  const [showAnalytics, setShowAnalytics] = useState(false);
  const analyzeMutation = trpc.analysis.analyzeThreat.useMutation({
    onSuccess: (data) => setAnalysisResult(data.analysis),
  });

  const selectedThreat = threatList?.find((t) => t.threatId === selectedThreatId);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Threat Analysis & Analytics</h1>
          <p className="text-sm text-muted-foreground mt-1">
            LLMを活用した攻撃パターン分析・意図推定・対策レポート生成
          </p>
        </div>
        <Button
          variant={showAnalytics ? "default" : "outline"}
          onClick={() => setShowAnalytics(!showAnalytics)}
          className="text-xs"
        >
          {showAnalytics ? "Show AI Analysis" : "Show Analytics"}
        </Button>
      </div>

      {showAnalytics && <ThreatAnalyticsDashboard days={7} />}

      {!showAnalytics && (
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Threat Selection */}
        <div className="space-y-4">
          <Card className="border-border/50 bg-card/80">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Brain className="h-4 w-4 text-primary" />
                Select Threat to Analyze
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <Select value={selectedThreatId} onValueChange={setSelectedThreatId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select a threat..." />
                </SelectTrigger>
                <SelectContent>
                  {threatList?.map((t) => (
                    <SelectItem key={t.threatId} value={t.threatId}>
                      <div className="flex items-center gap-2">
                        <span className="ns-mono text-xs">{t.threatId}</span>
                        <span className="text-xs text-muted-foreground">({t.type})</span>
                      </div>
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Button
                className="w-full gap-1.5"
                onClick={() => {
                  if (selectedThreatId) analyzeMutation.mutate({ threatId: selectedThreatId });
                }}
                disabled={!selectedThreatId || analyzeMutation.isPending}
              >
                {analyzeMutation.isPending ? (
                  <>
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Brain className="h-3.5 w-3.5" />
                    Analyze with AI
                  </>
                )}
              </Button>
            </CardContent>
          </Card>

          {/* Selected Threat Info */}
          {selectedThreat && (
            <Card className="border-border/50 bg-card/80">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-medium">Threat Details</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2 text-xs">
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">ID:</span>
                  <span className="ns-mono text-primary">{selectedThreat.threatId}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Type:</span>
                  <span>{selectedThreat.type}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Severity:</span>
                  <Badge variant="outline" className={`text-[10px] ns-mono ${severityColor[selectedThreat.severity]}`}>
                    {selectedThreat.severity}
                  </Badge>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Source:</span>
                  <span className="ns-mono">{selectedThreat.sourceIp}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Target:</span>
                  <span className="ns-mono">{selectedThreat.targetHost}:{selectedThreat.targetPort}</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-muted-foreground">Command:</span>
                  <code className="ns-mono text-[10px] p-1 rounded bg-background/50 border border-border/30">{selectedThreat.command}</code>
                </div>
                <p className="text-muted-foreground leading-relaxed mt-2">{selectedThreat.description}</p>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Analysis Result */}
        <div className="lg:col-span-2">
          <Card className="border-border/50 bg-card/80 min-h-[400px]">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <FileText className="h-4 w-4 text-primary" />
                AI Analysis Report
              </CardTitle>
            </CardHeader>
            <CardContent>
              {analyzeMutation.isPending ? (
                <div className="flex flex-col items-center justify-center h-64 gap-4">
                  <Loader2 className="h-8 w-8 animate-spin text-primary" />
                  <div className="text-center">
                    <p className="text-sm font-medium">Analyzing threat pattern...</p>
                    <p className="text-xs text-muted-foreground mt-1">
                      LLMが攻撃パターンを分析し、レポートを生成しています
                    </p>
                  </div>
                </div>
              ) : analysisResult ? (
                <div className="prose prose-invert prose-sm max-w-none">
                  <Streamdown>{analysisResult}</Streamdown>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center h-64 gap-3">
                  <Brain className="h-10 w-10 text-muted-foreground/30" />
                  <div className="text-center">
                    <p className="text-sm text-muted-foreground">脅威を選択し「Analyze with AI」をクリックしてください</p>
                    <p className="text-xs text-muted-foreground/60 mt-1">
                      攻撃パターン分析、意図推定、次の行動予測、対策推奨を生成します
                    </p>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
      )}
    </div>
  );
}
