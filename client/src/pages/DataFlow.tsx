import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Play, Pause, RotateCcw, ChevronRight } from "lucide-react";

const stages = [
  {
    id: 1,
    phase: "DETECT",
    label: "検知",
    color: "text-red-400",
    bg: "bg-red-500/10",
    border: "border-red-500/40",
    dotBg: "bg-red-500/20",
    dotBorder: "border-red-500",
    description: 'ハッカーが cat /etc/shadow（パスワードファイル閲覧）を実行する。',
    detail: "NullSphere Engineのkprobeが sys_open システムコールをフックし、/etc/shadow へのアクセスを即座に検知。",
    command: "$ cat /etc/shadow",
  },
  {
    id: 2,
    phase: "BLOCK",
    label: "遮断",
    color: "text-purple-400",
    bg: "bg-purple-500/10",
    border: "border-purple-500/40",
    dotBg: "bg-purple-500/20",
    dotBorder: "border-purple-500",
    description: "NullSphere Engine (eBPF) がカーネル空間でフックし、本番環境での実行をブロック（Kill）する。",
    detail: "eBPFプログラムが bpf_send_signal(SIGKILL) を発行し、対象プロセス (PID 4521) を即座に終了。",
    command: ">> SIGKILL sent to PID 4521",
  },
  {
    id: 3,
    phase: "REDIRECT",
    label: "転送",
    color: "text-cyan-400",
    bg: "bg-cyan-500/10",
    border: "border-cyan-500/40",
    dotBg: "bg-cyan-500/20",
    dotBorder: "border-cyan-500",
    description: "バックグラウンドで待機していた The Void (Micro-VM) に同名プロセスを渡し、セッションを繋ぐ。",
    detail: "Firecrackerが23msでMicro-VMを起動。攻撃者のTCPセッションをVM-001へシームレスに転送。",
    command: ">> Session migrated to VM-001 (23ms)",
  },
  {
    id: 4,
    phase: "DECEIVE",
    label: "欺瞞",
    color: "text-yellow-400",
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/40",
    dotBg: "bg-yellow-500/20",
    dotBorder: "border-yellow-500",
    description: 'ハッカーの画面には「偽のパスワード情報（囮）」が表示される。ハッカーは侵入に成功したと錯覚する。',
    detail: "NullHorizonが生成した偽の/etc/shadowファイルを返却。攻撃者は本物のデータを入手したと信じる。",
    command: "root:$6$fake$hash:19000:0:99999:7:::",
  },
  {
    id: 5,
    phase: "TRACE",
    label: "追跡",
    color: "text-cyan-400",
    bg: "bg-cyan-500/10",
    border: "border-cyan-500/40",
    dotBg: "bg-cyan-500/20",
    dotBorder: "border-cyan-500",
    description: "NullHorizonが囮にアクセスした通信経路を逆引きし、ハッカーのプロファイリング（IP, OS, 位置情報）を開始する。",
    detail: "逆探知により攻撃元を特定: 185.220.101.34 (Moscow, Russia) / Kali Linux / Rostelecom ISP / APT28関連",
    command: ">> Traceback: 3 hops identified",
  },
  {
    id: 6,
    phase: "VISUALIZE",
    label: "可視化",
    color: "text-green-400",
    bg: "bg-green-500/10",
    border: "border-green-500/40",
    dotBg: "bg-green-500/20",
    dotBorder: "border-green-500",
    description: '抽出データが Control Node に送られ、管理者のダッシュボードに「ハッカー捕捉完了」のアラートが届く。',
    detail: "全プロファイリングデータをダッシュボードに表示。SOCチームへ緊急アラートを送信完了。",
    command: ">> ALERT: Attacker captured ✓",
  },
];

export default function DataFlow() {
  const [activeStage, setActiveStage] = useState(0);
  const [isPlaying, setIsPlaying] = useState(false);

  useEffect(() => {
    if (!isPlaying) return;
    const timer = setInterval(() => {
      setActiveStage((prev) => {
        if (prev >= stages.length - 1) {
          setIsPlaying(false);
          return prev;
        }
        return prev + 1;
      });
    }, 2500);
    return () => clearInterval(timer);
  }, [isPlaying]);

  const reset = () => {
    setActiveStage(0);
    setIsPlaying(false);
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Data Flow Simulator</h1>
          <p className="text-sm text-muted-foreground mt-1">
            検知 → 遮断 → 転送 → 欺瞞 → 追跡 → 可視化
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsPlaying(!isPlaying)}
            className="gap-1.5"
          >
            {isPlaying ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
            {isPlaying ? "Pause" : "Play"}
          </Button>
          <Button variant="outline" size="sm" onClick={reset} className="gap-1.5">
            <RotateCcw className="h-3.5 w-3.5" />
            Reset
          </Button>
        </div>
      </div>

      {/* Progress Bar */}
      <div className="flex items-center gap-1">
        {stages.map((s, i) => (
          <div key={s.id} className="flex items-center flex-1">
            <button
              onClick={() => { setActiveStage(i); setIsPlaying(false); }}
              className={`flex-1 h-1.5 rounded-full transition-all duration-500 ${
                i <= activeStage ? "bg-primary" : "bg-muted"
              }`}
            />
            {i < stages.length - 1 && <ChevronRight className="h-3 w-3 text-muted-foreground/30 shrink-0" />}
          </div>
        ))}
      </div>

      {/* Stage Cards */}
      <div className="space-y-0">
        {stages.map((stage, idx) => {
          const isActive = idx === activeStage;
          const isPast = idx < activeStage;
          const isFuture = idx > activeStage;

          return (
            <div key={stage.id}>
              {/* Connector */}
              {idx > 0 && (
                <div className="flex items-center justify-center py-1">
                  <div className={`w-0.5 h-6 transition-colors duration-500 ${isPast || isActive ? "bg-primary/50" : "bg-muted/30"}`} />
                </div>
              )}

              <Card
                className={`transition-all duration-500 cursor-pointer ${
                  isActive
                    ? `${stage.border} ${stage.bg} shadow-lg`
                    : isPast
                    ? "border-border/50 bg-card/60 opacity-70"
                    : "border-border/30 bg-card/30 opacity-40"
                }`}
                onClick={() => { setActiveStage(idx); setIsPlaying(false); }}
              >
                <CardContent className="p-4">
                  <div className="flex items-start gap-4">
                    {/* Step Number */}
                    <div className={`flex items-center justify-center h-10 w-10 rounded-full border-2 shrink-0 ns-mono text-sm font-bold transition-all duration-500 ${
                      isActive ? `${stage.dotBg} ${stage.dotBorder} ${stage.color}` : "bg-muted/20 border-muted text-muted-foreground"
                    }`}>
                      {String(stage.id).padStart(2, "0")}
                    </div>

                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <Badge variant="outline" className={`text-[10px] ns-mono ${isActive ? stage.color : "text-muted-foreground"}`}>
                          {stage.phase}
                        </Badge>
                        <span className={`text-sm font-medium ${isActive ? stage.color : "text-muted-foreground"}`}>
                          {stage.label}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground">{stage.description}</p>

                      {isActive && (
                        <div className="mt-3 space-y-2 animate-in fade-in slide-in-from-top-2 duration-500">
                          <p className="text-sm">{stage.detail}</p>
                          <div className="p-2 rounded bg-background/80 border border-border/50">
                            <code className="text-xs ns-mono text-primary">{stage.command}</code>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          );
        })}
      </div>
    </div>
  );
}
