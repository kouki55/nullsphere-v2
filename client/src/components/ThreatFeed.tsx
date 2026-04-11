import { useEffect, useState, useRef } from 'react';
import { useSocketContext } from '@/_core/hooks/useSocket';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Zap, Clock, MapPin } from 'lucide-react';
import { toast } from 'sonner';

interface ThreatFeedEvent {
  feedId: string;
  timestamp: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  sourceIp: string;
  sourceCountry?: string;
  targetHost?: string;
  targetPort?: number;
  command?: string;
  status: string;
  metadata?: Record<string, any>;
}

const severityColor: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
};

const severityIcon: Record<string, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪',
};

interface ThreatFeedProps {
  maxItems?: number;
  autoScroll?: boolean;
  onThreatDetected?: (threat: ThreatFeedEvent) => void;
}

export function ThreatFeed({
  maxItems = 50,
  autoScroll = true,
  onThreatDetected,
}: ThreatFeedProps) {
  const { socket, isConnected, on } = useSocketContext();
  const [threats, setThreats] = useState<ThreatFeedEvent[]>([]);
  const [isLoading, setIsLoading] = useState(false);
  const feedContainerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!isConnected) return;

    const handleThreatFeedInit = (data: any) => {
      console.log('[ThreatFeed] Received initial buffer:', data);
      setThreats(data.events || []);
      setIsLoading(false);
    };

    const handleThreatFeed = (event: ThreatFeedEvent) => {
      console.log('[ThreatFeed] New threat event:', event);
      setThreats((prev) => {
        const updated = [event, ...prev];
        return updated.slice(0, maxItems);
      });

      if (onThreatDetected) {
        onThreatDetected(event);
      }

      if (['critical', 'high'].includes(event.severity)) {
        toast.error(event.title, {
          description: event.description.slice(0, 100),
          duration: 5000,
        });
      }
    };

    const handleThreatDetected = (event: ThreatFeedEvent) => {
      console.log('[ThreatFeed] Critical threat detected:', event);
      playAlertSound();
    };

    const unsubscribeFeedInit = on('threat:feed:init', handleThreatFeedInit);
    const unsubscribeFeed = on('threat:feed', handleThreatFeed);
    const unsubscribeDetected = on('threat:detected', handleThreatDetected);

    setIsLoading(true);
    socket?.emit('threat:feed:get', (data: any) => {
      handleThreatFeedInit(data);
    });

    return () => {
      unsubscribeFeedInit();
      unsubscribeFeed();
      unsubscribeDetected();
    };
  }, [isConnected, socket, on, maxItems, onThreatDetected]);

  useEffect(() => {
    if (autoScroll && feedContainerRef.current) {
      feedContainerRef.current.scrollTop = 0;
    }
  }, [threats, autoScroll]);

  return (
    <Card className="border-border/50 bg-card/80 h-full flex flex-col">
      <CardHeader className="pb-3 shrink-0">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Zap className="h-4 w-4 text-primary" />
            Real-time Threat Feed
          </CardTitle>
          <div className="flex items-center gap-2">
            <div
              className={`h-2 w-2 rounded-full ${
                isConnected ? 'bg-green-400' : 'bg-red-400'
              } ns-pulse`}
            />
            <span className="text-[10px] ns-mono text-muted-foreground">
              {isConnected ? 'LIVE' : 'OFFLINE'}
            </span>
          </div>
        </div>
      </CardHeader>
      <CardContent className="flex-1 overflow-hidden flex flex-col">
        {isLoading ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <span className="text-sm">Loading threat feed...</span>
          </div>
        ) : threats.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            <span className="text-sm">No threats detected</span>
          </div>
        ) : (
          <div
            ref={feedContainerRef}
            className="space-y-2 overflow-y-auto flex-1 pr-2"
          >
            {threats.map((threat) => (
              <ThreatFeedItem key={threat.feedId} threat={threat} />
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

interface ThreatFeedItemProps {
  threat: ThreatFeedEvent;
}

function ThreatFeedItem({ threat }: ThreatFeedItemProps) {
  const timestamp = new Date(threat.timestamp).toLocaleTimeString('ja-JP');

  return (
    <div
      className={`p-3 rounded-lg border transition-all hover:shadow-lg ${
        severityColor[threat.severity] || severityColor.info
      }`}
    >
      <div className="flex items-start gap-3">
        <div className="text-xl shrink-0">{severityIcon[threat.severity]}</div>
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2 mb-1">
            <h4 className="text-sm font-semibold truncate">{threat.title}</h4>
            <Badge
              variant="outline"
              className={`text-[10px] ns-mono shrink-0 ${
                severityColor[threat.severity]
              }`}
            >
              {threat.severity.toUpperCase()}
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground leading-snug mb-2">
            {threat.description.slice(0, 120)}
            {threat.description.length > 120 ? '...' : ''}
          </p>
          <div className="flex items-center gap-2 text-[10px] text-muted-foreground ns-mono flex-wrap">
            {threat.sourceIp && (
              <span className="flex items-center gap-1">
                <MapPin className="h-3 w-3" />
                {threat.sourceIp}
              </span>
            )}
            {threat.sourceCountry && (
              <span>({threat.sourceCountry})</span>
            )}
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {timestamp}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function playAlertSound() {
  try {
    const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
    const oscillator = audioContext.createOscillator();
    const gainNode = audioContext.createGain();

    oscillator.connect(gainNode);
    gainNode.connect(audioContext.destination);

    oscillator.frequency.value = 800;
    oscillator.type = 'sine';

    gainNode.gain.setValueAtTime(0.3, audioContext.currentTime);
    gainNode.gain.exponentialRampToValueAtTime(0.01, audioContext.currentTime + 0.5);

    oscillator.start(audioContext.currentTime);
    oscillator.stop(audioContext.currentTime + 0.5);
  } catch (e) {
    console.warn('[ThreatFeed] Could not play alert sound:', e);
  }
}
