import { trpc } from "@/lib/trpc";
import { MapView } from "@/components/Map";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Globe, Target } from "lucide-react";
import { useRef, useCallback } from "react";

const severityColor: Record<string, string> = {
  critical: "#ff4455",
  high: "#ff8c00",
  medium: "#ffcc00",
  low: "#00c8ff",
};

const TARGET_LOCATION = { lat: 35.6762, lng: 139.6503 }; // Tokyo - target server

// [C-1] XSS 修正: innerHTML テンプレートリテラルを廃止し、
//        DOM API で要素を組み立てることでエスケープを保証する
function createMarkerElement(color: string, labelText: string): HTMLElement {
  const wrapper = document.createElement("div");
  wrapper.style.cssText =
    "display:flex;flex-direction:column;align-items:center;";

  const dot = document.createElement("div");
  dot.style.cssText = [
    "width:12px",
    "height:12px",
    "border-radius:50%",
    `background:${color}`,
    `border:2px solid ${color}`,
    `box-shadow:0 0 10px ${color}80`,
    "animation:pulse 2s infinite",
  ].join(";");

  const label = document.createElement("div");
  label.style.cssText =
    "font-size:9px;font-family:monospace;margin-top:3px;white-space:nowrap;";
  label.style.color = color;
  // textContent はブラウザが自動エスケープするため XSS の心配がない
  label.textContent = labelText;

  wrapper.appendChild(dot);
  wrapper.appendChild(label);
  return wrapper;
}

function createTargetMarkerElement(): HTMLElement {
  const wrapper = document.createElement("div");
  wrapper.style.cssText =
    "display:flex;flex-direction:column;align-items:center;";

  const dot = document.createElement("div");
  dot.style.cssText =
    "width:16px;height:16px;border-radius:50%;background:#00ff99;border:2px solid #00cc77;box-shadow:0 0 12px rgba(0,255,153,0.5);";

  const label = document.createElement("div");
  label.style.cssText =
    "font-size:10px;color:#00ff99;font-family:monospace;margin-top:4px;white-space:nowrap;";
  label.textContent = "TARGET SERVER";

  wrapper.appendChild(dot);
  wrapper.appendChild(label);
  return wrapper;
}

export default function ThreatMap() {
  const { data: threatList } = trpc.threats.list.useQuery();
  const { data: attackerList } = trpc.attackers.list.useQuery();
  const mapRef = useRef<google.maps.Map | null>(null);
  const markersRef = useRef<google.maps.marker.AdvancedMarkerElement[]>([]);
  const linesRef = useRef<google.maps.Polyline[]>([]);

  const onMapReady = useCallback(
    (map: google.maps.Map) => {
      mapRef.current = map;

      // Dark map style
      map.setOptions({
        styles: [
          { elementType: "geometry", stylers: [{ color: "#0d1520" }] },
          { elementType: "labels.text.stroke", stylers: [{ color: "#0d1520" }] },
          { elementType: "labels.text.fill", stylers: [{ color: "#5a7a99" }] },
          { featureType: "water", elementType: "geometry", stylers: [{ color: "#080c12" }] },
          { featureType: "road", elementType: "geometry", stylers: [{ color: "#1a2d45" }] },
          { featureType: "road", elementType: "geometry.stroke", stylers: [{ color: "#0d1520" }] },
          { featureType: "poi", stylers: [{ visibility: "off" }] },
          { featureType: "transit", stylers: [{ visibility: "off" }] },
          { featureType: "administrative", elementType: "geometry.stroke", stylers: [{ color: "#1a2d45" }] },
          { featureType: "administrative.country", elementType: "labels.text.fill", stylers: [{ color: "#3a5a7a" }] },
        ],
        disableDefaultUI: false,
        zoomControl: true,
        mapTypeControl: false,
        streetViewControl: false,
        fullscreenControl: true,
      });

      // Add target marker (Tokyo) - 静的テキストのみなので安全
      new google.maps.marker.AdvancedMarkerElement({
        map,
        position: TARGET_LOCATION,
        content: createTargetMarkerElement(),
      });

      // Add attacker markers and attack lines
      if (attackerList) {
        attackerList.forEach((attacker) => {
          if (!attacker.lat || !attacker.lng) return;
          const pos = { lat: parseFloat(attacker.lat), lng: parseFloat(attacker.lng) };
          const color = severityColor[attacker.threatLevel] || "#00c8ff";

          // [C-1] 攻撃者 IP は攻撃者制御の値のため textContent で安全に挿入
          const el = createMarkerElement(color, attacker.ip);

          const marker = new google.maps.marker.AdvancedMarkerElement({
            map,
            position: pos,
            content: el,
            // title 属性はブラウザが自動エスケープするため安全
            title: `${attacker.attackerId} - ${attacker.ip} (${attacker.country})`,
          });
          markersRef.current.push(marker);

          // Attack line
          if (attacker.isActive) {
            const line = new google.maps.Polyline({
              path: [pos, TARGET_LOCATION],
              geodesic: true,
              strokeColor: color,
              strokeOpacity: 0.4,
              strokeWeight: 1.5,
              map,
            });
            linesRef.current.push(line);
          }
        });
      }
    },
    [attackerList]
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Interactive Threat Map</h1>
          <p className="text-sm text-muted-foreground mt-1">
            攻撃元・攻撃経路・標的サーバーをリアルタイムマッピング
          </p>
        </div>
        <div className="flex items-center gap-4 text-[10px] ns-mono">
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 rounded-full bg-red-500" />
            <span className="text-muted-foreground">Critical</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 rounded-full bg-orange-500" />
            <span className="text-muted-foreground">High</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 rounded-full bg-yellow-500" />
            <span className="text-muted-foreground">Medium</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 rounded-full bg-cyan-500" />
            <span className="text-muted-foreground">Low</span>
          </div>
          <div className="flex items-center gap-1.5">
            <div className="h-2.5 w-2.5 rounded-full bg-green-400" />
            <span className="text-muted-foreground">Target</span>
          </div>
        </div>
      </div>

      {/* Map */}
      <Card className="border-border/50 bg-card/80 overflow-hidden">
        <CardContent className="p-0">
          <MapView
            className="w-full h-[500px]"
            initialCenter={{ lat: 35, lng: 60 }}
            initialZoom={3}
            onMapReady={onMapReady}
          />
        </CardContent>
      </Card>

      {/* Threat List */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {threatList?.map((t) => (
          <Card key={t.id} className="border-border/50 bg-card/80">
            <CardContent className="p-3">
              <div className="flex items-center gap-3">
                <div className="p-1.5 rounded" style={{ backgroundColor: `${severityColor[t.severity]}20` }}>
                  <Target className="h-4 w-4" style={{ color: severityColor[t.severity] }} />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium ns-mono">{t.sourceIp}</span>
                    <Badge variant="outline" className="text-[9px]" style={{ color: severityColor[t.severity], borderColor: `${severityColor[t.severity]}50` }}>
                      {t.severity}
                    </Badge>
                  </div>
                  <div className="text-[11px] text-muted-foreground mt-0.5">
                    {t.sourceCountry}, {t.sourceCity} → {t.targetHost}
                  </div>
                </div>
                <Badge variant="outline" className="text-[10px] ns-mono">{t.status}</Badge>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
