/**
 * dns-tunnel-detector.ts
 * =======================
 * DNS トンネリング検知エンジン (Deep Packet Inspection)
 * DNS クエリに偽装したデータ持ち出しを検知・遮断
 */

export interface DNSQuery {
  timestamp: number;
  domain: string;
  queryType: 'A' | 'AAAA' | 'MX' | 'TXT' | 'CNAME' | 'NS' | 'SOA' | 'SRV' | 'PTR' | 'OTHER';
  sourceIp: string;
  sourcePort: number;
  clientId?: string;
}

export interface DNSAnomalyScore {
  subdomainLength: number;
  subdomainEntropy: number;
  queryFrequency: number;
  domainReputation: number;
  totalScore: number;
  isAnomaly: boolean;
  reason?: string;
}

/**
 * DNS トンネリング検知エンジン
 */
export class DNSTunnelDetector {
  private queries: DNSQuery[] = [];
  private clientQueryCounts: Map<string, number> = new Map();
  private domainQueryCounts: Map<string, number> = new Map();
  private maxQueries: number = 10000;
  private anomalyThreshold: number = 0.7;
  private maxQueriesPerSecond: number = 100;
  private maxSubdomainLength: number = 63; // DNS ラベルの最大長

  constructor(
    anomalyThreshold: number = 0.7,
    maxQueriesPerSecond: number = 100
  ) {
    this.anomalyThreshold = anomalyThreshold;
    this.maxQueriesPerSecond = maxQueriesPerSecond;
  }

  /**
   * DNS クエリを分析
   */
  analyzeDNSQuery(query: DNSQuery): DNSAnomalyScore {
    const score: DNSAnomalyScore = {
      subdomainLength: 0,
      subdomainEntropy: 0,
      queryFrequency: 0,
      domainReputation: 0,
      totalScore: 0,
      isAnomaly: false,
    };

    // 1. サブドメイン長の異常性を評価
    const subdomains = query.domain.split('.');
    const mainDomain = subdomains.slice(-2).join('.');
    const subdomainPart = subdomains.slice(0, -2).join('.');

    if (subdomainPart.length > this.maxSubdomainLength * 2) {
      score.subdomainLength = 0.8; // 異常に長いサブドメイン
      score.reason = `Abnormally long subdomain: ${subdomainPart.length} chars`;
    } else if (subdomainPart.length > 50) {
      score.subdomainLength = 0.5;
    }

    // 2. エントロピーを計算（ランダム性の指標）
    score.subdomainEntropy = this.calculateEntropy(subdomainPart);
    if (score.subdomainEntropy > 4.5) {
      // 高エントロピー = ランダムなサブドメイン = 疑わしい
      score.reason = `High entropy subdomain: ${score.subdomainEntropy.toFixed(2)}`;
    }

    // 3. クエリ頻度の異常性を評価
    const clientId = query.clientId || `${query.sourceIp}:${query.sourcePort}`;
    const currentCount = this.clientQueryCounts.get(clientId) || 0;

    if (currentCount > this.maxQueriesPerSecond) {
      score.queryFrequency = 0.9; // 異常に高いクエリ頻度
      score.reason = `High query frequency: ${currentCount} queries/sec`;
    } else if (currentCount > 50) {
      score.queryFrequency = 0.6;
    }

    // 4. ドメイン評判スコア（簡略版）
    // 実運用では DNSBL や脅威インテリジェンスと連携
    score.domainReputation = this.assessDomainReputation(mainDomain);

    // 5. 総合スコアを計算
    score.totalScore = (
      score.subdomainLength * 0.3 +
      score.subdomainEntropy * 0.4 +
      score.queryFrequency * 0.2 +
      score.domainReputation * 0.1
    );

    score.isAnomaly = score.totalScore >= this.anomalyThreshold;

    // クエリを記録
    this.addQuery(query, clientId);

    return score;
  }

  /**
   * エントロピーを計算
   */
  private calculateEntropy(text: string): number {
    if (!text || text.length === 0) {
      return 0;
    }

    const frequency: Record<string, number> = {};
    for (const char of text.toLowerCase()) {
      frequency[char] = (frequency[char] || 0) + 1;
    }

    let entropy = 0;
    const len = text.length;
    for (const count of Object.values(frequency)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }

  /**
   * ドメイン評判を評価
   */
  private assessDomainReputation(domain: string): number {
    // 既知の悪質なドメイン（簡略版）
    const blacklistedDomains = [
      'example.com',
      'test.com',
      'localhost',
    ];

    if (blacklistedDomains.includes(domain)) {
      return 0.8;
    }

    // 一般的な TLD は信頼できる
    const trustedTLDs = ['.com', '.org', '.net', '.edu', '.gov', '.jp', '.uk'];
    if (trustedTLDs.some((tld) => domain.endsWith(tld))) {
      return 0.1;
    }

    // その他の TLD は中程度のリスク
    return 0.3;
  }

  /**
   * クエリを記録
   */
  private addQuery(query: DNSQuery, clientId: string): void {
    this.queries.push(query);

    // クライアント別クエリ数を更新
    const currentCount = this.clientQueryCounts.get(clientId) || 0;
    this.clientQueryCounts.set(clientId, currentCount + 1);

    // ドメイン別クエリ数を更新
    const domainCount = this.domainQueryCounts.get(query.domain) || 0;
    this.domainQueryCounts.set(query.domain, domainCount + 1);

    // バッファサイズを超えた場合は古いクエリを削除
    if (this.queries.length > this.maxQueries) {
      const oldestQuery = this.queries.shift();
      if (oldestQuery) {
        const oldClientId = oldestQuery.clientId || `${oldestQuery.sourceIp}:${oldestQuery.sourcePort}`;
        const oldCount = this.clientQueryCounts.get(oldClientId) || 0;
        if (oldCount > 1) {
          this.clientQueryCounts.set(oldClientId, oldCount - 1);
        } else {
          this.clientQueryCounts.delete(oldClientId);
        }
      }
    }
  }

  /**
   * 異常なクエリを検出
   */
  getAnomalousQueries(): Array<{ query: DNSQuery; score: DNSAnomalyScore }> {
    const result: Array<{ query: DNSQuery; score: DNSAnomalyScore }> = [];

    for (const query of this.queries) {
      const score = this.analyzeDNSQuery(query);
      if (score.isAnomaly) {
        result.push({ query, score });
      }
    }

    return result;
  }

  /**
   * クライアント別の統計を取得
   */
  getClientStatistics(): Array<{
    clientId: string;
    queryCount: number;
    anomalyRate: number;
  }> {
    const result: Array<{
      clientId: string;
      queryCount: number;
      anomalyRate: number;
    }> = [];

    this.clientQueryCounts.forEach((count, clientId) => {
      const clientQueries = this.queries.filter(
        (q) => (q.clientId || `${q.sourceIp}:${q.sourcePort}`) === clientId
      );

      const anomalyCount = clientQueries.filter((q) => {
        const score = this.analyzeDNSQuery(q);
        return score.isAnomaly;
      }).length;

      result.push({
        clientId,
        queryCount: count,
        anomalyRate: count > 0 ? anomalyCount / count : 0,
      });
    });

    return result.sort((a, b) => b.anomalyRate - a.anomalyRate);
  }

  /**
   * ドメイン別の統計を取得
   */
  getDomainStatistics(): Array<{
    domain: string;
    queryCount: number;
  }> {
    const result: Array<{ domain: string; queryCount: number }> = [];

    this.domainQueryCounts.forEach((count, domain) => {
      result.push({ domain, queryCount: count });
    });

    return result.sort((a, b) => b.queryCount - a.queryCount);
  }

  /**
   * 最近のクエリを取得
   */
  getRecentQueries(limit: number = 100): DNSQuery[] {
    return this.queries.slice(-limit);
  }

  /**
   * 統計情報をリセット
   */
  reset(): void {
    this.queries = [];
    this.clientQueryCounts.clear();
    this.domainQueryCounts.clear();
  }
}

/**
 * グローバル DNS トンネリング検知インスタンス
 */
export const globalDNSTunnelDetector = new DNSTunnelDetector(0.7, 100);
