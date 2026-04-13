/**
 * mtls-client.ts
 * ===============
 * mTLS (相互TLS) クライアントの実装
 * kernel-bridge との通信を暗号化・認証する
 */

import * as fs from 'fs';
import * as path from 'path';
import * as tls from 'tls';
import { EventEmitter } from 'events';

export interface MTLSClientOptions {
  host: string;
  port: number;
  keyPath: string;
  certPath: string;
  caPath: string;
  rejectUnauthorized?: boolean;
  reconnectInterval?: number;
  maxReconnectAttempts?: number;
}

export class MTLSClient extends EventEmitter {
  private socket: tls.TLSSocket | null = null;
  private options: MTLSClientOptions;
  private reconnectAttempts: number = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private isConnecting: boolean = false;

  constructor(options: MTLSClientOptions) {
    super();
    this.options = {
      rejectUnauthorized: true,
      reconnectInterval: 5000,
      maxReconnectAttempts: 10,
      ...options,
    };
  }

  /**
   * mTLS サーバーに接続
   */
  async connect(): Promise<void> {
    if (this.isConnecting || this.socket) {
      return;
    }

    this.isConnecting = true;

    try {
      // 証明書とキーを読み込む
      const key = fs.readFileSync(this.options.keyPath, 'utf-8');
      const cert = fs.readFileSync(this.options.certPath, 'utf-8');
      const ca = fs.readFileSync(this.options.caPath, 'utf-8');

      // TLS ソケットを作成
      this.socket = tls.connect(
        {
          host: this.options.host,
          port: this.options.port,
          key,
          cert,
          ca,
          rejectUnauthorized: this.options.rejectUnauthorized,
        },
        () => {
          console.log('[MTLSClient] Connected to server');
          this.reconnectAttempts = 0;
          this.emit('connect');
        }
      );

      // データ受信時のハンドラ
      this.socket.on('data', (data: Buffer) => {
        try {
          const message = JSON.parse(data.toString('utf-8'));
          this.emit('message', message);
        } catch (error) {
          console.error('[MTLSClient] Failed to parse message:', error);
        }
      });

      // エラーハンドリング
      this.socket.on('error', (error) => {
        console.error('[MTLSClient] Socket error:', error);
        this.emit('error', error);
        this.handleDisconnect();
      });

      // 接続終了時
      this.socket.on('end', () => {
        console.log('[MTLSClient] Disconnected from server');
        this.handleDisconnect();
      });

      // 接続確立後のタイムアウトをクリア
      this.isConnecting = false;

      // 接続確立を待つ
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(() => {
          reject(new Error('Connection timeout'));
        }, 10000);

        const onConnect = () => {
          clearTimeout(timeout);
          this.socket?.removeListener('error', onError);
          resolve();
        };

        const onError = (error: Error) => {
          clearTimeout(timeout);
          this.socket?.removeListener('connect', onConnect);
          reject(error);
        };

        this.socket!.once('secureConnect', onConnect);
        this.socket!.once('error', onError);
      });
    } catch (error) {
      console.error('[MTLSClient] Failed to connect:', error);
      this.isConnecting = false;
      this.handleDisconnect();
      throw error;
    }
  }

  /**
   * 接続を処理
   */
  private handleDisconnect(): void {
    this.socket = null;
    this.isConnecting = false;

    // 再接続を試みる
    if (
      this.reconnectAttempts < (this.options.maxReconnectAttempts || 10)
    ) {
      this.reconnectAttempts++;
      console.log(
        `[MTLSClient] Reconnecting... (attempt ${this.reconnectAttempts}/${this.options.maxReconnectAttempts})`
      );

      this.reconnectTimer = setTimeout(() => {
        this.connect().catch((error) => {
          console.error('[MTLSClient] Reconnection failed:', error);
        });
      }, this.options.reconnectInterval || 5000);
    } else {
      console.error('[MTLSClient] Max reconnection attempts reached');
      this.emit('maxReconnectAttemptsReached');
    }
  }

  /**
   * サーバーにメッセージを送信
   */
  sendMessage(message: any): void {
    if (!this.socket || !this.socket.writable) {
      console.warn('[MTLSClient] Socket not connected');
      return;
    }

    try {
      const data = JSON.stringify(message);
      this.socket.write(data);
    } catch (error) {
      console.error('[MTLSClient] Failed to send message:', error);
    }
  }

  /**
   * 接続を切断
   */
  async disconnect(): Promise<void> {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.socket) {
      return new Promise((resolve) => {
        this.socket!.end(() => {
          console.log('[MTLSClient] Disconnected');
          resolve();
        });
      });
    }
  }

  /**
   * 接続状態を確認
   */
  isConnected(): boolean {
    return this.socket !== null && this.socket.writable;
  }
}

/**
 * mTLS クライアントのシングルトン インスタンス
 */
let mtlsClientInstance: MTLSClient | null = null;

/**
 * mTLS クライアントを初期化
 */
export async function initMTLSClient(
  host: string = 'localhost',
  port: number = 9998
): Promise<MTLSClient> {
  if (mtlsClientInstance) {
    return mtlsClientInstance;
  }

  const certDir = path.join(__dirname, '../../certs');

  const client = new MTLSClient({
    host,
    port,
    keyPath: path.join(certDir, 'client-key.pem'),
    certPath: path.join(certDir, 'client-cert.pem'),
    caPath: path.join(certDir, 'ca-cert.pem'),
    rejectUnauthorized: true,
  });

  await client.connect();
  mtlsClientInstance = client;

  return client;
}

/**
 * mTLS クライアントを取得
 */
export function getMTLSClient(): MTLSClient | null {
  return mtlsClientInstance;
}
