/**
 * mtls-server.ts
 * ===============
 * mTLS (相互TLS) サーバーの実装
 * nl_bridge との通信を暗号化・認証する
 */

import * as fs from 'fs';
import * as path from 'path';
import * as tls from 'tls';
import * as net from 'net';
import { EventEmitter } from 'events';
import { globalPacketFilter } from './packet-filter';

export interface MTLSServerOptions {
  port: number;
  keyPath: string;
  certPath: string;
  caPath: string;
  requestCert?: boolean;
  rejectUnauthorized?: boolean;
}

export class MTLSServer extends EventEmitter {
  private server: tls.Server | null = null;
  private options: MTLSServerOptions;

  constructor(options: MTLSServerOptions) {
    super();
    this.options = {
      requestCert: true,
      rejectUnauthorized: true,
      ...options,
    };
  }

  /**
   * mTLS サーバーを起動
   */
  async start(): Promise<void> {
    try {
      // 証明書とキーを読み込む
      const key = fs.readFileSync(this.options.keyPath, 'utf-8');
      const cert = fs.readFileSync(this.options.certPath, 'utf-8');
      const ca = fs.readFileSync(this.options.caPath, 'utf-8');

      // TLS サーバーを作成
      this.server = tls.createServer(
        {
          key,
          cert,
          ca,
          requestCert: this.options.requestCert,
          rejectUnauthorized: this.options.rejectUnauthorized,
        },
        (socket: tls.TLSSocket) => {
          this.handleConnection(socket);
        }
      );

      // エラーハンドリング
      this.server.on('error', (error) => {
        console.error('[MTLSServer] Error:', error);
        this.emit('error', error);
      });

      // サーバーをリッスン開始
      await new Promise<void>((resolve, reject) => {
        this.server!.listen(this.options.port, () => {
          console.log(`[MTLSServer] Started on port ${this.options.port}`);
          resolve();
        });

        this.server!.on('error', reject);
      });
    } catch (error) {
      console.error('[MTLSServer] Failed to start:', error);
      throw error;
    }
  }

  /**
   * クライアント接続を処理
   */
  private handleConnection(socket: tls.TLSSocket): void {
    const clientCert = socket.getPeerCertificate();

    // クライアント証明書を検証
    if (!clientCert || !clientCert.subject) {
      console.warn('[MTLSServer] Connection rejected: No client certificate');
      socket.destroy();
      return;
    }

    const clientCN = clientCert.subject.CN;
    const clientId = `${clientCN}-${Date.now()}`;
    console.log(`[MTLSServer] Client connected: ${clientCN}`);

    // パケットフィルターにクライアントを登録
    globalPacketFilter.registerClient(clientId, clientCert);

    // 接続イベントを発行
    this.emit('connection', socket, clientCert);

    // データ受信時のハンドラ
    socket.on('data', (data: Buffer) => {
      // パケットフィルタリング
      if (!globalPacketFilter.filterPacket(clientId, data.length)) {
        console.warn(`[MTLSServer] Packet rejected by filter for ${clientCN}`);
        socket.write(JSON.stringify({ error: 'Rate limit exceeded' }));
        return;
      }

      try {
        const message = JSON.parse(data.toString('utf-8'));
        this.emit('message', message, socket, clientCert);
      } catch (error) {
        console.error('[MTLSServer] Failed to parse message:', error);
        socket.write(JSON.stringify({ error: 'Invalid message format' }));
      }
    });

    // エラーハンドリング
    socket.on('error', (error) => {
      console.error('[MTLSServer] Socket error:', error);
    });

    // 接続終了時
    socket.on('end', () => {
      console.log(`[MTLSServer] Client disconnected: ${clientCN}`);
      globalPacketFilter.removeClient(clientId);
      this.emit('disconnect', clientCert);
    });
  }

  /**
   * クライアントにメッセージを送信
   */
  sendMessage(socket: tls.TLSSocket, message: any): void {
    try {
      const data = JSON.stringify(message);
      socket.write(data);
    } catch (error) {
      console.error('[MTLSServer] Failed to send message:', error);
    }
  }

  /**
   * サーバーを停止
   */
  async stop(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.server) {
        this.server.close((error) => {
          if (error) {
            console.error('[MTLSServer] Error closing server:', error);
            reject(error);
          } else {
            console.log('[MTLSServer] Stopped');
            resolve();
          }
        });
      } else {
        resolve();
      }
    });
  }
}

/**
 * mTLS サーバーのシングルトン インスタンス
 */
let mtlsServerInstance: MTLSServer | null = null;

/**
 * mTLS サーバーを初期化
 */
export async function initMTLSServer(port: number = 9998): Promise<MTLSServer> {
  if (mtlsServerInstance) {
    return mtlsServerInstance;
  }

  const certDir = path.join(__dirname, '../../certs');

  const server = new MTLSServer({
    port,
    keyPath: path.join(certDir, 'server-key.pem'),
    certPath: path.join(certDir, 'server-cert.pem'),
    caPath: path.join(certDir, 'ca-cert.pem'),
    requestCert: true,
    rejectUnauthorized: true,
  });

  await server.start();
  mtlsServerInstance = server;

  return server;
}

/**
 * mTLS サーバーを取得
 */
export function getMTLSServer(): MTLSServer | null {
  return mtlsServerInstance;
}
