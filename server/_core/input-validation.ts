/**
 * input-validation.ts
 * ====================
 * [M-1] Body サイズ制限
 * [M-5] 入力長さ制限
 *
 * リクエストボディのサイズと入力フィールドの長さを制限し、
 * DoS や バッファオーバーフロー を防ぐ
 */

import type { Express } from 'express';
import express from 'express';

/**
 * 入力制限の設定
 */
export const INPUT_LIMITS = {
  // [M-1] Body サイズ制限: 50MB から 10MB に削減
  BODY_SIZE_LIMIT: '10mb',
  
  // [M-5] 入力フィールドの長さ制限
  MAX_STRING_LENGTH: 1000,
  MAX_EMAIL_LENGTH: 254,
  MAX_URL_LENGTH: 2048,
  MAX_TEXTAREA_LENGTH: 10000,
  MAX_JSON_DEPTH: 10,
};

/**
 * Express アプリに Body サイズ制限を適用
 */
export function setupBodySizeLimit(app: Express): void {
  // JSON ボディサイズ制限
  app.use(express.json({ limit: INPUT_LIMITS.BODY_SIZE_LIMIT }));
  
  // URL エンコード ボディサイズ制限
  app.use(express.urlencoded({ limit: INPUT_LIMITS.BODY_SIZE_LIMIT }));

  console.log(`[Input Validation] Body size limit set to ${INPUT_LIMITS.BODY_SIZE_LIMIT}`);
}

/**
 * 文字列の長さを検証
 */
export function validateStringLength(
  value: string,
  maxLength: number = INPUT_LIMITS.MAX_STRING_LENGTH,
  fieldName: string = 'field'
): string {
  if (!value || typeof value !== 'string') {
    return '';
  }

  if (value.length > maxLength) {
    console.warn(
      `[Input Validation] ${fieldName} exceeds max length of ${maxLength}: ${value.length}`
    );
    return value.substring(0, maxLength);
  }

  return value;
}

/**
 * メールアドレスを検証
 */
export function validateEmail(email: string): boolean {
  if (!email || typeof email !== 'string') {
    return false;
  }

  if (email.length > INPUT_LIMITS.MAX_EMAIL_LENGTH) {
    return false;
  }

  // 簡易的なメールアドレス検証
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * URL を検証
 */
export function validateUrl(url: string): boolean {
  if (!url || typeof url !== 'string') {
    return false;
  }

  if (url.length > INPUT_LIMITS.MAX_URL_LENGTH) {
    return false;
  }

  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

/**
 * JSON オブジェクトの深さを検証
 */
export function validateJsonDepth(
  obj: any,
  maxDepth: number = INPUT_LIMITS.MAX_JSON_DEPTH,
  currentDepth: number = 0
): boolean {
  if (currentDepth > maxDepth) {
    return false;
  }

  if (typeof obj !== 'object' || obj === null) {
    return true;
  }

  if (Array.isArray(obj)) {
    return obj.every((item) => validateJsonDepth(item, maxDepth, currentDepth + 1));
  }

  return Object.values(obj).every((value) =>
    validateJsonDepth(value, maxDepth, currentDepth + 1)
  );
}
