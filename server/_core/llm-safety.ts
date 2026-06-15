/**
 * llm-safety.ts
 * ==============
 * [H-2] LLM プロンプトインジェクション対策
 *
 * ユーザー入力をサニタイズし、LLM への危険なプロンプトを防ぐ
 */

/**
 * 危険なプロンプトキーワード
 */
const DANGEROUS_KEYWORDS = [
  'ignore previous instructions',
  'forget all previous',
  'disregard',
  'override',
  'system prompt',
  'jailbreak',
  'bypass',
  'execute code',
  'run command',
  'shell',
  'exec',
];

/**
 * ユーザー入力をサニタイズ
 */
export function sanitizeUserInput(input: string): string {
  if (!input || typeof input !== 'string') {
    return '';
  }

  // 危険なキーワードを検出
  const lowerInput = input.toLowerCase();
  for (const keyword of DANGEROUS_KEYWORDS) {
    if (lowerInput.includes(keyword)) {
      console.warn(`[LLM Safety] Detected dangerous keyword: ${keyword}`);
      return '';
    }
  }

  // 長さ制限（最大 1000 文字）
  const maxLength = 1000;
  if (input.length > maxLength) {
    return input.substring(0, maxLength);
  }

  return input;
}

/**
 * LLM 出力をサニタイズ
 */
export function sanitizeLLMOutput(output: string): string {
  if (!output || typeof output !== 'string') {
    return '';
  }

  // スクリプトタグを削除
  let sanitized = output.replace(/<script[^>]*>.*?<\/script>/gi, '');

  // HTML エンティティ化
  sanitized = sanitized
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');

  return sanitized;
}

/**
 * プロンプトを構造化して安全性を向上
 */
export function createSafePrompt(
  systemPrompt: string,
  userInput: string
): string {
  const sanitizedInput = sanitizeUserInput(userInput);

  // 構造化プロンプト：ユーザー入力を明確に分離
  return `${systemPrompt}

[USER INPUT]
${sanitizedInput}
[END USER INPUT]

Please respond based only on the user input above.`;
}
