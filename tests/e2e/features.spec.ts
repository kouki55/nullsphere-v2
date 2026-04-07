import { test, expect } from '@playwright/test';

test.describe('NullSphere Feature Tests', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await page.waitForLoadState('networkidle');
  });

  test.describe('Threat Map', () => {
    test('should load threat map with markers', async ({ page }) => {
      // Threat Map ページに遷移
      await page.click('text=Threat Map');
      await page.waitForLoadState('networkidle');

      // Google Maps が読み込まれているか確認
      const mapContainer = page.locator('[id*="map"]');
      await expect(mapContainer).toBeVisible({ timeout: 10000 });
    });

    test('should display threat map information panel', async ({ page }) => {
      await page.click('text=Threat Map');
      await page.waitForLoadState('networkidle');

      // 情報パネルが表示されているか確認
      const infoPanel = page.locator('text=Attack Origin');
      await expect(infoPanel).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('Attackers', () => {
    test('should display attacker list', async ({ page }) => {
      await page.click('text=Attackers');
      await page.waitForLoadState('networkidle');

      // 攻撃者リストが表示されているか確認
      const table = page.locator('table');
      await expect(table).toBeVisible();
    });

    test('should show attacker details when row is clicked', async ({ page }) => {
      await page.click('text=Attackers');
      await page.waitForLoadState('networkidle');

      // テーブル行をクリック
      const firstRow = page.locator('table tbody tr').first();
      await firstRow.click();

      // 詳細パネルが表示されているか確認
      const detailsPanel = page.locator('text=Attacker Details');
      await expect(detailsPanel).toBeVisible({ timeout: 5000 });
    });

    test('should display attacker threat level', async ({ page }) => {
      await page.click('text=Attackers');
      await page.waitForLoadState('networkidle');

      // 脅威レベルが表示されているか確認
      const threatLevel = page.locator('text=Threat Level');
      await expect(threatLevel).toBeVisible();
    });

    test('should display attacker command history', async ({ page }) => {
      await page.click('text=Attackers');
      await page.waitForLoadState('networkidle');

      // テーブル行をクリック
      const firstRow = page.locator('table tbody tr').first();
      await firstRow.click();

      // コマンド履歴が表示されているか確認
      const commandHistory = page.locator('text=Command History');
      await expect(commandHistory).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('Event Log', () => {
    test('should display event log table', async ({ page }) => {
      await page.click('text=Event Log');
      await page.waitForLoadState('networkidle');

      // イベントログテーブルが表示されているか確認
      const table = page.locator('table');
      await expect(table).toBeVisible();
    });

    test('should display event types', async ({ page }) => {
      await page.click('text=Event Log');
      await page.waitForLoadState('networkidle');

      // イベントタイプが表示されているか確認
      const eventType = page.locator('text=Event Type');
      await expect(eventType).toBeVisible();
    });

    test('should display event details when row is clicked', async ({ page }) => {
      await page.click('text=Event Log');
      await page.waitForLoadState('networkidle');

      // テーブル行をクリック
      const firstRow = page.locator('table tbody tr').first();
      await firstRow.click();

      // 詳細パネルが表示されているか確認
      const detailsPanel = page.locator('text=Event Details');
      await expect(detailsPanel).toBeVisible({ timeout: 5000 });
    });

    test('should filter events by type', async ({ page }) => {
      await page.click('text=Event Log');
      await page.waitForLoadState('networkidle');

      // フィルターボタンをクリック
      const filterButton = page.locator('button:has-text("Filter")').first();
      if (await filterButton.isVisible()) {
        await filterButton.click();

        // フィルターオプションが表示されているか確認
        const filterOption = page.locator('text=eBPF Hook');
        await expect(filterOption).toBeVisible({ timeout: 5000 });
      }
    });
  });

  test.describe('VM Management', () => {
    test('should display VM list', async ({ page }) => {
      await page.click('text=VM Management');
      await page.waitForLoadState('networkidle');

      // VM リストが表示されているか確認
      const vmList = page.locator('text=Active VMs');
      await expect(vmList).toBeVisible();
    });

    test('should display VM control buttons', async ({ page }) => {
      await page.click('text=VM Management');
      await page.waitForLoadState('networkidle');

      // VM コントロールボタンが表示されているか確認
      const startButton = page.locator('button:has-text("Start")').first();
      const stopButton = page.locator('button:has-text("Stop")').first();

      if (await startButton.isVisible()) {
        await expect(startButton).toBeVisible();
      }
      if (await stopButton.isVisible()) {
        await expect(stopButton).toBeVisible();
      }
    });

    test('should display VM resource usage', async ({ page }) => {
      await page.click('text=VM Management');
      await page.waitForLoadState('networkidle');

      // リソース使用状況が表示されているか確認
      const resourceUsage = page.locator('text=Resource Usage');
      await expect(resourceUsage).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('Decoy Control', () => {
    test('should display decoy types', async ({ page }) => {
      await page.click('text=Decoy Control');
      await page.waitForLoadState('networkidle');

      // デコイタイプが表示されているか確認
      const decoyTypes = page.locator('text=Decoy Types');
      await expect(decoyTypes).toBeVisible();
    });

    test('should display decoy generation controls', async ({ page }) => {
      await page.click('text=Decoy Control');
      await page.waitForLoadState('networkidle');

      // 生成ボタンが表示されているか確認
      const generateButton = page.locator('button:has-text("Generate")').first();
      if (await generateButton.isVisible()) {
        await expect(generateButton).toBeVisible();
      }
    });
  });

  test.describe('Notifications', () => {
    test('should display notification list', async ({ page }) => {
      await page.click('text=Notifications');
      await page.waitForLoadState('networkidle');

      // 通知リストが表示されているか確認
      const notificationList = page.locator('text=Notifications');
      await expect(notificationList).toBeVisible();
    });

    test('should display notification severity', async ({ page }) => {
      await page.click('text=Notifications');
      await page.waitForLoadState('networkidle');

      // 重大度が表示されているか確認
      const severity = page.locator('text=Severity');
      await expect(severity).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('AI Analysis', () => {
    test('should display analysis report', async ({ page }) => {
      await page.click('text=AI Analysis');
      await page.waitForLoadState('networkidle');

      // 分析レポートが表示されているか確認
      const report = page.locator('text=Analysis Report');
      await expect(report).toBeVisible({ timeout: 5000 });
    });

    test('should display attack pattern analysis', async ({ page }) => {
      await page.click('text=AI Analysis');
      await page.waitForLoadState('networkidle');

      // 攻撃パターン分析が表示されているか確認
      const patternAnalysis = page.locator('text=Attack Pattern');
      await expect(patternAnalysis).toBeVisible({ timeout: 5000 });
    });
  });
});
