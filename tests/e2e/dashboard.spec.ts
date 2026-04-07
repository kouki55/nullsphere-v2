import { test, expect } from '@playwright/test';

test.describe('NullSphere Dashboard E2E Tests', () => {
  test.beforeEach(async ({ page }) => {
    // ダッシュボードにアクセス
    await page.goto('/');
    // ページロード完了を待機
    await page.waitForLoadState('networkidle');
  });

  test('should load dashboard successfully', async ({ page }) => {
    // ダッシュボードのタイトルが表示されているか確認
    const title = page.locator('text=Threat Detection Dashboard');
    await expect(title).toBeVisible();

    // システムステータスが表示されているか確認
    const systemStatus = page.locator('text=SYSTEM OPERATIONAL');
    await expect(systemStatus).toBeVisible();
  });

  test('should display dashboard metrics', async ({ page }) => {
    // 脅威統計が表示されているか確認
    const activeThreats = page.locator('text=Active Threats');
    await expect(activeThreats).toBeVisible();

    const blocked = page.locator('text=Blocked');
    await expect(blocked).toBeVisible();

    const isolatedVms = page.locator('text=Isolated VMs');
    await expect(isolatedVms).toBeVisible();

    const activeDecoys = page.locator('text=Active Decoys');
    await expect(activeDecoys).toBeVisible();

    const attackersTracked = page.locator('text=Attackers Tracked');
    await expect(attackersTracked).toBeVisible();

    const unreadAlerts = page.locator('text=Unread Alerts');
    await expect(unreadAlerts).toBeVisible();
  });

  test('should display system components', async ({ page }) => {
    // システムコンポーネントが表示されているか確認
    const nullsphereEngine = page.locator('text=NullSphere Engine');
    await expect(nullsphereEngine).toBeVisible();

    const theVoid = page.locator('text=The Void');
    await expect(theVoid).toBeVisible();

    const nullHorizon = page.locator('text=NullHorizon');
    await expect(nullHorizon).toBeVisible();

    const controlNode = page.locator('text=Control Node');
    await expect(controlNode).toBeVisible();
  });

  test('should navigate to Architecture page', async ({ page }) => {
    // サイドバーの Architecture リンクをクリック
    await page.click('text=Architecture');
    await page.waitForLoadState('networkidle');

    // Architecture ページが表示されているか確認
    const title = page.locator('text=System Architecture');
    await expect(title).toBeVisible();
  });

  test('should navigate to Data Flow page', async ({ page }) => {
    // サイドバーの Data Flow リンクをクリック
    await page.click('text=Data Flow');
    await page.waitForLoadState('networkidle');

    // Data Flow ページが表示されているか確認
    const title = page.locator('text=Data Flow Simulator');
    await expect(title).toBeVisible();
  });

  test('should navigate to Threat Map page', async ({ page }) => {
    // サイドバーの Threat Map リンクをクリック
    await page.click('text=Threat Map');
    await page.waitForLoadState('networkidle');

    // Threat Map ページが表示されているか確認
    const title = page.locator('text=Threat Map');
    await expect(title).toBeVisible();
  });

  test('should navigate to Attackers page', async ({ page }) => {
    // サイドバーの Attackers リンクをクリック
    await page.click('text=Attackers');
    await page.waitForLoadState('networkidle');

    // Attackers ページが表示されているか確認
    const title = page.locator('text=Attacker Profiles');
    await expect(title).toBeVisible();
  });

  test('should navigate to Event Log page', async ({ page }) => {
    // サイドバーの Event Log リンクをクリック
    await page.click('text=Event Log');
    await page.waitForLoadState('networkidle');

    // Event Log ページが表示されているか確認
    const title = page.locator('text=Event Log');
    await expect(title).toBeVisible();
  });

  test('should navigate to VM Management page', async ({ page }) => {
    // サイドバーの VM Management リンクをクリック
    await page.click('text=VM Management');
    await page.waitForLoadState('networkidle');

    // VM Management ページが表示されているか確認
    const title = page.locator('text=VM Management');
    await expect(title).toBeVisible();
  });

  test('should navigate to Decoy Control page', async ({ page }) => {
    // サイドバーの Decoy Control リンクをクリック
    await page.click('text=Decoy Control');
    await page.waitForLoadState('networkidle');

    // Decoy Control ページが表示されているか確認
    const title = page.locator('text=Decoy Control');
    await expect(title).toBeVisible();
  });

  test('should navigate to Notifications page', async ({ page }) => {
    // サイドバーの Notifications リンクをクリック
    await page.click('text=Notifications');
    await page.waitForLoadState('networkidle');

    // Notifications ページが表示されているか確認
    const title = page.locator('text=Notifications');
    await expect(title).toBeVisible();
  });

  test('should navigate to AI Analysis page', async ({ page }) => {
    // サイドバーの AI Analysis リンクをクリック
    await page.click('text=AI Analysis');
    await page.waitForLoadState('networkidle');

    // AI Analysis ページが表示されているか確認
    const title = page.locator('text=AI Analysis');
    await expect(title).toBeVisible();
  });

  test('should navigate back to Dashboard from other pages', async ({ page }) => {
    // Architecture ページに遷移
    await page.click('text=Architecture');
    await page.waitForLoadState('networkidle');

    // Dashboard リンクをクリック
    await page.click('text=Dashboard');
    await page.waitForLoadState('networkidle');

    // ダッシュボードが表示されているか確認
    const title = page.locator('text=Threat Detection Dashboard');
    await expect(title).toBeVisible();
  });

  test('should display sidebar navigation', async ({ page }) => {
    // サイドバーが表示されているか確認
    const sidebar = page.locator('text=OVERVIEW');
    await expect(sidebar).toBeVisible();

    const threatIntel = page.locator('text=THREAT INTELLIGENCE');
    await expect(threatIntel).toBeVisible();

    const isolationDeception = page.locator('text=ISOLATION & DECEPTION');
    await expect(isolationDeception).toBeVisible();

    const intelligence = page.locator('text=INTELLIGENCE');
    await expect(intelligence).toBeVisible();
  });
});
