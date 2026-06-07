import { test, expect } from "@playwright/test";
import { login } from "./helpers.js";

test("login, number verification, and dialing via the mock carrier", async ({ page }) => {
  await login(page, "e2e-user@example.com");
  await expect(page.locator("#accountEmail")).toHaveText("e2e-user@example.com");

  // Register a number.
  await page.fill("#newNumber", "+447400123456");
  await Promise.all([
    page.waitForResponse((r) => r.url().endsWith("/api/numbers") && r.request().method() === "POST"),
    page.click("#addNumberButton"),
  ]);
  await expect(page.locator("#numbersList")).toContainText("+447400123456");

  // Verify ownership using the dev OTP from the verify response.
  const [verifyResp] = await Promise.all([
    page.waitForResponse((r) => r.url().includes("/verify")),
    page.click('button[data-action="send"]'),
  ]);
  const { devCode } = await verifyResp.json();
  await page.fill("input[data-code]", devCode);
  await page.click('button[data-action="confirm"]');
  await expect(page.locator(".badge.ok")).toBeVisible();

  // Dial a normal international number -> the mock places the call.
  await page.selectOption("#callerId", { index: 0 });
  await page.fill("#dialTarget", "+33123456789");
  await page.click("#dialButton");
  await expect(page.locator("#dialStatus")).toContainText("Calling");

  // Premium-rate is blocked.
  await page.fill("#dialTarget", "+449001234567");
  await page.click("#dialButton");
  await expect(page.locator("#dialStatus")).toContainText("Blocked");
});
