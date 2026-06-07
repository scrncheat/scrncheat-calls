import { expect } from "@playwright/test";

/** Drive the passwordless login UI, reading the dev OTP from the response. */
export async function login(page, email) {
  await page.goto("/");
  await page.fill("#email", email);
  const [resp] = await Promise.all([
    page.waitForResponse(
      (r) => r.url().includes("/api/auth/request-code") && r.request().method() === "POST"
    ),
    page.click("#sendCodeButton"),
  ]);
  const { devCode } = await resp.json();
  await page.fill("#code", devCode);
  await page.click("#verifyButton");
  await expect(page.locator("#connStatus")).toHaveText("online", { timeout: 20000 });
}
