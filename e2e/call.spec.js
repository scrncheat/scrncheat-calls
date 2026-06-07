import { test, expect } from "@playwright/test";
import { login } from "./helpers.js";

test("two users connect an in-app WebRTC call", async ({ browser }) => {
  const ctxA = await browser.newContext();
  const ctxB = await browser.newContext();
  await ctxA.grantPermissions(["microphone"]);
  await ctxB.grantPermissions(["microphone"]);

  const pageA = await ctxA.newPage();
  const pageB = await ctxB.newPage();

  await login(pageA, "alice-e2e@example.com");
  await login(pageB, "bob-e2e@example.com");

  // Alice calls Bob.
  await pageA.fill("#callTarget", "bob-e2e@example.com");
  await pageA.click("#callButton");

  // Bob accepts.
  await expect(pageB.locator("#incomingCall")).toBeVisible({ timeout: 20000 });
  await expect(pageB.locator("#incomingFrom")).toHaveText("alice-e2e@example.com");
  await pageB.click("#acceptButton");

  // Both sides reach a connected media state.
  await expect(pageA.locator("#callStatus")).toHaveText("Connected.", { timeout: 30000 });
  await expect(pageB.locator("#callStatus")).toHaveText("Connected.", { timeout: 30000 });

  await ctxA.close();
  await ctxB.close();
});
