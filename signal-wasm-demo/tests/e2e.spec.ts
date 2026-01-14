import { expect, test } from "@playwright/test";

test("complete 1:1 messaging flow with custom usernames", async ({ page }) => {
  // 1. Load the page
  await page.goto("/");

  // 2. Verify inputs are present and fill them (even though defaults match)
  const aliceInput = page.getByPlaceholder("Client A");
  const bobInput = page.getByPlaceholder("Client B");

  await expect(aliceInput).toBeVisible();
  await expect(bobInput).toBeVisible();

  await aliceInput.fill("Alice");
  await bobInput.fill("Bob");

  // 3. Init WASM
  await page.getByRole("button", { name: "1. Init WASM" }).click();
  // Wait for it to become "✅ WASM Ready"
  await expect(
    page.getByRole("button", { name: "✅ WASM Ready" })
  ).toBeVisible();

  // 4. Create Alice
  await page.getByRole("button", { name: "2. Create Alice" }).click();
  await expect(
    page.getByRole("button", { name: "✅ Alice Ready" })
  ).toBeVisible();

  // 5. Create Bob
  await page.getByRole("button", { name: "3. Create Bob" }).click();
  await expect(
    page.getByRole("button", { name: "✅ Bob Ready" })
  ).toBeVisible();

  // 6. Establish Session
  await page.getByRole("button", { name: "1. Alice→Bob Session" }).click();
  // Check log for success
  await expect(
    page.locator(".log-message", { hasText: "✅ Session established!" })
  ).toBeVisible();

  // 7. Alice Encrypt
  await page.getByRole("button", { name: "2. Alice Encrypt" }).click();
  // Check log for encryption
  await expect(
    page.locator(".log-message", { hasText: "Encrypted to Bob" })
  ).toBeVisible();

  // 8. Bob Decrypt
  await page.getByRole("button", { name: "3. Bob Decrypt" }).click();

  // 9. Assert Decryption
  // "🔓 Decrypted from Alice" should appear in a log message, followed by the plaintext "Hello Bob! 🔒"
  // The log UI structure is: <div class="log-message">🔓 Decrypted from Alice</div> <pre class="log-data">Hello Bob! 🔒</pre>

  // We can just check for the text "Hello Bob! 🔒" being visible on the page
  await expect(page.getByText("Hello Bob! 🔒")).toBeVisible();
});
