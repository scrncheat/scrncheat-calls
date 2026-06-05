// Outbound email via the Cloudflare Email Service `send_email` binding (EMAIL).
//
// Mirrors the proven recipe in pierrefouquet/agentic-inbox: a binding named
// EMAIL with no destination restriction, which on the Workers Paid plan delivers
// to arbitrary recipients once the sending domain is authenticated.
//
// We build the (plain-text) RFC 822 message by hand — no MIME dependency — and
// import cloudflare:email lazily so nothing is required until an email is
// actually sent. Kept as a tiny seam so it can be swapped or mocked in tests.

function buildRawEmail({ fromName, from, to, subject, text }) {
  const domain = (from.split("@")[1] || "localhost").trim();
  const messageId = `<${crypto.randomUUID()}@${domain}>`;
  const headers = [
    `From: ${fromName} <${from}>`,
    `To: <${to}>`,
    `Subject: ${subject}`,
    `Message-ID: ${messageId}`,
    `Date: ${new Date().toUTCString()}`,
    "MIME-Version: 1.0",
    "Content-Type: text/plain; charset=utf-8",
    "Content-Transfer-Encoding: 7bit",
  ];
  const body = text.replace(/\r?\n/g, "\r\n");
  return headers.join("\r\n") + "\r\n\r\n" + body + "\r\n";
}

/**
 * Send the passwordless login code to `to`.
 * @param {any} env Worker env (expects env.EMAIL, env.EMAIL_FROM, env.EMAIL_FROM_NAME)
 */
export async function sendLoginCodeEmail(env, to, code) {
  if (!env.EMAIL) {
    // Misconfigured (or local/dev without the binding): don't crash the login
    // flow. Surfaces in logs so it's caught during deploy testing.
    console.warn("EMAIL binding not configured; login code not sent.");
    return;
  }

  const raw = buildRawEmail({
    fromName: env.EMAIL_FROM_NAME || "Pierre Fouquet Calls",
    from: env.EMAIL_FROM,
    to,
    subject: "Your Pierre Fouquet Calls login code",
    text:
      `Your login code is ${code}\n\n` +
      `It expires in 10 minutes and can be used once.\n` +
      `If you didn't try to sign in, you can ignore this email.`,
  });

  const { EmailMessage } = await import("cloudflare:email");
  await env.EMAIL.send(new EmailMessage(env.EMAIL_FROM, to, raw));
}
