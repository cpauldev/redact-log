<img src="https://raw.githubusercontent.com/cpauldev/redact-engine/main/banner.png" alt="RedactEngine Banner" width="100%" />

# RedactEngine: Sensitive Data Redaction for TypeScript

![TypeScript](https://img.shields.io/badge/-TypeScript-3178C6?style=flat-square&logo=typescript&logoColor=white) ![Redaction](https://img.shields.io/badge/-Data_Redaction-4F46E5?style=flat-square) ![Console](https://img.shields.io/badge/-Console_Bridge-06B6D4?style=flat-square) ![License](https://img.shields.io/badge/-MIT_License-blue?style=flat-square) [![Changelog](https://img.shields.io/badge/Changelog-v0.1.1-blue?style=flat-square)](./CHANGELOG.md)

RedactEngine is a sensitive data redaction engine for TypeScript with recursive object sanitization, string masking, logger wrappers, console bridging, and safe error handling. It gives your app one redaction layer instead of relying on every callsite to remember what is safe to print.

It is designed for developers building APIs, SaaS dashboards, CLIs, workers, billing flows, auth systems, or webhook handlers where logs are necessary but accidental secret exposure is costly. Use it when you want safe console output, structured logging inputs, provider-specific presets, and predictable handling for nested objects, `Error`, `Map`, `Set`, circular values, and max-depth limits.

#### 🤖 Ask your coding assistant

> "Audit my codebase to see if adding the `redact-engine` package on npm is beneficial. If so, explain why and draft an integration plan identifying logger entrypoints, custom redaction rules, provider presets, and console bridge points using the package README and source code."

---

## Why use RedactEngine?

| Feature              | Without RedactEngine                                                                | With **RedactEngine**                                                                              |
| :------------------- | :------------------------------------------------------------------------------- | :---------------------------------------------------------------------------------------------- |
| **Sensitive Fields** | Every logger call needs manual filtering.                                        | 🛡️ **Sensitive Fields.** Central key-pattern redaction handles common secret names.             |
| **Token Strings**    | Bearer tokens, JWTs, cookies, and assignment-style secrets can leak in messages. | 🎟️ **Token Strings.** String rules redact common token formats anywhere in text.                |
| **Provider Logs**    | Stripe-like IDs and keys require custom sanitizer code.                          | 🔌 **Provider Logs.** Use `stripeRedactionPreset` or add your own preset.                       |
| **Complex Values**   | Circular objects, errors, maps, and sets often break or leak details.            | 🧩 **Complex Values.** Built-in traversal sanitizes common runtime values safely.               |
| **Console Usage**    | Existing `console.*` calls bypass logger sanitization.                           | 🖥️ **Console Bridge.** `createConsoleBridge()` routes console calls through a redacting logger. |

---

## Installation

Install RedactEngine via your preferred package manager:

```bash
# npm
npm install redact-engine

# yarn
yarn add redact-engine

# pnpm
pnpm add redact-engine

# bun
bun add redact-engine
```

---

## Quick Start

```ts
import { createLogger, stripeRedactionPreset } from "redact-engine";

const logger = createLogger({
  level: "info",
  presets: [stripeRedactionPreset],
});

logger.error("payment failed for api_key=sk_live_abc123", {
  headers: {
    authorization: "Bearer eyJhbGciOi...",
    cookie: "session=secret",
  },
  customerId: "cus_123",
});

// Logs to the underlying console sink:
// "payment failed for api_key=[REDACTED]" {
//   headers: {
//     authorization: "Bearer [REDACTED]",
//     cookie: "session=[REDACTED]"
//   },
//   customerId: "[CUSTOMER_ID]"
// }
```

Output values are redacted before they are passed to the underlying console sink.

---

## Core Usage

### Redact strings

```ts
import { redactString } from "redact-engine";

redactString("Authorization: Bearer secret-token");
// "Authorization: Bearer [REDACTED]"
```

### Redact structured values

```ts
import { redactValue } from "redact-engine";

const safe = redactValue({
  email: "person@example.com",
  apiKey: "sk_live_123",
  nested: {
    token: "secret",
  },
});
```

### Create a custom redactor

```ts
import { createRedactor } from "redact-engine";

const redactor = createRedactor({
  keyPatterns: [/tenantSecret/i],
  stringRules: [
    {
      pattern: /internal-[a-z0-9]+/gi,
      replacement: "[INTERNAL_ID]",
    },
  ],
});

const safe = redactor.redactValue(payload);
```

### Bridge existing console calls

```ts
import { createConsoleBridge, createLogger } from "redact-engine";

const logger = createLogger({ level: "warn" });
const restoreConsole = createConsoleBridge(logger);

console.error("token=secret");

restoreConsole();
```

---

## API Reference

| Export                                  | Purpose                                                                |
| :-------------------------------------- | :--------------------------------------------------------------------- |
| `redactString(value)`                   | Redacts sensitive token-like text in a string.                         |
| `redactValue(value)`                    | Recursively redacts sensitive fields and string values.                |
| `createRedactor(options)`               | Creates a reusable redactor with custom rules and presets.             |
| `createLogger(options)`                 | Creates a redacting logger with level filtering.                       |
| `createConsoleBridge(logger, console?)` | Routes `console.debug/info/log/warn/error` through a redacting logger. |
| `defaultRedactionPreset`                | Built-in secret, token, cookie, JWT, and credential rules.             |
| `stripeRedactionPreset`                 | Stripe-style key, ID, email, card, and phone redaction rules.          |

---

## Development

To build the package and generate TypeScript declarations:

```bash
bun run build
```

To run the package unit tests:

```bash
bun run test
```

To run the package type check:

```bash
bun run typecheck
```

After building, verify the published runtime exports:

```bash
bun run test:smoke
```

---

## Related Packages

- [`rate-engine`](https://github.com/cpauldev/rate-engine) for policy-driven rate limiting.
- [`boundary-engine`](https://github.com/cpauldev/boundary-engine) for safe HTTP route boundaries.
- [`secret-engine`](https://github.com/cpauldev/secret-engine) for context-bound encryption and secret handling.
- [`session-engine`](https://github.com/cpauldev/session-engine) for browser session and cache lifecycle management.

---

## License

MIT © [Christian Paul](https://github.com/cpauldev)
