# Changelog

All notable changes to this project will be documented in this file.

## [0.1.0] - 2026-06-25

Initial release of `RedactEngine`, a redaction-first logging toolkit for TypeScript applications.

### Added

- Added string and structured-value redaction helpers for secrets, tokens, cookies, JWTs, credentials, and provider identifiers.
- Added `createRedactor()` for reusable redaction configuration across logging surfaces.
- Added `createLogger()` for wrapping logger calls with redaction before values reach output.
- Added `createConsoleBridge()` for safely forwarding console output through the redaction pipeline.
- Added presets for common sensitive values, including Stripe-style identifiers and auth-related payloads.
- Added support for nested objects, arrays, `Error`, `Map`, `Set`, circular references, max-depth limits, and key-based field redaction.
- Added examples showing sanitized console output so developers can see both input and protected log results.
- Added TypeScript declarations, package-local tests, typecheck, build, and built-dist smoke scripts.
