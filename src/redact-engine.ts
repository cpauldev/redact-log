import type {
  ConsoleLike,
  LogLevel,
  Logger,
  LoggerOptions,
  RedactionPreset,
  Redactor,
  RedactorOptions,
  ReplacementRule,
} from "./types";

const DEFAULT_CENSOR = "[REDACTED]";
const DEFAULT_CIRCULAR = "[CIRCULAR]";
const DEFAULT_MAX_DEPTH = 8;

/**
 * Default preset for redacting common credentials, passwords, APIs, tokens, and cookies.
 */
export const defaultRedactionPreset: RedactionPreset = {
  keyPatterns: [
    /(password|secret|api[_-]?key|token|authorization|cookie|session[_-]?id|client[_-]?secret|private[_-]?key|refresh[_-]?token|access[_-]?token|id[_-]?token|csrf|verification[_-]?code)/i,
  ],
  stringRules: [
    {
      pattern: /\b(Bearer|Basic)\s+[A-Za-z0-9\-._~+/]+=*/gi,
      replacement: (_match, scheme) => `${scheme} ${DEFAULT_CENSOR}`,
    },
    {
      pattern: /\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g,
      replacement: DEFAULT_CENSOR,
    },
    {
      pattern:
        /(\b(?:token|access_token|refresh_token|id_token|client_secret|api_key|password|session_id|csrf_token|verification_code)\s*[=:]\s*)([^&,\s;]+)/gi,
      replacement: (_match, prefix) => `${prefix}${DEFAULT_CENSOR}`,
    },
    {
      pattern:
        /(\b(?:__Secure-|__Host-)?(?:session|auth|token|refresh|access|id|csrf)[A-Za-z0-9_-]*=)([^;,\s]+)/gi,
      replacement: (_match, prefix) => `${prefix}${DEFAULT_CENSOR}`,
    },
  ],
};

/**
 * Stripe-specific preset for redacting Stripe keys, customer/subscription IDs, card patterns, emails, and phone numbers.
 */
export const stripeRedactionPreset: RedactionPreset = {
  stringRules: [
    { pattern: /sk_live_[a-zA-Z0-9]+/g, replacement: "[STRIPE_SECRET_KEY]" },
    { pattern: /sk_test_[a-zA-Z0-9]+/g, replacement: "[STRIPE_TEST_KEY]" },
    {
      pattern: /rk_live_[a-zA-Z0-9]+/g,
      replacement: "[STRIPE_RESTRICTED_KEY]",
    },
    {
      pattern: /rk_test_[a-zA-Z0-9]+/g,
      replacement: "[STRIPE_RESTRICTED_KEY_TEST]",
    },
    {
      pattern: /pk_live_[a-zA-Z0-9]+/g,
      replacement: "[STRIPE_PUBLISHABLE_KEY]",
    },
    {
      pattern: /pk_test_[a-zA-Z0-9]+/g,
      replacement: "[STRIPE_PUBLISHABLE_KEY_TEST]",
    },
    { pattern: /whsec_[a-zA-Z0-9]+/g, replacement: "[WEBHOOK_SECRET]" },
    { pattern: /price_[a-zA-Z0-9]+/g, replacement: "[PRICE_ID]" },
    { pattern: /prod_[a-zA-Z0-9]+/g, replacement: "[PRODUCT_ID]" },
    { pattern: /cus_[a-zA-Z0-9]+/g, replacement: "[CUSTOMER_ID]" },
    { pattern: /sub_[a-zA-Z0-9]+/g, replacement: "[SUBSCRIPTION_ID]" },
    { pattern: /pm_[a-zA-Z0-9]+/g, replacement: "[PAYMENT_METHOD_ID]" },
    { pattern: /pi_[a-zA-Z0-9]+/g, replacement: "[PAYMENT_INTENT_ID]" },
    { pattern: /in_[a-zA-Z0-9]+/g, replacement: "[INVOICE_ID]" },
    {
      pattern: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi,
      replacement: "[EMAIL]",
    },
    {
      pattern: /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
      replacement: "[CARD]",
    },
    {
      pattern: /\b\+?1?\s*\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g,
      replacement: "[PHONE]",
    },
  ],
};

function mergeOptions(
  options: RedactorOptions = {},
): Required<RedactorOptions> {
  const presets = [defaultRedactionPreset, ...(options.presets ?? [])];
  return {
    censor: options.censor ?? DEFAULT_CENSOR,
    circularValue: options.circularValue ?? DEFAULT_CIRCULAR,
    maxDepth: options.maxDepth ?? DEFAULT_MAX_DEPTH,
    keyPatterns: [
      ...presets.flatMap((preset) => preset.keyPatterns ?? []),
      ...(options.keyPatterns ?? []),
    ],
    stringRules: [
      ...presets.flatMap((preset) => preset.stringRules ?? []),
      ...(options.stringRules ?? []),
    ],
    presets: [],
  };
}

function applyRule(value: string, rule: ReplacementRule): string {
  if (typeof rule.replacement === "string") {
    return value.replace(rule.pattern, rule.replacement);
  }
  const replacement = rule.replacement;
  return value.replace(rule.pattern, (...args) =>
    replacement(args[0], ...args.slice(1)),
  );
}

function testPattern(pattern: RegExp, value: string): boolean {
  pattern.lastIndex = 0;
  return pattern.test(value);
}

/**
 * Creates a custom redactor instance configured with string rules, key patterns, and presets.
 *
 * @param options Redactor configuration options.
 * @returns A redactor instance with `redactString` and `redactValue` methods.
 */
export function createRedactor(options: RedactorOptions = {}): Redactor {
  const resolved = mergeOptions(options);

  const redactStringWithOptions = (value: string): string =>
    resolved.stringRules.reduce(
      (current, rule) => applyRule(current, rule),
      value,
    );

  const isSensitiveKey = (key: string): boolean =>
    resolved.keyPatterns.some((pattern) => testPattern(pattern, key));

  const visit = (
    input: unknown,
    depth: number,
    seen: WeakSet<object>,
  ): unknown => {
    if (input === null || input === undefined) return input;
    if (depth > resolved.maxDepth) return resolved.censor;
    if (typeof input === "string") return redactStringWithOptions(input);
    if (
      typeof input === "number" ||
      typeof input === "boolean" ||
      typeof input === "bigint"
    ) {
      return input;
    }
    if (typeof input === "symbol" || typeof input === "function") {
      return String(input);
    }
    if (input instanceof Date) return input.toISOString();
    if (input instanceof Error) {
      if (seen.has(input)) return resolved.circularValue;
      seen.add(input);
      const output: Record<string, unknown> = {
        name: input.name,
        message: redactStringWithOptions(input.message),
        stack: input.stack ? redactStringWithOptions(input.stack) : undefined,
      };
      for (const [key, value] of Object.entries(input)) {
        if (key === "name" || key === "message" || key === "stack") continue;
        output[key] = isSensitiveKey(key)
          ? resolved.censor
          : visit(value, depth + 1, seen);
      }
      seen.delete(input);
      return output;
    }
    if (Array.isArray(input)) {
      if (seen.has(input)) return resolved.circularValue;
      seen.add(input);
      const output = input.map((item) => visit(item, depth + 1, seen));
      seen.delete(input);
      return output;
    }
    if (input instanceof Map) {
      if (seen.has(input)) return resolved.circularValue;
      seen.add(input);
      const output = Array.from(input.entries()).map(([key, value]) => {
        const redactedKey = visit(key, depth + 1, seen);
        const redactedValue =
          typeof key === "string" && isSensitiveKey(key)
            ? resolved.censor
            : visit(value, depth + 1, seen);
        return [redactedKey, redactedValue];
      });
      seen.delete(input);
      return output;
    }
    if (input instanceof Set) {
      if (seen.has(input)) return resolved.circularValue;
      seen.add(input);
      const output = Array.from(input.values()).map((value) =>
        visit(value, depth + 1, seen),
      );
      seen.delete(input);
      return output;
    }
    if (typeof input === "object") {
      if (seen.has(input)) return resolved.circularValue;
      seen.add(input);
      const output: Record<string, unknown> = {};
      for (const [key, value] of Object.entries(
        input as Record<string, unknown>,
      )) {
        output[key] = isSensitiveKey(key)
          ? resolved.censor
          : visit(value, depth + 1, seen);
      }
      seen.delete(input);
      return output;
    }
    return String(input);
  };

  return {
    redactString: redactStringWithOptions,
    redactValue: <T>(value: T): T =>
      visit(value, 0, new WeakSet<object>()) as T,
  };
}

const defaultRedactor = createRedactor();

/**
 * Redacts sensitive credentials and tokens within a flat string using the default preset.
 *
 * @param value The string to sanitize.
 * @returns The sanitized string.
 */
export function redactString(value: string): string {
  return defaultRedactor.redactString(value);
}

/**
 * Recursively sanitizes sensitive object keys and string values using the default preset.
 * Supports handling of circular objects, Errors, Maps, and Sets.
 *
 * @param value The object or value to sanitize.
 * @returns A sanitized deep copy of the value.
 */
export function redactValue<T>(value: T): T {
  return defaultRedactor.redactValue(value);
}

const LEVEL_RANK: Record<LogLevel, number> = {
  trace: 10,
  debug: 20,
  info: 30,
  warn: 40,
  error: 50,
  fatal: 60,
  silent: 99,
};

const LEVEL_TO_METHOD: Record<
  Exclude<LogLevel, "silent">,
  keyof ConsoleLike
> = {
  trace: "trace",
  debug: "debug",
  info: "info",
  warn: "warn",
  error: "error",
  fatal: "error",
};

/**
 * Creates a redacting logger that sanitizes message strings and metadata objects before writing them to the console.
 *
 * @param options Logger options including redaction rules, target console, and log level.
 * @returns A structured Logger instance.
 */
export function createLogger(options: LoggerOptions = {}): Logger {
  const redactor = createRedactor(options);
  const target = options.console ?? globalThis.console;
  const sinks = {
    trace: target.trace?.bind(target),
    debug: target.debug?.bind(target),
    info: target.info?.bind(target),
    log: target.log?.bind(target),
    warn: target.warn?.bind(target),
    error: target.error?.bind(target),
  };
  const level = options.level ?? "info";

  const emit = (entryLevel: Exclude<LogLevel, "silent">, args: unknown[]) => {
    if (LEVEL_RANK[entryLevel] < LEVEL_RANK[level]) return;
    const method = LEVEL_TO_METHOD[entryLevel];
    const sink = sinks[method] ?? sinks.error ?? sinks.warn ?? sinks.log;
    if (!sink) return;
    sink(...args.map((arg) => redactor.redactValue(arg)));
  };

  return {
    trace: (...args) => emit("trace", args),
    debug: (...args) => emit("debug", args),
    info: (...args) => emit("info", args),
    warn: (...args) => emit("warn", args),
    error: (...args) => emit("error", args),
    fatal: (...args) => emit("fatal", args),
  };
}

/**
 * Bridges the global console object to route console calls through a redacting logger.
 *
 * @param logger The redacting logger to route messages through.
 * @param target The target console-like object to mock (defaults to globalThis.console).
 * @returns A function that restores the original console methods when called.
 */
export function createConsoleBridge(
  logger: Logger,
  target: ConsoleLike = globalThis.console,
): () => void {
  const original = {
    debug: target.debug,
    info: target.info,
    log: target.log,
    warn: target.warn,
    error: target.error,
  };

  target.debug = (...args: unknown[]) => logger.debug(...args);
  target.info = (...args: unknown[]) => logger.info(...args);
  target.log = (...args: unknown[]) => logger.info(...args);
  target.warn = (...args: unknown[]) => logger.warn(...args);
  target.error = (...args: unknown[]) => logger.error(...args);

  return () => {
    target.debug = original.debug;
    target.info = original.info;
    target.log = original.log;
    target.warn = original.warn;
    target.error = original.error;
  };
}
