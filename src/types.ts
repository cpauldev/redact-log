/**
 * A rule defining a pattern matching string segment and its replacement string or generator.
 */
export type ReplacementRule = {
  /** The regular expression pattern to identify sensitive strings. */
  pattern: RegExp;
  /** The text replacement or callback function generating the replacement text. */
  replacement: string | ((match: string, ...args: unknown[]) => string);
};

/**
 * A predefined set of rules and patterns to apply to log messages and objects.
 */
export type RedactionPreset = {
  /** Regular expression patterns matching sensitive keys in objects. */
  keyPatterns?: RegExp[];
  /** Rules for replacing sensitive substrings in strings. */
  stringRules?: ReplacementRule[];
};

/**
 * Configuration options for the Redactor instance.
 */
export type RedactorOptions = {
  /** The placeholder string used to replace sensitive info. Defaults to '[REDACTED]'. */
  censor?: string;
  /** The placeholder string used to represent circular object references. Defaults to '[CIRCULAR]'. */
  circularValue?: string;
  /** Maximum object traversal depth before censoring. Defaults to 8. */
  maxDepth?: number;
  /** Additional custom regular expression patterns matching sensitive keys. */
  keyPatterns?: RegExp[];
  /** Additional custom rules for replacing sensitive substrings. */
  stringRules?: ReplacementRule[];
  /** Predefined redaction presets to incorporate (e.g. stripeRedactionPreset). */
  presets?: RedactionPreset[];
};

/**
 * An object instance exposing methods to redact strings and complex object hierarchies.
 */
export type Redactor = {
  /** Redacts sensitive substrings within a raw string message. */
  redactString: (value: string) => string;
  /** Traverses and redacts sensitive keys/values within objects, arrays, or maps. */
  redactValue: <T>(value: T) => T;
};

/**
 * Supported logging levels.
 */
export type LogLevel =
  | "trace"
  | "debug"
  | "info"
  | "warn"
  | "error"
  | "fatal"
  | "silent";

/**
 * Minimal console/logger facade exposing standard leveled log methods.
 */
export type Logger = {
  trace: (...args: unknown[]) => void;
  debug: (...args: unknown[]) => void;
  info: (...args: unknown[]) => void;
  warn: (...args: unknown[]) => void;
  error: (...args: unknown[]) => void;
  fatal: (...args: unknown[]) => void;
};

/**
 * Console-like interfaces containing optional leveled log methods.
 */
export type ConsoleLike = Partial<
  Pick<Console, "trace" | "debug" | "info" | "log" | "warn" | "error">
>;

/**
 * Options for initializing a RedactEngine custom Logger wrapper.
 */
export type LoggerOptions = RedactorOptions & {
  /** The underlying Console or target writer stream. */
  console?: ConsoleLike;
  /** The minimum log level required to output messages. Defaults to 'info'. */
  level?: LogLevel;
};
