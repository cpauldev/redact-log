export {
  createConsoleBridge,
  createLogger,
  createRedactor,
  defaultRedactionPreset,
  redactString,
  redactValue,
  stripeRedactionPreset,
} from "./redact-engine";

export type {
  ConsoleLike,
  LogLevel,
  Logger,
  LoggerOptions,
  RedactionPreset,
  Redactor,
  RedactorOptions,
  ReplacementRule,
} from "./types";
