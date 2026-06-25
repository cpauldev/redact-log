import { describe, expect, it, mock } from "bun:test";

import {
  createConsoleBridge,
  createLogger,
  createRedactor,
  redactString,
  redactValue,
  stripeRedactionPreset,
} from "../index";

describe("redact-engine", () => {
  it("redacts sensitive object keys and token-like strings", () => {
    const value = redactValue({
      apiKey: "sk_live_secret",
      nested: {
        header: "Bearer abc.def.ghi",
        note: "session=abcdef;",
      },
    });

    expect(value.apiKey).toBe("[REDACTED]");
    expect(value.nested.header).toBe("Bearer [REDACTED]");
    expect(value.nested.note).toBe("session=[REDACTED];");
  });

  it("handles circular values", () => {
    const value: { self?: unknown } = {};
    value.self = value;
    expect(redactValue(value).self).toBe("[CIRCULAR]");

    const arr: unknown[] = [];
    arr.push(arr);
    const redArr = redactValue(arr) as unknown[];
    expect(redArr[0]).toBe("[CIRCULAR]");

    const map = new Map<unknown, unknown>();
    map.set("self", map);
    const redMap = redactValue(map) as unknown as Array<[unknown, unknown]>;
    expect(redMap[0][1]).toBe("[CIRCULAR]");

    const set = new Set<unknown>();
    set.add(set);
    const redSet = redactValue(set) as unknown as unknown[];
    expect(redSet[0]).toBe("[CIRCULAR]");
  });

  it("handles Error, Map, and Set", () => {
    const error = new Error("token=secret");
    Object.assign(error, {
      code: "E_TEST",
      statusCode: 500,
      apiKey: "sk_live_secret",
    });
    const value = redactValue({
      error,
      map: new Map([["authorization", "Basic abc"]]),
      set: new Set(["eyJabc.def.ghi"]),
    }) as unknown as {
      error: {
        message: string;
        code: string;
        statusCode: number;
        apiKey: string;
      };
      map: Array<[unknown, unknown]>;
      set: unknown[];
    };
    expect(value.error).toMatchObject({ message: "token=[REDACTED]" });
    expect(value.error).toMatchObject({
      code: "E_TEST",
      statusCode: 500,
      apiKey: "[REDACTED]",
    });
    expect(value.map[0][1]).toBe("[REDACTED]");
    expect(value.set[0]).toBe("[REDACTED]");
  });

  it("redacts sensitive map values by key and preserves shared non-circular objects", () => {
    const shared = { value: "safe" };
    const value = redactValue({
      first: shared,
      second: shared,
      map: new Map([
        ["apiKey", "sk_live_secret"],
        ["label", "visible"],
      ]),
    }) as unknown as {
      first: { value: string };
      second: { value: string };
      map: Array<[unknown, unknown]>;
    };

    expect(value.first).toEqual({ value: "safe" });
    expect(value.second).toEqual({ value: "safe" });
    expect(value.map[0]).toEqual(["apiKey", "[REDACTED]"]);
    expect(value.map[1]).toEqual(["label", "visible"]);
  });

  it("does not let global key-pattern state skip repeated sensitive keys", () => {
    const redactor = createRedactor({
      keyPatterns: [/apiKey/g],
    });

    expect(
      redactor.redactValue({
        apiKey: "one",
        nested: { apiKey: "two" },
      }),
    ).toEqual({
      apiKey: "[REDACTED]",
      nested: { apiKey: "[REDACTED]" },
    });
  });

  it("supports Stripe-style preset redaction", () => {
    const redactor = createRedactor({ presets: [stripeRedactionPreset] });
    expect(redactor.redactString("key sk_live_abc customer cus_123")).toBe(
      "key [STRIPE_SECRET_KEY] customer [CUSTOMER_ID]",
    );
  });

  it("supports custom string rules", () => {
    const redactor = createRedactor({
      stringRules: [{ pattern: /tenant_[a-z]+/g, replacement: "[TENANT]" }],
    });
    expect(redactor.redactString("tenant_alpha")).toBe("[TENANT]");
  });

  it("creates a redacting logger and console bridge", () => {
    const error = mock();
    const info = mock();
    const consoleLike = { error, info };
    const logger = createLogger({ console: consoleLike, level: "info" });

    logger.error("password=secret");
    expect(error).toHaveBeenCalledWith("password=[REDACTED]");

    const cleanup = createConsoleBridge(logger, consoleLike);
    consoleLike.info?.("Bearer abc");
    expect(info).toHaveBeenCalledWith("Bearer [REDACTED]");
    cleanup();
  });

  it("exposes default redactString", () => {
    expect(redactString("api_key=abc")).toBe("api_key=[REDACTED]");
  });
});
