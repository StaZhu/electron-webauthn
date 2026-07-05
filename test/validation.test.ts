import { describe, expect, test } from "bun:test";
import {
  isNumber,
  isString,
  mapNativeAuthorizationError,
} from "../packages/macos/src/helpers/validation";

const AUTHORIZATION_ERROR_DOMAIN =
  "com.apple.AuthenticationServices.AuthorizationError";

describe("validation helpers", () => {
  test("isString accepts empty string", () => {
    expect(isString("")).toBe(true);
    expect(isString("rp.example")).toBe(true);
    expect(isString(null)).toBe(false);
    expect(isString(undefined)).toBe(false);
  });

  test("isNumber rejects non-finite numbers", () => {
    expect(isNumber(0)).toBe(true);
    expect(isNumber(1000)).toBe(true);
    expect(isNumber(NaN)).toBe(false);
    expect(isNumber(Infinity)).toBe(false);
    expect(isNumber(null)).toBe(false);
  });

  test("mapNativeAuthorizationError uses native NSError fields", () => {
    expect(
      mapNativeAuthorizationError({
        nativeDomain: AUTHORIZATION_ERROR_DOMAIN,
        nativeCode: 1006,
      })
    ).toBe("InvalidStateError");

    expect(
      mapNativeAuthorizationError({
        nativeDomain: AUTHORIZATION_ERROR_DOMAIN,
        nativeCode: 1001,
      })
    ).toBe("NotAllowedError");
  });

  test("mapNativeAuthorizationError parses English NSError descriptions", () => {
    expect(
      mapNativeAuthorizationError({
        message:
          "The operation couldn't be completed. (com.apple.AuthenticationServices.AuthorizationError error 1006.)",
      })
    ).toBe("InvalidStateError");

    expect(
      mapNativeAuthorizationError({
        message:
          "The operation couldn't be completed. (com.apple.AuthenticationServices.AuthorizationError error 1001.)",
      })
    ).toBe("NotAllowedError");
  });

  test("mapNativeAuthorizationError parses localized NSError descriptions", () => {
    expect(
      mapNativeAuthorizationError({
        message:
          "操作无法完成。（com.apple.AuthenticationServices.AuthorizationError错误1006。）",
      })
    ).toBe("InvalidStateError");

    expect(
      mapNativeAuthorizationError({
        message:
          "操作无法完成。（com.apple.AuthenticationServices.AuthorizationError错误1001。）",
      })
    ).toBe("NotAllowedError");
  });

  test("mapNativeAuthorizationError defaults to NotAllowedError", () => {
    expect(mapNativeAuthorizationError({ message: "unknown failure" })).toBe(
      "NotAllowedError"
    );
    expect(mapNativeAuthorizationError({})).toBe("NotAllowedError");
  });

  test("mapNativeAuthorizationError maps nativeTimeout to AbortError", () => {
    // A self-initiated timeout cancellation surfaces as AbortError regardless of the
    // underlying NSError code (which is typically a cancel code that would otherwise
    // map to NotAllowedError).
    expect(mapNativeAuthorizationError({ nativeTimeout: true })).toBe(
      "AbortError"
    );
    expect(
      mapNativeAuthorizationError({
        nativeTimeout: true,
        nativeDomain: AUTHORIZATION_ERROR_DOMAIN,
        nativeCode: 1001,
      })
    ).toBe("AbortError");
    expect(
      mapNativeAuthorizationError({
        nativeTimeout: true,
        message:
          "The operation couldn't be completed. (com.apple.AuthenticationServices.AuthorizationError error 1001.)",
      })
    ).toBe("AbortError");
  });

  test("mapNativeAuthorizationError treats missing nativeTimeout as non-timeout", () => {
    expect(mapNativeAuthorizationError({ nativeTimeout: false })).toBe(
      "NotAllowedError"
    );
    expect(
      mapNativeAuthorizationError({
        nativeTimeout: false,
        nativeDomain: AUTHORIZATION_ERROR_DOMAIN,
        nativeCode: 1006,
      })
    ).toBe("InvalidStateError");
  });
});
