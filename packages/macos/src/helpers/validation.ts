export function isString(value: unknown): value is string {
  return typeof value === "string";
}

export function isNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value);
}

export function isObject(value: unknown) {
  return value && typeof value === "object";
}

const AUTHORIZATION_ERROR_DOMAIN =
  "com.apple.AuthenticationServices.AuthorizationError";

interface AuthorizationErrorLike {
  message?: string;
  nativeCode?: number;
  nativeDomain?: string;
}

export function mapNativeAuthorizationError(
  error: AuthorizationErrorLike
): "InvalidStateError" | "NotAllowedError" {
  // Prefer NSError code/domain from authorizationController delegates (never localized).
  if (
    error?.nativeDomain === AUTHORIZATION_ERROR_DOMAIN &&
    typeof error.nativeCode === "number"
  ) {
    return error.nativeCode === 1006 ? "InvalidStateError" : "NotAllowedError";
  }

  // Fallback: domain name and numeric code survive localization in NSError descriptions.
  const msg = error?.message ?? "";
  const match = msg.match(/AuthorizationError\D{0,20}?(\d+)/);
  const code = match ? Number(match[1]) : null;
  if (code === 1006) {
    // ASAuthorizationError.matchedExcludedCredential (create excludeCredentials only).
    return "InvalidStateError";
  }
  return "NotAllowedError";
}
