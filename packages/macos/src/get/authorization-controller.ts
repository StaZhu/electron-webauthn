import { NobjcClass, NobjcObject, getPointer } from "objc-js";
import type { ASAuthorizationController } from "objcjs-types/AuthenticationServices";
import { NSDataFromBuffer } from "objcjs-types/nsdata";

const getControllerState = new Map<string, Buffer>();

function getObjectPointerString(self: NobjcObject) {
  return getPointer(self).toString("base64");
}

export function setClientDataHash(self: NobjcObject, clientDataHash: Buffer) {
  const selfPointer = getObjectPointerString(self);
  getControllerState.set(selfPointer, clientDataHash);
}

export function removeClientDataHash(self: NobjcObject) {
  const selfPointer = getObjectPointerString(self);
  getControllerState.delete(selfPointer);
}

export const WebauthnGetController = NobjcClass.define({
  name: "WebauthnGetController",
  superclass: "ASAuthorizationController",
  methods: {
    // Overrides _requestContextWithRequests$error$ to inject our clientDataHash into BOTH
    // platform and security-key assertion options. Previously only the platform variant was
    // mutated (with security-key used as a fallback), so security-key get requests signed
    // a clientDataJSON that didn't match what we returned to the page and the relying party
    // couldn't verify the assertion.
    _requestContextWithRequests$error$: {
      types: "@@:@^@",
      implementation: (self: any, requests: any, outError: any) => {
        const context = NobjcClass.super(
          self,
          "_requestContextWithRequests$error$",
          requests,
          outError
        );

        const selfPointer = getObjectPointerString(self);
        if (getControllerState.has(selfPointer)) {
          const clientDataHash = getControllerState.get(selfPointer);

          const platformOptions =
            context.platformKeyCredentialAssertionOptions();
          if (platformOptions) {
            platformOptions.setClientDataHash$(
              NSDataFromBuffer(clientDataHash)
            );
            context.setPlatformKeyCredentialAssertionOptions$(
              platformOptions.copyWithZone$(null)
            );
          }

          // Mirror on security-key options. The setters/write-back selectors are private;
          // objc-js throws a capturable JS Error for an unrecognized selector instead of
          // crashing, so a try/catch here degrades to platform-only behavior if missing.
          const securityKeyOptions =
            context.securityKeyCredentialAssertionOptions();
          if (securityKeyOptions) {
            try {
              securityKeyOptions.setClientDataHash$(
                NSDataFromBuffer(clientDataHash)
              );
              context.setSecurityKeyCredentialAssertionOptions$(
                securityKeyOptions.copyWithZone$(null)
              );
            } catch {
              // Security-key private setters unavailable on this OS - leave its options
              // untouched rather than aborting the whole ceremony.
            }
          }
        }

        return context;
      },
    },
  },
}) as unknown as typeof ASAuthorizationController;
// Basically just ASAuthorizationController with slight bit of overrides ^
