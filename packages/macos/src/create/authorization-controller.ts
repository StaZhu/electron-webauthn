import { NobjcClass, NobjcObject, getPointer } from "objc-js";
import type { ExcludeCredential } from "./internal-handler.js";
import type { ASAuthorizationController } from "objcjs-types/AuthenticationServices";
import { NSDataFromBuffer } from "objcjs-types/nsdata";
import { NSArrayFromObjects, NSStringFromString } from "objcjs-types/helpers";
import { NSNumber } from "objcjs-types/Foundation";
import { ASCPublicKeyCredentialDescriptor } from "../additional-objc/ASCPublicKeyCredentialDescriptor.js";

const createControllerState = new Map<
  string,
  [Buffer, PublicKeyCredentialParams[], boolean, ExcludeCredential[]]
>();

function getObjectPointerString(self: NobjcObject) {
  return getPointer(self).toString("base64");
}

export interface PublicKeyCredentialParams {
  type: "public-key";
  algorithm: number;
}

export function setControllerState(
  self: NobjcObject,
  clientDataHash: Buffer,
  pubKeyCredParams: PublicKeyCredentialParams[],
  residentKeyRequired: boolean,
  excludeCredentialIds: ExcludeCredential[]
) {
  const selfPointer = getObjectPointerString(self);
  createControllerState.set(selfPointer, [
    clientDataHash,
    pubKeyCredParams,
    residentKeyRequired,
    excludeCredentialIds,
  ]);
}

export function removeControllerState(self: NobjcObject) {
  const selfPointer = getObjectPointerString(self);
  createControllerState.delete(selfPointer);
}

// Mutate a single registration-options object in place: client data hash, challenge
// null-out, supported algorithms, resident-key requirement (platform only), and excluded
// credentials. `isSecurityKey` suppresses the resident-key setter (see note below).
function applyCreateOptions(
  registrationOptions: NobjcObject,
  isSecurityKey: boolean,
  clientDataHash: Buffer,
  pubKeyCredParams: PublicKeyCredentialParams[],
  residentKeyRequired: boolean,
  excludeCredentials: ExcludeCredential[]
) {
  registrationOptions.setClientDataHash$(NSDataFromBuffer(clientDataHash));
  registrationOptions.setChallenge$(null);

  // Set supported algorithm identifiers
  const supportedAlgos: NobjcObject[] = [];
  for (const param of pubKeyCredParams) {
    if (param.type === "public-key") {
      const nsNum = NSNumber.numberWithInteger$(param.algorithm);
      supportedAlgos.push(nsNum);
    }
  }
  if (supportedAlgos.length > 0) {
    registrationOptions.setSupportedAlgorithmIdentifiers$(
      NSArrayFromObjects(supportedAlgos as unknown as NobjcObject[])
    );
  }

  // Set resident key requirement
  // If this is enabled for security keys, users will not be able to scan QR code to register a new credential.
  if (!isSecurityKey) {
    registrationOptions.setShouldRequireResidentKey$(residentKeyRequired);
  }

  // Set excluded credentials
  const excludeList: NobjcObject[] = [];
  for (const cred of excludeCredentials) {
    // Convert transports to NSArray of NSString
    const transports: NobjcObject[] = [];
    if (cred.transports) {
      for (const transport of cred.transports) {
        transports.push(NSStringFromString(transport));
      }
    }

    // Create descriptor
    const credentialID = NSDataFromBuffer(cred.id);
    const transportsArray = NSArrayFromObjects(transports);

    // ASCPublicKeyCredentialDescriptor is a private class!
    const initializedDescriptor =
      ASCPublicKeyCredentialDescriptor.alloc().initWithCredentialID$transports$(
        credentialID,
        transportsArray
      );
    excludeList.push(initializedDescriptor);
  }
  if (excludeList.length > 0) {
    registrationOptions.setExcludedCredentials$(
      NSArrayFromObjects(excludeList)
    );
  }
}

export const WebauthnCreateController = NobjcClass.define({
  name: "WebauthnCreateController",
  superclass: "ASAuthorizationController",
  methods: {
    // Overrides _requestContextWithRequests$error$ to inject our clientDataHash (and a few
    // other private fields) into BOTH platform and security-key registration options. The
    // previous implementation only handled whichever of the two existed (platform first,
    // security-key as a fallback), so when attachment:"all" submitted both requests the
    // security-key request kept Apple's default hash and signed a different clientDataJSON
    // than the one we returned to the page -> relying-party verification failed.
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
        if (context && createControllerState.has(selfPointer)) {
          const [
            clientDataHash,
            pubKeyCredParams,
            residentKeyRequired,
            excludeCredentials,
          ] = createControllerState.get(selfPointer);

          const platformOptions =
            context.platformKeyCredentialCreationOptions();
          if (platformOptions) {
            applyCreateOptions(
              platformOptions,
              false,
              clientDataHash,
              pubKeyCredParams,
              residentKeyRequired,
              excludeCredentials
            );
          }

          // Mirror the injection on the security-key options. The setters are private selectors
          // and are applied as a batch: if any of them is missing on this macOS, we let the
          // error propagate (caught by the create handler -> NotAllowedError) rather than
          // leaving the security-key request with a partial mutation — e.g. clientDataHash set
          // but excludeCredentials dropped, which would let a user register an excluded
          // credential on the security-key path. Fail-closed beats a silently insecure request.
          const securityKeyOptions =
            context.securityKeyCredentialCreationOptions();
          if (securityKeyOptions) {
            applyCreateOptions(
              securityKeyOptions,
              true,
              clientDataHash,
              pubKeyCredParams,
              residentKeyRequired,
              excludeCredentials
            );
          }
        }

        return context;
      },
    },
  },
}) as unknown as typeof ASAuthorizationController;
// Basically just ASAuthorizationController with slight bit of overrides ^
