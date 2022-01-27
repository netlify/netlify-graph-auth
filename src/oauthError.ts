type ErrorObject = {
  error: string;
  error_description: string;
};

declare class OAuthError extends Error {
  readonly oauthError: ErrorObject;
  constructor(errorObject: ErrorObject, fileName?: string, lineNumber?: number);
}

function OAuthError(
  errorObject: ErrorObject,
  fileName?: string,
  lineNumber?: number,
): OAuthError {
  const message = `OAuthError: ${errorObject.error} ${errorObject.error_description}`;

  // @ts-ignore
  const oauthErrorInstance: OAuthError = new Error(
    message,
    // @ts-ignore
    fileName,
    lineNumber,
  );

  // @ts-ignore
  oauthErrorInstance.oauthError = errorObject as ErrorObject;
  Object.setPrototypeOf(oauthErrorInstance, Object.getPrototypeOf(this));
  if (Error.captureStackTrace) {
    Error.captureStackTrace(oauthErrorInstance, OAuthError);
  }

  return oauthErrorInstance;
}

OAuthError.prototype = Object.create(Error.prototype, {
  constructor: {
    value: Error,
    enumerable: false,
    writable: true,
    configurable: true,
  },
});

if (Object.setPrototypeOf) {
  Object.setPrototypeOf(OAuthError, Error);
} else {
  OAuthError.__proto__ = Error;
}

export default OAuthError;
