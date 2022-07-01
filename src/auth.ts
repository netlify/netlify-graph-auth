import OAuthError from './oauthError';
import {hasLocalStorage, InMemoryStorage, LocalStorage} from './storage';
import URI from './uri';
import PKCE from './pkce';
import {findMissingAuthServices} from './helpers';

import type {Storage} from './storage';

type Timer = ReturnType<typeof setTimeout>;

export type NetlifyGraphAuthStaticService =
  | 'adroll'
  | 'asana'
  | 'box'
  | 'contentful'
  | 'dev-to'
  | 'dribbble'
  | 'dropbox'
  | 'eggheadio'
  | 'eventil'
  | 'facebook'
  | 'firebase'
  | 'github'
  | 'gmail'
  | 'google'
  | 'google-ads'
  | 'google-analytics'
  | 'google-calendar'
  | 'google-compute'
  | 'google-docs'
  | 'google-search-console'
  | 'google-translate'
  | 'hubspot'
  | 'intercom'
  | 'mailchimp'
  | 'meetup'
  | 'netlify'
  | 'product-hunt'
  | 'quickbooks'
  | 'salesforce'
  | 'slack'
  | 'spotify'
  | 'stripe'
  | 'trello'
  | 'twilio'
  | 'twitch-tv'
  | 'twitter'
  | 'ynab'
  | 'youtube'
  | 'zeit'
  | 'zendesk';

type StaticService = {type: 'service'; service: NetlifyGraphAuthStaticService};
type ServiceByGQLField = {type: 'gqlField'; graphQLField: string};
type Service = StaticService | ServiceByGQLField;

export type NetlifyGraphAuthService =
  | NetlifyGraphAuthStaticService
  | {service: NetlifyGraphAuthStaticService}
  | {graphQLField: string};

type CommunicationMode = 'post_message' | 'redirect';

export type Opts = {
  graphOrigin?: string;
  siteId: string;
  oauthFinishOrigin?: string;
  oauthFinishPath?: string;
  saveAuthToStorage?: boolean;
  storage?: Storage;
  communicationMode?: CommunicationMode;
  graphqlUrl?: string | undefined | null;
};

export type LogoutResult = {
  result: 'success' | 'failure';
  errors?: Array<any>;
};

type Token = {
  accessToken: string;
  expireDate: number;
  refreshToken?: string | undefined | null;
};

export type ServiceStatus = {
  isLoggedIn: boolean;
};

export type LoggedInServices = {
  [service: string]: {
    serviceEnum: string;
    foreignUserIds: Array<string>;
    usedTestFlow: boolean;
  };
};

export type ServiceInfo = {
  serviceEnum: string;
  friendlyServiceName: string;
  supportsTestFlow: boolean;
};

export type ServicesList = Array<ServiceInfo>;

export type ServicesStatus = {
  string?: ServiceStatus;
};

export type AuthResponse = {
  token: Token;
  service?: Service;
  foreignUserId?: string;
};

function getService(arg: NetlifyGraphAuthService): Service | undefined {
  if (typeof arg === 'string') {
    return {type: 'service', service: arg as NetlifyGraphAuthStaticService};
  } else {
    if ('graphQLField' in arg) {
      return {type: 'gqlField', graphQLField: arg.graphQLField};
    } else if ('service' in arg) {
      return {type: 'service', service: arg.service};
    }
  }
}

function serializeService(arg: Service): string {
  const value = arg.type === 'service' ? arg.service : arg.graphQLField;
  return arg.type + ':' + value;
}

type StateParam = string;

const POLL_INTERVAL = 35;

function friendlyServiceName(service: Service): string {
  if (service.type === 'service') {
    switch (service.service) {
      case 'adroll':
        return 'Adroll';
      case 'asana':
        return 'Asana';
      case 'box':
        return 'Box';
      case 'dev-to':
        return 'Dev.to';
      case 'dribbble':
        return 'Dribbble';
      case 'dropbox':
        return 'Dropbox';
      case 'contentful':
        return 'Contentful';
      case 'eggheadio':
        return 'Egghead.io';
      case 'eventil':
        return 'Eventil';
      case 'facebook':
        return 'Facebook';
      case 'firebase':
        return 'Firebase';
      case 'github':
        return 'GitHub';
      case 'gmail':
        return 'Gmail';
      case 'google':
        return 'Google';
      case 'google-ads':
        return 'Google Ads';
      case 'google-analytics':
        return 'Google Analytics';
      case 'google-calendar':
        return 'Google Calendar';
      case 'google-compute':
        return 'Google Compute';
      case 'google-docs':
        return 'Google Docs';
      case 'google-search-console':
        return 'Google Search Console';
      case 'google-translate':
        return 'Google Translate';
      case 'hubspot':
        return 'Hubspot';
      case 'intercom':
        return 'Intercom';
      case 'mailchimp':
        return 'Mailchimp';
      case 'meetup':
        return 'Meetup';
      case 'netlify':
        return 'Netlify';
      case 'product-hunt':
        return 'Product Hunt';
      case 'quickbooks':
        return 'QuickBooks';
      case 'salesforce':
        return 'Salesforce';
      case 'slack':
        return 'Slack';
      case 'spotify':
        return 'Spotify';
      case 'stripe':
        return 'Stripe';
      case 'trello':
        return 'Trello';
      case 'twilio':
        return 'Twilio';
      case 'twitter':
        return 'Twitter';
      case 'twitch-tv':
        return 'Twitch';
      case 'ynab':
        return 'You Need a Budget';
      case 'youtube':
        return 'YouTube';
      case 'zeit':
        return 'Vercel';
      case 'zendesk':
        return 'Zendesk';
      default:
        return service.service;
    }
  } else {
    return service.graphQLField;
  }
}

function camelCase(s) {
  return s.replace(/-./g, (x) => x[1].toUpperCase());
}

function getOAuthURLSegment(service: Service) {
  if (service.type === 'service') {
    return service.service;
  } else {
    switch (service.graphQLField) {
      case 'gitHub':
        return 'github';
      case 'youTube':
        return 'youtube';
      case 'facebookBusiness':
        return 'facebook';
      case 'devTo':
        return 'dev-to';
      case 'googleAds':
        return 'google-ads';
      case 'googleAnalytics':
        return 'google-analytics';
      case 'googleCalendar':
        return 'google-calendar';
      case 'googleCompute':
        return 'google-compute';
      case 'googleDocs':
        return 'google-docs';
      case 'googleSearchConsole':
        return 'google-search-console';
      case 'googleTranslate':
        return 'google-translate';
      case 'productHunt':
        return 'product-hunt';
      case 'twitchTv':
        return 'twitch-tv';
      default:
        return service.graphQLField;
    }
  }
}

function getWindowOpts(): Object {
  const windowWidth = Math.min(800, Math.floor(window.outerWidth * 0.8));
  const windowHeight = Math.min(630, Math.floor(window.outerHeight * 0.5));
  const windowArea = {
    width: windowWidth,
    height: windowHeight,
    left: Math.round(window.screenX + (window.outerWidth - windowWidth) / 2),
    top: Math.round(window.screenY + (window.outerHeight - windowHeight) / 8),
  };

  // TODO: figure out how to show the toolbar icons in the window for password managers
  return {
    width: windowArea.width,
    height: windowArea.height,
    left: windowArea.left,
    top: windowArea.top,
    toolbar: 0,
    scrollbars: 1,
    status: 1,
    resizable: 1,
    menuBar: 0,
  };
}

function createAuthWindow({
  url,
  service,
}: {
  url?: string | undefined;
  service: Service;
}): Window | null {
  const windowOpts = getWindowOpts();
  const w = window.open(
    url || '',
    // A unique name prevents orphaned popups from stealing our window.open
    `${getOAuthURLSegment(service)}_${Math.random()}`.replace('.', ''),
    Object.keys(windowOpts)
      .map((k) => `${k}=${windowOpts[k]}`)
      .join(','),
  );

  if (!url && w && w.document) {
    try {
      w.document.title = `Log in with ${friendlyServiceName(service)}`;
      w.document.body.innerHTML = `<div style="display:flex;justify-content:center;align-items:center;height:100vh;width:100vw%"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100" preserveAspectRatio="xMidYMid" width="48px" height="48px" style="background: none;"><circle cx="50" cy="50" fill="none" stroke="#3cc7b6" stroke-width="8" r="24" stroke-dasharray="112 40" transform="rotate(138.553 50 50)"><animateTransform attributeName="transform" type="rotate" calcMode="linear" values="0 50 50;360 50 50" keyTimes="0;1" dur="1s" begin="0s" repeatCount="indefinite"></animateTransform></circle></svg></div>`;
    } catch (e) {}
  }

  return w;
}

// Cycles path through URL.origin to ensure that it's the same format we'll
// see in the auth window's location
function normalizeRedirectOrigin(origin: string): string {
  return URI.parse(origin).origin;
}

// Cycles path through URL.pathname to ensure that it's the same format we'll
// see in the auth window's location
function normalizeRedirectPath(path: string): string {
  return path === '/' ? '' : path;
}

const loggedInQuery = `
query LoggedInQuery {
  me {
    serviceMetadata {
      loggedInServices {
        id
        friendlyServiceName
        graphQLField
        foreignUserId
        usedTestFlow
      }
    }
  }
}
`;

const allServicesQuery = `
query AllServicesQuery {
  oneGraph {
    services(filter: {supportsOauthLogin: true}) {
      id
      friendlyServiceName
      graphQLField
      supportsTestFlow
    }
  }
}
`;

function getServiceEnum(service: string): string {
  return service.toUpperCase().replace(/-/g, '_');
}

function fromServiceEnum(serviceEnum: string): string {
  return serviceEnum.toLowerCase().replace(/_/g, '-');
}

function getIsLoggedIn(
  queryResult: Record<string, any>,
  service: Service,
  foreignUserId?: string | null | undefined,
): boolean {
  const loggedInServices =
    queryResult?.data?.me?.serviceMetadata?.loggedInServices || [];
  return !!loggedInServices.find((serviceInfo) => {
    if (service.type === 'service') {
      const serviceEnum = getServiceEnum(service.service);

      return (
        serviceInfo.service === serviceEnum &&
        (!foreignUserId || foreignUserId === serviceInfo.foreignUserId)
      );
    } else {
      return (
        serviceInfo.graphQLField === service.graphQLField &&
        (!foreignUserId || foreignUserId === serviceInfo.foreignUserId)
      );
    }
  });
}

function getServiceErrors(errors: {path: string[]}[], service: string) {
  return errors.filter((error) => error.path && error.path.includes(service));
}

const logoutMutation = `mutation SignOutServicesMutation(
  $servicesGraphQLFields: [String!]
  $services: [OneGraphServiceEnum!]
) {
  signoutServices(data: {
    $services: $services
    $servicesGraphQLFields: $servicesGraphQLFields
   }) {
    me {
      serviceMetadata {
        loggedInServices {
          id
          graphQLField
          friendlyServiceName
          foreignUserId
        }
      }
    }
  }
}`;

const logoutUserMutation = `mutation SignOutServicesMutation(
  $service: OneGraphServiceEnum
  $graphQLField: String
  $foreignUserId: String!
) {
  signoutServiceUser(
    input: {
      service: $service
      graphQLField: $graphQLField
      foreignUserId: $foreignUserId
    }
  ) {
    me {
      serviceMetadata {
        loggedInServices {
          service
          foreignUserId
        }
      }
    }
  }
}`;

async function fetchQuery(
  fetchUrl: string,
  query: string,
  variables: Record<string, any>,
  token?: Token | null,
): Promise<Record<string, any>> {
  const headers: {[key: string]: string} = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (token) {
    headers.Authorization = `Bearer ${token.accessToken}`;
  }
  const response = await fetch(fetchUrl, {
    method: 'POST',
    headers: headers,
    body: JSON.stringify({query, variables}),
  });
  return await response.json();
}

async function exchangeCode(
  graphOrigin: string,
  siteId: string,
  redirectOrigin: string,
  redirectPath: string,
  code: string,
  token: Token | null,
  verifier: string,
): Promise<Object> {
  const redirectUri = redirectOrigin + redirectPath;
  const url = URI.make({
    origin: graphOrigin,
    path: '/oauth/code',
    query: {
      app_id: siteId,
      redirect_uri: redirectUri,
      code,
      code_verifier: verifier,
    },
  });
  const headers: {[key: string]: string} = {
    'Content-Type': 'application/json',
    Accept: 'application/json',
  };
  if (token) {
    headers.Authorization = `Bearer ${token.accessToken}`;
  }
  const response = await fetch(URI.toString(url), {
    method: 'POST',
    headers,
  });
  return await response.json();
}

type ExchangeRefreshTokenErrorResponse = {
  error: string;
  error_description: string;
};

type ExchangeRefreshTokenSuccessResponse = {
  access_token: string;
  refresh_token: string;
  expires_in: number;
  service: string;
  service_graphql_field: string;
  foreign_user_id: string | undefined;
};

type ExchangeRefreshTokenResponse =
  | ExchangeRefreshTokenErrorResponse
  | ExchangeRefreshTokenSuccessResponse;

async function exchangeRefreshToken(
  graphOrigin: string,
  siteId: string,
  refreshToken: string,
): Promise<ExchangeRefreshTokenResponse> {
  const url = URI.make({
    origin: graphOrigin,
    path: '/oauth/token',
    query: {
      app_id: siteId,
    },
  });
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    accept: 'application/json',
  };
  const response = await fetch(URI.toString(url), {
    method: 'POST',
    headers,
    body: URI.queryToString({
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
    }),
  });
  return await response.json();
}

function byteArrayToString(byteArray) {
  return byteArray.reduce(
    (acc: string, byte: number) => acc + (byte & 0xff).toString(16).slice(-2),
    '',
  );
}

function makeStateParam(): StateParam {
  return byteArrayToString(window.crypto.getRandomValues(new Uint8Array(32)));
}

function isExpired(token: Token): boolean {
  return token.expireDate < Date.now();
}

function tokenFromStorage(storage: Storage, siteId: string): Token | null {
  const v = storage.getItem(siteId);
  if (v) {
    const possibleToken = JSON.parse(v);
    if (
      typeof possibleToken.accessToken === 'string' &&
      typeof possibleToken.expireDate === 'number' &&
      !isExpired(possibleToken)
    ) {
      return possibleToken;
    }
  }
  return null;
}

const DEFAULT_GRAPH_ORIGIN = 'https://serve.onegraph.com';

type _makeAuthUrlInput = {
  scopes: Array<string> | undefined;
  service: Service;
  stateParam: string;
  useTestFlow: boolean | undefined;
  verifier: string;
};

export class NetlifyGraphAuth {
  _authWindows: {string?: Window | null} = {};
  _intervalIds: {string?: Timer} = {};
  _messageListeners: {string?: any} = {};
  _fetchUrl: string;
  _redirectOrigin: string;
  _redirectPath: string;
  _accessToken: Token | null = null;
  graphOrigin: string;
  siteId: string;
  _storageKey: string;
  _storage: Storage;
  _communicationMode: CommunicationMode;

  constructor(opts: Opts) {
    const {siteId, oauthFinishOrigin, oauthFinishPath} = opts;
    this.graphOrigin = opts.graphOrigin || DEFAULT_GRAPH_ORIGIN;
    this.siteId = siteId;
    const windowUri = URI.parse(window.location.toString());
    this._redirectOrigin = normalizeRedirectOrigin(
      oauthFinishOrigin || windowUri.origin,
    );
    if (this._redirectOrigin !== windowUri.origin) {
      console.warn('oauthFinishOrigin does not match window.location.origin');
    }
    this._redirectPath = normalizeRedirectPath(
      oauthFinishPath || windowUri.path,
    );

    const fetchUrl = URI.make({
      origin: opts.graphOrigin || DEFAULT_GRAPH_ORIGIN,
      path: '/graphql',
      query: {app_id: siteId},
    });
    this._fetchUrl = opts.graphqlUrl || URI.toString(fetchUrl);
    this._storage =
      opts.storage ||
      (hasLocalStorage() ? new LocalStorage() : new InMemoryStorage());
    this._storageKey = this.siteId;
    this._accessToken = tokenFromStorage(this._storage, this._storageKey);
    this._communicationMode = opts.communicationMode || 'post_message';
  }

  _clearInterval: (service: string) => void = (service: string) => {
    const intervalId = this._intervalIds[service];
    // @ts-ignore: Some nodejs vs browser type nonsense
    clearInterval(intervalId);
    delete this._intervalIds[service];
  };

  _clearMessageListener: (service: string) => void = (service: string) => {
    window.removeEventListener(
      'message',
      this._messageListeners[service],
      false,
    );
    delete this._messageListeners[service];
  };

  closeAuthWindow: (service: string) => void = (service: string) => {
    const w = this._authWindows[service];
    w && w.close();
    delete this._authWindows[service];
  };

  cleanup: (service: string, keepWindowOpen?: boolean) => void = (
    service: string,
    keepWindowOpen?: boolean,
  ) => {
    this._clearInterval(service);
    this._clearMessageListener(service);
    if (!keepWindowOpen) {
      this.closeAuthWindow(service);
    }
  };

  accessToken: () => Token | null = (): Token | null => this._accessToken;

  tokenExpireDate: () => Date | null = (): Date | null => {
    if (!this._accessToken) {
      return null;
    }
    return new Date(this._accessToken.expireDate);
  };

  tokenExpiresSecondsFromNow: () => number | null = (): number | null => {
    const expireDate = this.tokenExpireDate();
    if (!expireDate) {
      return null;
    }
    const milliseconds = expireDate.getTime() - new Date().getTime();
    if (milliseconds < 0) {
      return null;
    }

    return Math.floor(milliseconds / 1000);
  };

  refreshToken: (refreshToken: string) => Promise<Token | null> = async (
    refreshToken: string,
  ): Promise<Token | null> => {
    const baseResponse = await exchangeRefreshToken(
      this.graphOrigin,
      this.siteId,
      refreshToken,
    );
    if (!baseResponse) {
      throw new OAuthError({
        error: 'invalid_grant',
        error_description: 'Invalid response refreshing token.',
      });
    }
    const errorResponse = baseResponse as ExchangeRefreshTokenErrorResponse;
    if (errorResponse.error) {
      throw new OAuthError({
        error: errorResponse.error,
        error_description: errorResponse.error_description,
      });
    }
    const successResponse = baseResponse as ExchangeRefreshTokenSuccessResponse;
    if (
      !successResponse.access_token ||
      !successResponse.expires_in ||
      !successResponse.refresh_token
    ) {
      throw new OAuthError({
        error: 'invalid_grant',
        error_description:
          'Inavlid response from server while refreshing token.',
      });
    } else {
      const token: Token = {
        accessToken: successResponse.access_token,
        expireDate: Date.now() + successResponse.expires_in * 1000,
        refreshToken: successResponse.refresh_token,
      };

      this.setToken(token);

      return token;
    }
  };

  authHeaders: () => {Authorization?: string} = (): {
    Authorization?: string;
  } => {
    if (this._accessToken) {
      return {Authorization: `Bearer ${this._accessToken.accessToken}`};
    } else {
      return {};
    }
  };

  friendlyServiceName(service: Service): string {
    return friendlyServiceName(service);
  }

  _makeAuthUrl: (opts: _makeAuthUrlInput) => Promise<string> = async (
    opts: _makeAuthUrlInput,
  ): Promise<string> => {
    const {service, verifier, stateParam, scopes, useTestFlow} = opts;
    const challenge = await PKCE.codeChallengeOfVerifier(verifier);
    const query: any = {
      service: getOAuthURLSegment(service),
      app_id: this.siteId,
      response_type: 'code',
      redirect_origin: this._redirectOrigin,
      redirect_path: this._redirectPath,
      communication_mode: this._communicationMode,
      code_challenge: challenge.challenge,
      code_challenge_method: challenge.method,
      state: stateParam,
      ...(scopes ? {scopes: scopes.join(',')} : {}),
    };
    if (useTestFlow) {
      query.test = 'true';
    }
    const authUrl = URI.make({
      origin: this.graphOrigin,
      path: '/oauth/start',
      query,
    });
    return URI.toString(authUrl);
  };

  setToken: (token: Token) => void = (token: Token): void => {
    this._accessToken = token;
    const {refreshToken, ...storableToken} = token;
    this._storage.setItem(this._storageKey, JSON.stringify(storableToken));
  };

  _waitForAuthFinishPostMessage: (
    service: Service,
    stateParam: StateParam,
    verifier: string,
  ) => Promise<AuthResponse> = (
    service: Service,
    stateParam: StateParam,
    verifier: string,
  ): Promise<AuthResponse> => {
    const serviceString = serializeService(service);
    return new Promise((resolve, reject) => {
      function parseEvent(event) {
        try {
          return JSON.parse(event.data);
        } catch (e) {
          return {};
        }
      }
      const listener = (event) => {
        const message = parseEvent(event);
        if (message && message.version <= 2) {
          const {state} = message;
          if (state !== stateParam) {
            console.warn('Invalid state param, skipping event');
          } else {
            const {error, error_description, code} = message;
            if (!code) {
              reject(
                new OAuthError({
                  error: error || 'invalid_grant',
                  error_description: error_description || 'Missing code',
                }),
              );
            } else {
              exchangeCode(
                this.graphOrigin,
                this.siteId,
                this._redirectOrigin,
                this._redirectPath,
                code,
                this._accessToken,
                verifier,
              )
                .then((baseResponse) => {
                  const errorResponse =
                    baseResponse as ExchangeRefreshTokenErrorResponse;

                  const successResponse =
                    baseResponse as ExchangeRefreshTokenSuccessResponse;

                  if (errorResponse.error) {
                    reject(new OAuthError(errorResponse));
                  } else if (
                    typeof successResponse.access_token === 'string' &&
                    typeof successResponse.expires_in === 'number'
                  ) {
                    const token: Token = {
                      accessToken: successResponse.access_token,
                      expireDate:
                        Date.now() + successResponse.expires_in * 1000,
                      refreshToken: successResponse.refresh_token,
                    };
                    this.setToken(token);
                    resolve({
                      token,
                      service: {
                        type: 'gqlField',
                        graphQLField: successResponse.service_graphql_field,
                      },
                      foreignUserId: successResponse.foreign_user_id,
                    });
                  } else {
                    reject(new Error('Unexpected result from server'));
                  }
                })
                .catch((e) => reject(e));
            }
          }
        }
      };
      this._messageListeners[serviceString] = listener;
      window.addEventListener('message', listener, false);
    });
  };

  _waitForAuthFinishRedirect: (
    service: Service,
    stateParam: StateParam,
    verifier: string,
  ) => Promise<AuthResponse> = (
    service: Service,
    stateParam: StateParam,
    verifier: string,
  ): Promise<AuthResponse> => {
    return new Promise((resolve, reject) => {
      const serviceString = serializeService(service);
      this._intervalIds[serviceString] = setInterval(() => {
        try {
          const authWindow = this._authWindows[serviceString];
          const authUri =
            authWindow && URI.safeParse(authWindow.location.toString());
          if (authUri && authUri.origin === this._redirectOrigin) {
            const params = authUri.query;
            if (stateParam !== params.state) {
              reject(
                new OAuthError({
                  error: 'invalid_request',
                  error_description: 'The state param does not match',
                }),
              );
            } else {
              const code = params.code;
              if (!code) {
                reject(
                  new OAuthError({
                    error: 'invalid_grant',
                    error_description: 'Missing code',
                  }),
                );
              } else {
                exchangeCode(
                  this.graphOrigin,
                  this.siteId,
                  this._redirectOrigin,
                  this._redirectPath,
                  code,
                  this._accessToken,
                  verifier,
                )
                  .then((baseResponse) => {
                    const errorResponse =
                      baseResponse as ExchangeRefreshTokenErrorResponse;
                    const successResponse =
                      baseResponse as ExchangeRefreshTokenSuccessResponse;

                    if (errorResponse.error) {
                      reject(new OAuthError(errorResponse));
                    } else if (
                      typeof successResponse.access_token === 'string' &&
                      typeof successResponse.expires_in === 'number'
                    ) {
                      const token: Token = {
                        accessToken: successResponse.access_token,
                        expireDate:
                          Date.now() + successResponse.expires_in * 1000,
                        refreshToken: successResponse.refresh_token,
                      };
                      this.setToken(token);
                      resolve({token});
                    } else {
                      reject(new Error('Unexpected result from server'));
                    }
                  })
                  .catch((e) => reject(e));
              }
            }
          }
        } catch (e) {
          if (e instanceof window.DOMException) {
            // do nothing--probably on the service's or onegraph's domain
          } else {
            console.error(
              'unexpected error waiting for auth to finish for ' + service,
              e,
            );
            reject(e);
          }
        }
      }, POLL_INTERVAL);
    });
  };

  /**
   * @throws {OAuthError}
   */
  login: (
    service: NetlifyGraphAuthService,
    scopes?: Array<string> | undefined,
    useTestFlow?: boolean,
  ) => Promise<AuthResponse> = async (
    serviceInput: NetlifyGraphAuthService,
    scopes: Array<string> | undefined,
    useTestFlow?: boolean,
  ): Promise<AuthResponse> => {
    const service = getService(serviceInput);
    if (!service) {
      throw new OAuthError({
        error: 'invalid_request',
        error_description:
          "Missing required argument. Provide service as first argument to login (e.g. `auth.login('stripe')`).",
      });
    }
    const serviceString = serializeService(service);
    this.cleanup(serviceString);
    const stateParam = makeStateParam();
    const verifier = PKCE.generateVerifier();
    // Create an auth window without a URL initially so that browser associates
    // window.open with the event (usually a click) that triggered login.
    // If we waited until _makeAuthUrl's promise resolved, we might trigger
    // a popup blocker
    const authWindow = createAuthWindow({service});
    this._authWindows[serviceString] = authWindow;
    const authFinish =
      this._communicationMode === 'redirect'
        ? this._waitForAuthFinishRedirect
        : this._waitForAuthFinishPostMessage;
    const windowUrl = this._makeAuthUrl({
      service,
      verifier,
      stateParam,
      scopes,
      useTestFlow,
    });
    try {
      const url = await windowUrl;
      try {
        // @ts-ignore: we catch this in the next line
        authWindow.location.href = url;
      } catch (e) {
        throw new OAuthError({
          error: 'invalid_response',
          error_description: 'Popup window was closed or blocked',
        });
      }
      const result_3 = await authFinish(service, stateParam, verifier);
      this.cleanup(serviceString);
      return result_3;
    } catch (e_1) {
      this.cleanup(serviceString, true);
      throw e_1;
    }
  };

  isLoggedIn: (
    args: NetlifyGraphAuthService | {foreignUserId?: string; service: string},
  ) => Promise<boolean> = async (
    args: NetlifyGraphAuthService | {foreignUserId?: string; service: string},
  ): Promise<boolean> => {
    const accessToken = this._accessToken;
    if (accessToken) {
      const serviceInput =
        typeof args === 'string'
          ? args
          : 'service' in args
          ? (args.service as NetlifyGraphAuthStaticService)
          : args;
      const service = getService(serviceInput);

      if (!service) {
        throw new Error(
          "Missing required argument. Provide service as first argument to isLoggedIn (e.g. `auth.isLoggedIn('stripe')`).",
        );
      }
      const foreignUserId =
        typeof args === 'string'
          ? null
          : 'foreignUserId' in args
          ? args.foreignUserId
          : null;
      const result = await fetchQuery(
        this._fetchUrl,
        loggedInQuery,
        {},
        accessToken,
      );
      return getIsLoggedIn(result, service, foreignUserId);
    } else {
      return Promise.resolve(false);
    }
  };

  allServices: () => Promise<ServicesList> =
    async (): Promise<ServicesList> => {
      const result = await fetchQuery(
        this._fetchUrl,
        allServicesQuery,
        {},
        null,
      );
      return result.data.oneGraph.services.map((serviceInfo) => ({
        serviceEnum: serviceInfo.service,
        service: fromServiceEnum(serviceInfo.service),
        friendlyServiceName: serviceInfo.friendlyServiceName,
        supportsTestFlow: serviceInfo.supportsTestFlow,
      }));
    };

  loggedInServices: () => Promise<LoggedInServices> =
    async (): Promise<LoggedInServices> => {
      const accessToken = this._accessToken;
      if (accessToken) {
        const result = await fetchQuery(
          this._fetchUrl,
          loggedInQuery,
          {},
          accessToken,
        );
        const loggedInServices =
          result?.data?.me?.serviceMetadata?.loggedInServices || [];
        return loggedInServices.reduce((acc, serviceInfo) => {
          const serviceKey = fromServiceEnum(serviceInfo.service);
          const loggedInInfo = acc[serviceKey] || {
            serviceEnum: serviceInfo.service,
            foreignUserIds: [],
          };
          acc[serviceKey] = {
            ...loggedInInfo,
            usedTestFlow: serviceInfo.usedTestFlow,
            foreignUserIds: [
              serviceInfo.foreignUserId,
              ...loggedInInfo.foreignUserIds,
            ],
          };
          return acc;
        }, {});
      } else {
        return Promise.resolve({});
      }
    };

  logout: (
    service: NetlifyGraphAuthService,
    foreignUserId?: string,
  ) => Promise<LogoutResult> = async (
    serviceInput: NetlifyGraphAuthService,
    foreignUserId?: string,
  ): Promise<LogoutResult> => {
    const service = getService(serviceInput);
    if (!service) {
      throw new Error(
        "Missing required argument. Provide service as first argument to logout (e.g. `auth.logout('stripe')`).",
      );
    }
    const serviceString = serializeService(service);
    this.cleanup(serviceString);
    const accessToken = this._accessToken;
    if (accessToken) {
      const signoutPromise = foreignUserId
        ? fetchQuery(
            this._fetchUrl,
            logoutUserMutation,
            Object.assign(
              {
                foreignUserId: foreignUserId,
              },
              service.type === 'service'
                ? {service: service.service}
                : {graphQLField: service.graphQLField},
            ),
            accessToken,
          )
        : fetchQuery(
            this._fetchUrl,
            logoutMutation,
            service.type === 'service'
              ? {
                  services: [getServiceEnum(service.service)],
                }
              : {servicesGraphQLFields: service.graphQLField},
            accessToken,
          );
      const result = await signoutPromise;
      if (
        result.errors?.length &&
        getServiceErrors(
          result.errors,
          service.type === 'service' ? service.service : service.graphQLField,
        ).length
      ) {
        return {result: 'failure', errors: result.errors};
      } else {
        const loggedIn = getIsLoggedIn(
          {data: result.signoutServices},
          service,
          foreignUserId,
        );
        return {result: loggedIn ? 'failure' : 'success'};
      }
    } else {
      return Promise.resolve({result: 'failure'});
    }
  };

  destroy: () => void = () => {
    Object.keys(this._intervalIds).forEach((key: string) => this.cleanup(key));
    Object.keys(this._authWindows).forEach((key: string) => this.cleanup(key));
    this._storage.removeItem(this._storageKey);
    this._accessToken = null;
  };

  findMissingAuthServices: any = findMissingAuthServices;
}

export default NetlifyGraphAuth;
