var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// .wrangler/tmp/bundle-fkHa3b/checked-fetch.js
function checkURL(request, init) {
  const url = request instanceof URL ? request : new URL(
    (typeof request === "string" ? new Request(request, init) : request).url
  );
  if (url.port && url.port !== "443" && url.protocol === "https:") {
    if (!urls.has(url.toString())) {
      urls.add(url.toString());
      console.warn(
        `WARNING: known issue with \`fetch()\` requests to custom HTTPS ports in published Workers:
 - ${url.toString()} - the custom port will be ignored when the Worker is published using the \`wrangler deploy\` command.
`
      );
    }
  }
}
var urls;
var init_checked_fetch = __esm({
  ".wrangler/tmp/bundle-fkHa3b/checked-fetch.js"() {
    urls = /* @__PURE__ */ new Set();
    __name(checkURL, "checkURL");
    globalThis.fetch = new Proxy(globalThis.fetch, {
      apply(target, thisArg, argArray) {
        const [request, init] = argArray;
        checkURL(request, init);
        return Reflect.apply(target, thisArg, argArray);
      }
    });
  }
});

// wrangler-modules-watch:wrangler:modules-watch
var init_wrangler_modules_watch = __esm({
  "wrangler-modules-watch:wrangler:modules-watch"() {
    init_checked_fetch();
    init_modules_watch_stub();
  }
});

// node_modules/wrangler/templates/modules-watch-stub.js
var init_modules_watch_stub = __esm({
  "node_modules/wrangler/templates/modules-watch-stub.js"() {
    init_wrangler_modules_watch();
  }
});

// src/utils/hipaa-security.ts
var hipaa_security_exports = {};
__export(hipaa_security_exports, {
  HIPAA_LOCKOUT_POLICY: () => HIPAA_LOCKOUT_POLICY,
  HIPAA_PASSWORD_POLICY: () => HIPAA_PASSWORD_POLICY,
  HIPAA_SESSION_CONFIG: () => HIPAA_SESSION_CONFIG,
  calculateDocumentChecksum: () => calculateDocumentChecksum,
  calculateLockoutEnd: () => calculateLockoutEnd,
  createAuditLog: () => createAuditLog,
  generateMFABackupCodes: () => generateMFABackupCodes,
  generateMFASecret: () => generateMFASecret,
  generateSecureToken: () => generateSecureToken,
  getSessionTimeoutWarning: () => getSessionTimeoutWarning,
  isAccountLocked: () => isAccountLocked,
  isSessionExpired: () => isSessionExpired,
  sanitizeAuditDetails: () => sanitizeAuditDetails,
  shouldResetFailedAttempts: () => shouldResetFailedAttempts,
  validatePassword: () => validatePassword,
  verifyDocumentIntegrity: () => verifyDocumentIntegrity,
  verifyTOTP: () => verifyTOTP
});
import { createHmac, randomBytes } from "node:crypto";
function validatePassword(password, userInfo, policy = HIPAA_PASSWORD_POLICY) {
  const errors = [];
  if (password.length < policy.minLength) {
    errors.push(`Password must be at least ${policy.minLength} characters long`);
  }
  if (policy.requireUppercase && !/[A-Z]/.test(password)) {
    errors.push("Password must contain at least one uppercase letter");
  }
  if (policy.requireLowercase && !/[a-z]/.test(password)) {
    errors.push("Password must contain at least one lowercase letter");
  }
  if (policy.requireNumbers && !/\d/.test(password)) {
    errors.push("Password must contain at least one number");
  }
  if (policy.requireSpecialChars && !/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) {
    errors.push("Password must contain at least one special character");
  }
  if (policy.preventCommonPasswords) {
    const lowerPassword = password.toLowerCase();
    if (COMMON_PASSWORDS.some((common) => lowerPassword.includes(common))) {
      errors.push("Password is too common or easily guessable");
    }
  }
  if (policy.preventUserInfo && userInfo) {
    const lowerPassword = password.toLowerCase();
    if (userInfo.name && lowerPassword.includes(userInfo.name.toLowerCase())) {
      errors.push("Password cannot contain your name");
    }
    if (userInfo.email) {
      const emailPrefix = userInfo.email.split("@")[0].toLowerCase();
      if (lowerPassword.includes(emailPrefix)) {
        errors.push("Password cannot contain your email address");
      }
    }
  }
  const strength = calculatePasswordStrength(password);
  return {
    valid: errors.length === 0,
    errors,
    strength
  };
}
function calculatePasswordStrength(password) {
  let score = 0;
  if (password.length >= 8) score++;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password)) score++;
  if (/[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password) && password.length >= 14) score++;
  if (score <= 3) return "weak";
  if (score <= 5) return "medium";
  if (score <= 7) return "strong";
  return "very-strong";
}
function generateSecureToken(length = 32) {
  return randomBytes(length).toString("hex");
}
function generateMFASecret() {
  return randomBytes(20).toString("base64").replace(/[^A-Z0-9]/gi, "").substring(0, 32);
}
function generateMFABackupCodes(count = 10) {
  const codes = [];
  for (let i = 0; i < count; i++) {
    const code = randomBytes(4).toString("hex").toUpperCase();
    codes.push(`${code.substring(0, 4)}-${code.substring(4, 8)}`);
  }
  return codes;
}
function verifyTOTP(secret, token) {
  const window = 1;
  const timeStep = 30;
  const currentTime = Math.floor(Date.now() / 1e3);
  for (let i = -window; i <= window; i++) {
    const time = currentTime + i * timeStep;
    const expectedToken = generateTOTP(secret, time);
    if (expectedToken === token) {
      return true;
    }
  }
  return false;
}
function generateTOTP(secret, time) {
  const timeHex = Math.floor(time / 30).toString(16).padStart(16, "0");
  const timeBuffer = Buffer.from(timeHex, "hex");
  const hmac = createHmac("sha1", Buffer.from(secret, "base64"));
  hmac.update(timeBuffer);
  const hash = hmac.digest();
  const offset = hash[hash.length - 1] & 15;
  const binary = (hash[offset] & 127) << 24 | (hash[offset + 1] & 255) << 16 | (hash[offset + 2] & 255) << 8 | hash[offset + 3] & 255;
  const otp = binary % 1e6;
  return otp.toString().padStart(6, "0");
}
function calculateDocumentChecksum(data) {
  return crypto.subtle.digest("SHA-256", data).then((hashBuffer) => {
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  });
}
function verifyDocumentIntegrity(data, expectedChecksum) {
  return calculateDocumentChecksum(data).then(
    (actualChecksum) => actualChecksum === expectedChecksum
  );
}
function isSessionExpired(lastActivity, sessionStart, config = HIPAA_SESSION_CONFIG) {
  const now = Date.now() / 1e3;
  const inactivitySeconds = now - lastActivity;
  const absoluteSeconds = now - sessionStart;
  const maxInactivitySeconds = config.maxInactivityMinutes * 60;
  const maxAbsoluteSeconds = config.absoluteTimeoutMinutes * 60;
  if (inactivitySeconds > maxInactivitySeconds) {
    return { expired: true, reason: "inactivity" };
  }
  if (absoluteSeconds > maxAbsoluteSeconds) {
    return { expired: true, reason: "absolute" };
  }
  return { expired: false };
}
function getSessionTimeoutWarning(lastActivity, config = HIPAA_SESSION_CONFIG) {
  const now = Date.now() / 1e3;
  const inactivitySeconds = now - lastActivity;
  const maxInactivitySeconds = config.maxInactivityMinutes * 60;
  const warningSeconds = config.warningMinutesBeforeTimeout * 60;
  const secondsRemaining = maxInactivitySeconds - inactivitySeconds;
  if (secondsRemaining <= warningSeconds && secondsRemaining > 0) {
    return { shouldWarn: true, secondsRemaining: Math.floor(secondsRemaining) };
  }
  return { shouldWarn: false };
}
function isAccountLocked(accountLockedUntil) {
  if (!accountLockedUntil) return false;
  const now = Date.now() / 1e3;
  return accountLockedUntil > now;
}
function calculateLockoutEnd(policy = HIPAA_LOCKOUT_POLICY) {
  const now = Date.now() / 1e3;
  return now + policy.lockoutDurationMinutes * 60;
}
function shouldResetFailedAttempts(lastFailedAttempt, policy = HIPAA_LOCKOUT_POLICY) {
  const now = Date.now() / 1e3;
  const timeSinceLastAttempt = now - lastFailedAttempt;
  return timeSinceLastAttempt > policy.resetAfterMinutes * 60;
}
function createAuditLog(entry) {
  return {
    ...entry,
    timestamp: Math.floor(Date.now() / 1e3)
  };
}
function sanitizeAuditDetails(details) {
  const sanitized = { ...details };
  const sensitiveKeys = ["password", "password_hash", "secret", "token", "api_key", "mfa_secret"];
  for (const key of Object.keys(sanitized)) {
    if (sensitiveKeys.some((sensitive) => key.toLowerCase().includes(sensitive))) {
      sanitized[key] = "[REDACTED]";
    }
  }
  return sanitized;
}
var HIPAA_PASSWORD_POLICY, COMMON_PASSWORDS, HIPAA_SESSION_CONFIG, HIPAA_LOCKOUT_POLICY;
var init_hipaa_security = __esm({
  "src/utils/hipaa-security.ts"() {
    init_checked_fetch();
    init_modules_watch_stub();
    HIPAA_PASSWORD_POLICY = {
      minLength: 12,
      requireUppercase: true,
      requireLowercase: true,
      requireNumbers: true,
      requireSpecialChars: true,
      preventCommonPasswords: true,
      preventUserInfo: true,
      maxAge: 90,
      preventReuse: 5
    };
    COMMON_PASSWORDS = [
      "password",
      "password123",
      "123456",
      "12345678",
      "qwerty",
      "abc123",
      "monkey",
      "1234567",
      "letmein",
      "trustno1",
      "dragon",
      "baseball",
      "iloveyou",
      "master",
      "sunshine",
      "ashley",
      "bailey",
      "passw0rd",
      "shadow",
      "123123",
      "654321",
      "superman",
      "qazwsx",
      "michael",
      "football",
      "welcome",
      "jesus",
      "ninja",
      "mustang",
      "password1"
    ];
    __name(validatePassword, "validatePassword");
    __name(calculatePasswordStrength, "calculatePasswordStrength");
    __name(generateSecureToken, "generateSecureToken");
    __name(generateMFASecret, "generateMFASecret");
    __name(generateMFABackupCodes, "generateMFABackupCodes");
    __name(verifyTOTP, "verifyTOTP");
    __name(generateTOTP, "generateTOTP");
    __name(calculateDocumentChecksum, "calculateDocumentChecksum");
    __name(verifyDocumentIntegrity, "verifyDocumentIntegrity");
    HIPAA_SESSION_CONFIG = {
      maxInactivityMinutes: 15,
      absoluteTimeoutMinutes: 480,
      warningMinutesBeforeTimeout: 2
    };
    __name(isSessionExpired, "isSessionExpired");
    __name(getSessionTimeoutWarning, "getSessionTimeoutWarning");
    HIPAA_LOCKOUT_POLICY = {
      maxFailedAttempts: 5,
      lockoutDurationMinutes: 30,
      resetAfterMinutes: 60
    };
    __name(isAccountLocked, "isAccountLocked");
    __name(calculateLockoutEnd, "calculateLockoutEnd");
    __name(shouldResetFailedAttempts, "shouldResetFailedAttempts");
    __name(createAuditLog, "createAuditLog");
    __name(sanitizeAuditDetails, "sanitizeAuditDetails");
  }
});

// .wrangler/tmp/bundle-fkHa3b/middleware-loader.entry.ts
init_checked_fetch();
init_modules_watch_stub();

// .wrangler/tmp/bundle-fkHa3b/middleware-insertion-facade.js
init_checked_fetch();
init_modules_watch_stub();

// src/worker.ts
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/index.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/hono.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/hono-base.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/compose.js
init_checked_fetch();
init_modules_watch_stub();
var compose = /* @__PURE__ */ __name((middleware, onError, onNotFound) => {
  return (context, next) => {
    let index = -1;
    return dispatch(0);
    async function dispatch(i) {
      if (i <= index) {
        throw new Error("next() called multiple times");
      }
      index = i;
      let res;
      let isError = false;
      let handler;
      if (middleware[i]) {
        handler = middleware[i][0][0];
        context.req.routeIndex = i;
      } else {
        handler = i === middleware.length && next || void 0;
      }
      if (handler) {
        try {
          res = await handler(context, () => dispatch(i + 1));
        } catch (err) {
          if (err instanceof Error && onError) {
            context.error = err;
            res = await onError(err, context);
            isError = true;
          } else {
            throw err;
          }
        }
      } else {
        if (context.finalized === false && onNotFound) {
          res = await onNotFound(context);
        }
      }
      if (res && (context.finalized === false || isError)) {
        context.res = res;
      }
      return context;
    }
    __name(dispatch, "dispatch");
  };
}, "compose");

// node_modules/hono/dist/context.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/request.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/request/constants.js
init_checked_fetch();
init_modules_watch_stub();
var GET_MATCH_RESULT = Symbol();

// node_modules/hono/dist/utils/body.js
init_checked_fetch();
init_modules_watch_stub();
var parseBody = /* @__PURE__ */ __name(async (request, options = /* @__PURE__ */ Object.create(null)) => {
  const { all = false, dot = false } = options;
  const headers = request instanceof HonoRequest ? request.raw.headers : request.headers;
  const contentType = headers.get("Content-Type");
  if (contentType?.startsWith("multipart/form-data") || contentType?.startsWith("application/x-www-form-urlencoded")) {
    return parseFormData(request, { all, dot });
  }
  return {};
}, "parseBody");
async function parseFormData(request, options) {
  const formData = await request.formData();
  if (formData) {
    return convertFormDataToBodyData(formData, options);
  }
  return {};
}
__name(parseFormData, "parseFormData");
function convertFormDataToBodyData(formData, options) {
  const form = /* @__PURE__ */ Object.create(null);
  formData.forEach((value, key) => {
    const shouldParseAllValues = options.all || key.endsWith("[]");
    if (!shouldParseAllValues) {
      form[key] = value;
    } else {
      handleParsingAllValues(form, key, value);
    }
  });
  if (options.dot) {
    Object.entries(form).forEach(([key, value]) => {
      const shouldParseDotValues = key.includes(".");
      if (shouldParseDotValues) {
        handleParsingNestedValues(form, key, value);
        delete form[key];
      }
    });
  }
  return form;
}
__name(convertFormDataToBodyData, "convertFormDataToBodyData");
var handleParsingAllValues = /* @__PURE__ */ __name((form, key, value) => {
  if (form[key] !== void 0) {
    if (Array.isArray(form[key])) {
      ;
      form[key].push(value);
    } else {
      form[key] = [form[key], value];
    }
  } else {
    if (!key.endsWith("[]")) {
      form[key] = value;
    } else {
      form[key] = [value];
    }
  }
}, "handleParsingAllValues");
var handleParsingNestedValues = /* @__PURE__ */ __name((form, key, value) => {
  let nestedForm = form;
  const keys = key.split(".");
  keys.forEach((key2, index) => {
    if (index === keys.length - 1) {
      nestedForm[key2] = value;
    } else {
      if (!nestedForm[key2] || typeof nestedForm[key2] !== "object" || Array.isArray(nestedForm[key2]) || nestedForm[key2] instanceof File) {
        nestedForm[key2] = /* @__PURE__ */ Object.create(null);
      }
      nestedForm = nestedForm[key2];
    }
  });
}, "handleParsingNestedValues");

// node_modules/hono/dist/utils/url.js
init_checked_fetch();
init_modules_watch_stub();
var splitPath = /* @__PURE__ */ __name((path) => {
  const paths = path.split("/");
  if (paths[0] === "") {
    paths.shift();
  }
  return paths;
}, "splitPath");
var splitRoutingPath = /* @__PURE__ */ __name((routePath) => {
  const { groups, path } = extractGroupsFromPath(routePath);
  const paths = splitPath(path);
  return replaceGroupMarks(paths, groups);
}, "splitRoutingPath");
var extractGroupsFromPath = /* @__PURE__ */ __name((path) => {
  const groups = [];
  path = path.replace(/\{[^}]+\}/g, (match, index) => {
    const mark = `@${index}`;
    groups.push([mark, match]);
    return mark;
  });
  return { groups, path };
}, "extractGroupsFromPath");
var replaceGroupMarks = /* @__PURE__ */ __name((paths, groups) => {
  for (let i = groups.length - 1; i >= 0; i--) {
    const [mark] = groups[i];
    for (let j = paths.length - 1; j >= 0; j--) {
      if (paths[j].includes(mark)) {
        paths[j] = paths[j].replace(mark, groups[i][1]);
        break;
      }
    }
  }
  return paths;
}, "replaceGroupMarks");
var patternCache = {};
var getPattern = /* @__PURE__ */ __name((label, next) => {
  if (label === "*") {
    return "*";
  }
  const match = label.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
  if (match) {
    const cacheKey = `${label}#${next}`;
    if (!patternCache[cacheKey]) {
      if (match[2]) {
        patternCache[cacheKey] = next && next[0] !== ":" && next[0] !== "*" ? [cacheKey, match[1], new RegExp(`^${match[2]}(?=/${next})`)] : [label, match[1], new RegExp(`^${match[2]}$`)];
      } else {
        patternCache[cacheKey] = [label, match[1], true];
      }
    }
    return patternCache[cacheKey];
  }
  return null;
}, "getPattern");
var tryDecode = /* @__PURE__ */ __name((str, decoder) => {
  try {
    return decoder(str);
  } catch {
    return str.replace(/(?:%[0-9A-Fa-f]{2})+/g, (match) => {
      try {
        return decoder(match);
      } catch {
        return match;
      }
    });
  }
}, "tryDecode");
var tryDecodeURI = /* @__PURE__ */ __name((str) => tryDecode(str, decodeURI), "tryDecodeURI");
var getPath = /* @__PURE__ */ __name((request) => {
  const url = request.url;
  const start = url.indexOf(
    "/",
    url.charCodeAt(9) === 58 ? 13 : 8
  );
  let i = start;
  for (; i < url.length; i++) {
    const charCode = url.charCodeAt(i);
    if (charCode === 37) {
      const queryIndex = url.indexOf("?", i);
      const path = url.slice(start, queryIndex === -1 ? void 0 : queryIndex);
      return tryDecodeURI(path.includes("%25") ? path.replace(/%25/g, "%2525") : path);
    } else if (charCode === 63) {
      break;
    }
  }
  return url.slice(start, i);
}, "getPath");
var getPathNoStrict = /* @__PURE__ */ __name((request) => {
  const result = getPath(request);
  return result.length > 1 && result.at(-1) === "/" ? result.slice(0, -1) : result;
}, "getPathNoStrict");
var mergePath = /* @__PURE__ */ __name((base, sub, ...rest) => {
  if (rest.length) {
    sub = mergePath(sub, ...rest);
  }
  return `${base?.[0] === "/" ? "" : "/"}${base}${sub === "/" ? "" : `${base?.at(-1) === "/" ? "" : "/"}${sub?.[0] === "/" ? sub.slice(1) : sub}`}`;
}, "mergePath");
var checkOptionalParameter = /* @__PURE__ */ __name((path) => {
  if (path.charCodeAt(path.length - 1) !== 63 || !path.includes(":")) {
    return null;
  }
  const segments = path.split("/");
  const results = [];
  let basePath = "";
  segments.forEach((segment) => {
    if (segment !== "" && !/\:/.test(segment)) {
      basePath += "/" + segment;
    } else if (/\:/.test(segment)) {
      if (/\?/.test(segment)) {
        if (results.length === 0 && basePath === "") {
          results.push("/");
        } else {
          results.push(basePath);
        }
        const optionalSegment = segment.replace("?", "");
        basePath += "/" + optionalSegment;
        results.push(basePath);
      } else {
        basePath += "/" + segment;
      }
    }
  });
  return results.filter((v, i, a) => a.indexOf(v) === i);
}, "checkOptionalParameter");
var _decodeURI = /* @__PURE__ */ __name((value) => {
  if (!/[%+]/.test(value)) {
    return value;
  }
  if (value.indexOf("+") !== -1) {
    value = value.replace(/\+/g, " ");
  }
  return value.indexOf("%") !== -1 ? tryDecode(value, decodeURIComponent_) : value;
}, "_decodeURI");
var _getQueryParam = /* @__PURE__ */ __name((url, key, multiple) => {
  let encoded;
  if (!multiple && key && !/[%+]/.test(key)) {
    let keyIndex2 = url.indexOf(`?${key}`, 8);
    if (keyIndex2 === -1) {
      keyIndex2 = url.indexOf(`&${key}`, 8);
    }
    while (keyIndex2 !== -1) {
      const trailingKeyCode = url.charCodeAt(keyIndex2 + key.length + 1);
      if (trailingKeyCode === 61) {
        const valueIndex = keyIndex2 + key.length + 2;
        const endIndex = url.indexOf("&", valueIndex);
        return _decodeURI(url.slice(valueIndex, endIndex === -1 ? void 0 : endIndex));
      } else if (trailingKeyCode == 38 || isNaN(trailingKeyCode)) {
        return "";
      }
      keyIndex2 = url.indexOf(`&${key}`, keyIndex2 + 1);
    }
    encoded = /[%+]/.test(url);
    if (!encoded) {
      return void 0;
    }
  }
  const results = {};
  encoded ??= /[%+]/.test(url);
  let keyIndex = url.indexOf("?", 8);
  while (keyIndex !== -1) {
    const nextKeyIndex = url.indexOf("&", keyIndex + 1);
    let valueIndex = url.indexOf("=", keyIndex);
    if (valueIndex > nextKeyIndex && nextKeyIndex !== -1) {
      valueIndex = -1;
    }
    let name = url.slice(
      keyIndex + 1,
      valueIndex === -1 ? nextKeyIndex === -1 ? void 0 : nextKeyIndex : valueIndex
    );
    if (encoded) {
      name = _decodeURI(name);
    }
    keyIndex = nextKeyIndex;
    if (name === "") {
      continue;
    }
    let value;
    if (valueIndex === -1) {
      value = "";
    } else {
      value = url.slice(valueIndex + 1, nextKeyIndex === -1 ? void 0 : nextKeyIndex);
      if (encoded) {
        value = _decodeURI(value);
      }
    }
    if (multiple) {
      if (!(results[name] && Array.isArray(results[name]))) {
        results[name] = [];
      }
      ;
      results[name].push(value);
    } else {
      results[name] ??= value;
    }
  }
  return key ? results[key] : results;
}, "_getQueryParam");
var getQueryParam = _getQueryParam;
var getQueryParams = /* @__PURE__ */ __name((url, key) => {
  return _getQueryParam(url, key, true);
}, "getQueryParams");
var decodeURIComponent_ = decodeURIComponent;

// node_modules/hono/dist/request.js
var tryDecodeURIComponent = /* @__PURE__ */ __name((str) => tryDecode(str, decodeURIComponent_), "tryDecodeURIComponent");
var HonoRequest = class {
  static {
    __name(this, "HonoRequest");
  }
  raw;
  #validatedData;
  #matchResult;
  routeIndex = 0;
  path;
  bodyCache = {};
  constructor(request, path = "/", matchResult = [[]]) {
    this.raw = request;
    this.path = path;
    this.#matchResult = matchResult;
    this.#validatedData = {};
  }
  param(key) {
    return key ? this.#getDecodedParam(key) : this.#getAllDecodedParams();
  }
  #getDecodedParam(key) {
    const paramKey = this.#matchResult[0][this.routeIndex][1][key];
    const param = this.#getParamValue(paramKey);
    return param ? /\%/.test(param) ? tryDecodeURIComponent(param) : param : void 0;
  }
  #getAllDecodedParams() {
    const decoded = {};
    const keys = Object.keys(this.#matchResult[0][this.routeIndex][1]);
    for (const key of keys) {
      const value = this.#getParamValue(this.#matchResult[0][this.routeIndex][1][key]);
      if (value && typeof value === "string") {
        decoded[key] = /\%/.test(value) ? tryDecodeURIComponent(value) : value;
      }
    }
    return decoded;
  }
  #getParamValue(paramKey) {
    return this.#matchResult[1] ? this.#matchResult[1][paramKey] : paramKey;
  }
  query(key) {
    return getQueryParam(this.url, key);
  }
  queries(key) {
    return getQueryParams(this.url, key);
  }
  header(name) {
    if (name) {
      return this.raw.headers.get(name) ?? void 0;
    }
    const headerData = {};
    this.raw.headers.forEach((value, key) => {
      headerData[key] = value;
    });
    return headerData;
  }
  async parseBody(options) {
    return this.bodyCache.parsedBody ??= await parseBody(this, options);
  }
  #cachedBody = /* @__PURE__ */ __name((key) => {
    const { bodyCache, raw: raw2 } = this;
    const cachedBody = bodyCache[key];
    if (cachedBody) {
      return cachedBody;
    }
    const anyCachedKey = Object.keys(bodyCache)[0];
    if (anyCachedKey) {
      return bodyCache[anyCachedKey].then((body) => {
        if (anyCachedKey === "json") {
          body = JSON.stringify(body);
        }
        return new Response(body)[key]();
      });
    }
    return bodyCache[key] = raw2[key]();
  }, "#cachedBody");
  json() {
    return this.#cachedBody("text").then((text) => JSON.parse(text));
  }
  text() {
    return this.#cachedBody("text");
  }
  arrayBuffer() {
    return this.#cachedBody("arrayBuffer");
  }
  blob() {
    return this.#cachedBody("blob");
  }
  formData() {
    return this.#cachedBody("formData");
  }
  addValidatedData(target, data) {
    this.#validatedData[target] = data;
  }
  valid(target) {
    return this.#validatedData[target];
  }
  get url() {
    return this.raw.url;
  }
  get method() {
    return this.raw.method;
  }
  get [GET_MATCH_RESULT]() {
    return this.#matchResult;
  }
  get matchedRoutes() {
    return this.#matchResult[0].map(([[, route]]) => route);
  }
  get routePath() {
    return this.#matchResult[0].map(([[, route]]) => route)[this.routeIndex].path;
  }
};

// node_modules/hono/dist/utils/html.js
init_checked_fetch();
init_modules_watch_stub();
var HtmlEscapedCallbackPhase = {
  Stringify: 1,
  BeforeStream: 2,
  Stream: 3
};
var raw = /* @__PURE__ */ __name((value, callbacks) => {
  const escapedString = new String(value);
  escapedString.isEscaped = true;
  escapedString.callbacks = callbacks;
  return escapedString;
}, "raw");
var resolveCallback = /* @__PURE__ */ __name(async (str, phase, preserveCallbacks, context, buffer) => {
  if (typeof str === "object" && !(str instanceof String)) {
    if (!(str instanceof Promise)) {
      str = str.toString();
    }
    if (str instanceof Promise) {
      str = await str;
    }
  }
  const callbacks = str.callbacks;
  if (!callbacks?.length) {
    return Promise.resolve(str);
  }
  if (buffer) {
    buffer[0] += str;
  } else {
    buffer = [str];
  }
  const resStr = Promise.all(callbacks.map((c) => c({ phase, buffer, context }))).then(
    (res) => Promise.all(
      res.filter(Boolean).map((str2) => resolveCallback(str2, phase, false, context, buffer))
    ).then(() => buffer[0])
  );
  if (preserveCallbacks) {
    return raw(await resStr, callbacks);
  } else {
    return resStr;
  }
}, "resolveCallback");

// node_modules/hono/dist/context.js
var TEXT_PLAIN = "text/plain; charset=UTF-8";
var setDefaultContentType = /* @__PURE__ */ __name((contentType, headers) => {
  return {
    "Content-Type": contentType,
    ...headers
  };
}, "setDefaultContentType");
var Context = class {
  static {
    __name(this, "Context");
  }
  #rawRequest;
  #req;
  env = {};
  #var;
  finalized = false;
  error;
  #status;
  #executionCtx;
  #res;
  #layout;
  #renderer;
  #notFoundHandler;
  #preparedHeaders;
  #matchResult;
  #path;
  constructor(req, options) {
    this.#rawRequest = req;
    if (options) {
      this.#executionCtx = options.executionCtx;
      this.env = options.env;
      this.#notFoundHandler = options.notFoundHandler;
      this.#path = options.path;
      this.#matchResult = options.matchResult;
    }
  }
  get req() {
    this.#req ??= new HonoRequest(this.#rawRequest, this.#path, this.#matchResult);
    return this.#req;
  }
  get event() {
    if (this.#executionCtx && "respondWith" in this.#executionCtx) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no FetchEvent");
    }
  }
  get executionCtx() {
    if (this.#executionCtx) {
      return this.#executionCtx;
    } else {
      throw Error("This context has no ExecutionContext");
    }
  }
  get res() {
    return this.#res ||= new Response(null, {
      headers: this.#preparedHeaders ??= new Headers()
    });
  }
  set res(_res) {
    if (this.#res && _res) {
      _res = new Response(_res.body, _res);
      for (const [k, v] of this.#res.headers.entries()) {
        if (k === "content-type") {
          continue;
        }
        if (k === "set-cookie") {
          const cookies = this.#res.headers.getSetCookie();
          _res.headers.delete("set-cookie");
          for (const cookie of cookies) {
            _res.headers.append("set-cookie", cookie);
          }
        } else {
          _res.headers.set(k, v);
        }
      }
    }
    this.#res = _res;
    this.finalized = true;
  }
  render = /* @__PURE__ */ __name((...args) => {
    this.#renderer ??= (content) => this.html(content);
    return this.#renderer(...args);
  }, "render");
  setLayout = /* @__PURE__ */ __name((layout) => this.#layout = layout, "setLayout");
  getLayout = /* @__PURE__ */ __name(() => this.#layout, "getLayout");
  setRenderer = /* @__PURE__ */ __name((renderer) => {
    this.#renderer = renderer;
  }, "setRenderer");
  header = /* @__PURE__ */ __name((name, value, options) => {
    if (this.finalized) {
      this.#res = new Response(this.#res.body, this.#res);
    }
    const headers = this.#res ? this.#res.headers : this.#preparedHeaders ??= new Headers();
    if (value === void 0) {
      headers.delete(name);
    } else if (options?.append) {
      headers.append(name, value);
    } else {
      headers.set(name, value);
    }
  }, "header");
  status = /* @__PURE__ */ __name((status) => {
    this.#status = status;
  }, "status");
  set = /* @__PURE__ */ __name((key, value) => {
    this.#var ??= /* @__PURE__ */ new Map();
    this.#var.set(key, value);
  }, "set");
  get = /* @__PURE__ */ __name((key) => {
    return this.#var ? this.#var.get(key) : void 0;
  }, "get");
  get var() {
    if (!this.#var) {
      return {};
    }
    return Object.fromEntries(this.#var);
  }
  #newResponse(data, arg, headers) {
    const responseHeaders = this.#res ? new Headers(this.#res.headers) : this.#preparedHeaders ?? new Headers();
    if (typeof arg === "object" && "headers" in arg) {
      const argHeaders = arg.headers instanceof Headers ? arg.headers : new Headers(arg.headers);
      for (const [key, value] of argHeaders) {
        if (key.toLowerCase() === "set-cookie") {
          responseHeaders.append(key, value);
        } else {
          responseHeaders.set(key, value);
        }
      }
    }
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        if (typeof v === "string") {
          responseHeaders.set(k, v);
        } else {
          responseHeaders.delete(k);
          for (const v2 of v) {
            responseHeaders.append(k, v2);
          }
        }
      }
    }
    const status = typeof arg === "number" ? arg : arg?.status ?? this.#status;
    return new Response(data, { status, headers: responseHeaders });
  }
  newResponse = /* @__PURE__ */ __name((...args) => this.#newResponse(...args), "newResponse");
  body = /* @__PURE__ */ __name((data, arg, headers) => this.#newResponse(data, arg, headers), "body");
  text = /* @__PURE__ */ __name((text, arg, headers) => {
    return !this.#preparedHeaders && !this.#status && !arg && !headers && !this.finalized ? new Response(text) : this.#newResponse(
      text,
      arg,
      setDefaultContentType(TEXT_PLAIN, headers)
    );
  }, "text");
  json = /* @__PURE__ */ __name((object, arg, headers) => {
    return this.#newResponse(
      JSON.stringify(object),
      arg,
      setDefaultContentType("application/json", headers)
    );
  }, "json");
  html = /* @__PURE__ */ __name((html, arg, headers) => {
    const res = /* @__PURE__ */ __name((html2) => this.#newResponse(html2, arg, setDefaultContentType("text/html; charset=UTF-8", headers)), "res");
    return typeof html === "object" ? resolveCallback(html, HtmlEscapedCallbackPhase.Stringify, false, {}).then(res) : res(html);
  }, "html");
  redirect = /* @__PURE__ */ __name((location, status) => {
    const locationString = String(location);
    this.header(
      "Location",
      !/[^\x00-\xFF]/.test(locationString) ? locationString : encodeURI(locationString)
    );
    return this.newResponse(null, status ?? 302);
  }, "redirect");
  notFound = /* @__PURE__ */ __name(() => {
    this.#notFoundHandler ??= () => new Response();
    return this.#notFoundHandler(this);
  }, "notFound");
};

// node_modules/hono/dist/router.js
init_checked_fetch();
init_modules_watch_stub();
var METHOD_NAME_ALL = "ALL";
var METHOD_NAME_ALL_LOWERCASE = "all";
var METHODS = ["get", "post", "put", "delete", "options", "patch"];
var MESSAGE_MATCHER_IS_ALREADY_BUILT = "Can not add a route since the matcher is already built.";
var UnsupportedPathError = class extends Error {
  static {
    __name(this, "UnsupportedPathError");
  }
};

// node_modules/hono/dist/utils/constants.js
init_checked_fetch();
init_modules_watch_stub();
var COMPOSED_HANDLER = "__COMPOSED_HANDLER";

// node_modules/hono/dist/hono-base.js
var notFoundHandler = /* @__PURE__ */ __name((c) => {
  return c.text("404 Not Found", 404);
}, "notFoundHandler");
var errorHandler = /* @__PURE__ */ __name((err, c) => {
  if ("getResponse" in err) {
    const res = err.getResponse();
    return c.newResponse(res.body, res);
  }
  console.error(err);
  return c.text("Internal Server Error", 500);
}, "errorHandler");
var Hono = class {
  static {
    __name(this, "Hono");
  }
  get;
  post;
  put;
  delete;
  options;
  patch;
  all;
  on;
  use;
  router;
  getPath;
  _basePath = "/";
  #path = "/";
  routes = [];
  constructor(options = {}) {
    const allMethods = [...METHODS, METHOD_NAME_ALL_LOWERCASE];
    allMethods.forEach((method) => {
      this[method] = (args1, ...args) => {
        if (typeof args1 === "string") {
          this.#path = args1;
        } else {
          this.#addRoute(method, this.#path, args1);
        }
        args.forEach((handler) => {
          this.#addRoute(method, this.#path, handler);
        });
        return this;
      };
    });
    this.on = (method, path, ...handlers) => {
      for (const p of [path].flat()) {
        this.#path = p;
        for (const m of [method].flat()) {
          handlers.map((handler) => {
            this.#addRoute(m.toUpperCase(), this.#path, handler);
          });
        }
      }
      return this;
    };
    this.use = (arg1, ...handlers) => {
      if (typeof arg1 === "string") {
        this.#path = arg1;
      } else {
        this.#path = "*";
        handlers.unshift(arg1);
      }
      handlers.forEach((handler) => {
        this.#addRoute(METHOD_NAME_ALL, this.#path, handler);
      });
      return this;
    };
    const { strict, ...optionsWithoutStrict } = options;
    Object.assign(this, optionsWithoutStrict);
    this.getPath = strict ?? true ? options.getPath ?? getPath : getPathNoStrict;
  }
  #clone() {
    const clone = new Hono({
      router: this.router,
      getPath: this.getPath
    });
    clone.errorHandler = this.errorHandler;
    clone.#notFoundHandler = this.#notFoundHandler;
    clone.routes = this.routes;
    return clone;
  }
  #notFoundHandler = notFoundHandler;
  errorHandler = errorHandler;
  route(path, app2) {
    const subApp = this.basePath(path);
    app2.routes.map((r) => {
      let handler;
      if (app2.errorHandler === errorHandler) {
        handler = r.handler;
      } else {
        handler = /* @__PURE__ */ __name(async (c, next) => (await compose([], app2.errorHandler)(c, () => r.handler(c, next))).res, "handler");
        handler[COMPOSED_HANDLER] = r.handler;
      }
      subApp.#addRoute(r.method, r.path, handler);
    });
    return this;
  }
  basePath(path) {
    const subApp = this.#clone();
    subApp._basePath = mergePath(this._basePath, path);
    return subApp;
  }
  onError = /* @__PURE__ */ __name((handler) => {
    this.errorHandler = handler;
    return this;
  }, "onError");
  notFound = /* @__PURE__ */ __name((handler) => {
    this.#notFoundHandler = handler;
    return this;
  }, "notFound");
  mount(path, applicationHandler, options) {
    let replaceRequest;
    let optionHandler;
    if (options) {
      if (typeof options === "function") {
        optionHandler = options;
      } else {
        optionHandler = options.optionHandler;
        if (options.replaceRequest === false) {
          replaceRequest = /* @__PURE__ */ __name((request) => request, "replaceRequest");
        } else {
          replaceRequest = options.replaceRequest;
        }
      }
    }
    const getOptions = optionHandler ? (c) => {
      const options2 = optionHandler(c);
      return Array.isArray(options2) ? options2 : [options2];
    } : (c) => {
      let executionContext = void 0;
      try {
        executionContext = c.executionCtx;
      } catch {
      }
      return [c.env, executionContext];
    };
    replaceRequest ||= (() => {
      const mergedPath = mergePath(this._basePath, path);
      const pathPrefixLength = mergedPath === "/" ? 0 : mergedPath.length;
      return (request) => {
        const url = new URL(request.url);
        url.pathname = url.pathname.slice(pathPrefixLength) || "/";
        return new Request(url, request);
      };
    })();
    const handler = /* @__PURE__ */ __name(async (c, next) => {
      const res = await applicationHandler(replaceRequest(c.req.raw), ...getOptions(c));
      if (res) {
        return res;
      }
      await next();
    }, "handler");
    this.#addRoute(METHOD_NAME_ALL, mergePath(path, "*"), handler);
    return this;
  }
  #addRoute(method, path, handler) {
    method = method.toUpperCase();
    path = mergePath(this._basePath, path);
    const r = { basePath: this._basePath, path, method, handler };
    this.router.add(method, path, [handler, r]);
    this.routes.push(r);
  }
  #handleError(err, c) {
    if (err instanceof Error) {
      return this.errorHandler(err, c);
    }
    throw err;
  }
  #dispatch(request, executionCtx, env, method) {
    if (method === "HEAD") {
      return (async () => new Response(null, await this.#dispatch(request, executionCtx, env, "GET")))();
    }
    const path = this.getPath(request, { env });
    const matchResult = this.router.match(method, path);
    const c = new Context(request, {
      path,
      matchResult,
      env,
      executionCtx,
      notFoundHandler: this.#notFoundHandler
    });
    if (matchResult[0].length === 1) {
      let res;
      try {
        res = matchResult[0][0][0][0](c, async () => {
          c.res = await this.#notFoundHandler(c);
        });
      } catch (err) {
        return this.#handleError(err, c);
      }
      return res instanceof Promise ? res.then(
        (resolved) => resolved || (c.finalized ? c.res : this.#notFoundHandler(c))
      ).catch((err) => this.#handleError(err, c)) : res ?? this.#notFoundHandler(c);
    }
    const composed = compose(matchResult[0], this.errorHandler, this.#notFoundHandler);
    return (async () => {
      try {
        const context = await composed(c);
        if (!context.finalized) {
          throw new Error(
            "Context is not finalized. Did you forget to return a Response object or `await next()`?"
          );
        }
        return context.res;
      } catch (err) {
        return this.#handleError(err, c);
      }
    })();
  }
  fetch = /* @__PURE__ */ __name((request, ...rest) => {
    return this.#dispatch(request, rest[1], rest[0], request.method);
  }, "fetch");
  request = /* @__PURE__ */ __name((input, requestInit, Env, executionCtx) => {
    if (input instanceof Request) {
      return this.fetch(requestInit ? new Request(input, requestInit) : input, Env, executionCtx);
    }
    input = input.toString();
    return this.fetch(
      new Request(
        /^https?:\/\//.test(input) ? input : `http://localhost${mergePath("/", input)}`,
        requestInit
      ),
      Env,
      executionCtx
    );
  }, "request");
  fire = /* @__PURE__ */ __name(() => {
    addEventListener("fetch", (event) => {
      event.respondWith(this.#dispatch(event.request, event, void 0, event.request.method));
    });
  }, "fire");
};

// node_modules/hono/dist/router/reg-exp-router/index.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/router/reg-exp-router/router.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/router/reg-exp-router/node.js
init_checked_fetch();
init_modules_watch_stub();
var LABEL_REG_EXP_STR = "[^/]+";
var ONLY_WILDCARD_REG_EXP_STR = ".*";
var TAIL_WILDCARD_REG_EXP_STR = "(?:|/.*)";
var PATH_ERROR = Symbol();
var regExpMetaChars = new Set(".\\+*[^]$()");
function compareKey(a, b) {
  if (a.length === 1) {
    return b.length === 1 ? a < b ? -1 : 1 : -1;
  }
  if (b.length === 1) {
    return 1;
  }
  if (a === ONLY_WILDCARD_REG_EXP_STR || a === TAIL_WILDCARD_REG_EXP_STR) {
    return 1;
  } else if (b === ONLY_WILDCARD_REG_EXP_STR || b === TAIL_WILDCARD_REG_EXP_STR) {
    return -1;
  }
  if (a === LABEL_REG_EXP_STR) {
    return 1;
  } else if (b === LABEL_REG_EXP_STR) {
    return -1;
  }
  return a.length === b.length ? a < b ? -1 : 1 : b.length - a.length;
}
__name(compareKey, "compareKey");
var Node = class {
  static {
    __name(this, "Node");
  }
  #index;
  #varIndex;
  #children = /* @__PURE__ */ Object.create(null);
  insert(tokens, index, paramMap, context, pathErrorCheckOnly) {
    if (tokens.length === 0) {
      if (this.#index !== void 0) {
        throw PATH_ERROR;
      }
      if (pathErrorCheckOnly) {
        return;
      }
      this.#index = index;
      return;
    }
    const [token, ...restTokens] = tokens;
    const pattern = token === "*" ? restTokens.length === 0 ? ["", "", ONLY_WILDCARD_REG_EXP_STR] : ["", "", LABEL_REG_EXP_STR] : token === "/*" ? ["", "", TAIL_WILDCARD_REG_EXP_STR] : token.match(/^\:([^\{\}]+)(?:\{(.+)\})?$/);
    let node;
    if (pattern) {
      const name = pattern[1];
      let regexpStr = pattern[2] || LABEL_REG_EXP_STR;
      if (name && pattern[2]) {
        if (regexpStr === ".*") {
          throw PATH_ERROR;
        }
        regexpStr = regexpStr.replace(/^\((?!\?:)(?=[^)]+\)$)/, "(?:");
        if (/\((?!\?:)/.test(regexpStr)) {
          throw PATH_ERROR;
        }
      }
      node = this.#children[regexpStr];
      if (!node) {
        if (Object.keys(this.#children).some(
          (k) => k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR
        )) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[regexpStr] = new Node();
        if (name !== "") {
          node.#varIndex = context.varIndex++;
        }
      }
      if (!pathErrorCheckOnly && name !== "") {
        paramMap.push([name, node.#varIndex]);
      }
    } else {
      node = this.#children[token];
      if (!node) {
        if (Object.keys(this.#children).some(
          (k) => k.length > 1 && k !== ONLY_WILDCARD_REG_EXP_STR && k !== TAIL_WILDCARD_REG_EXP_STR
        )) {
          throw PATH_ERROR;
        }
        if (pathErrorCheckOnly) {
          return;
        }
        node = this.#children[token] = new Node();
      }
    }
    node.insert(restTokens, index, paramMap, context, pathErrorCheckOnly);
  }
  buildRegExpStr() {
    const childKeys = Object.keys(this.#children).sort(compareKey);
    const strList = childKeys.map((k) => {
      const c = this.#children[k];
      return (typeof c.#varIndex === "number" ? `(${k})@${c.#varIndex}` : regExpMetaChars.has(k) ? `\\${k}` : k) + c.buildRegExpStr();
    });
    if (typeof this.#index === "number") {
      strList.unshift(`#${this.#index}`);
    }
    if (strList.length === 0) {
      return "";
    }
    if (strList.length === 1) {
      return strList[0];
    }
    return "(?:" + strList.join("|") + ")";
  }
};

// node_modules/hono/dist/router/reg-exp-router/trie.js
init_checked_fetch();
init_modules_watch_stub();
var Trie = class {
  static {
    __name(this, "Trie");
  }
  #context = { varIndex: 0 };
  #root = new Node();
  insert(path, index, pathErrorCheckOnly) {
    const paramAssoc = [];
    const groups = [];
    for (let i = 0; ; ) {
      let replaced = false;
      path = path.replace(/\{[^}]+\}/g, (m) => {
        const mark = `@\\${i}`;
        groups[i] = [mark, m];
        i++;
        replaced = true;
        return mark;
      });
      if (!replaced) {
        break;
      }
    }
    const tokens = path.match(/(?::[^\/]+)|(?:\/\*$)|./g) || [];
    for (let i = groups.length - 1; i >= 0; i--) {
      const [mark] = groups[i];
      for (let j = tokens.length - 1; j >= 0; j--) {
        if (tokens[j].indexOf(mark) !== -1) {
          tokens[j] = tokens[j].replace(mark, groups[i][1]);
          break;
        }
      }
    }
    this.#root.insert(tokens, index, paramAssoc, this.#context, pathErrorCheckOnly);
    return paramAssoc;
  }
  buildRegExp() {
    let regexp = this.#root.buildRegExpStr();
    if (regexp === "") {
      return [/^$/, [], []];
    }
    let captureIndex = 0;
    const indexReplacementMap = [];
    const paramReplacementMap = [];
    regexp = regexp.replace(/#(\d+)|@(\d+)|\.\*\$/g, (_, handlerIndex, paramIndex) => {
      if (handlerIndex !== void 0) {
        indexReplacementMap[++captureIndex] = Number(handlerIndex);
        return "$()";
      }
      if (paramIndex !== void 0) {
        paramReplacementMap[Number(paramIndex)] = ++captureIndex;
        return "";
      }
      return "";
    });
    return [new RegExp(`^${regexp}`), indexReplacementMap, paramReplacementMap];
  }
};

// node_modules/hono/dist/router/reg-exp-router/router.js
var emptyParam = [];
var nullMatcher = [/^$/, [], /* @__PURE__ */ Object.create(null)];
var wildcardRegExpCache = /* @__PURE__ */ Object.create(null);
function buildWildcardRegExp(path) {
  return wildcardRegExpCache[path] ??= new RegExp(
    path === "*" ? "" : `^${path.replace(
      /\/\*$|([.\\+*[^\]$()])/g,
      (_, metaChar) => metaChar ? `\\${metaChar}` : "(?:|/.*)"
    )}$`
  );
}
__name(buildWildcardRegExp, "buildWildcardRegExp");
function clearWildcardRegExpCache() {
  wildcardRegExpCache = /* @__PURE__ */ Object.create(null);
}
__name(clearWildcardRegExpCache, "clearWildcardRegExpCache");
function buildMatcherFromPreprocessedRoutes(routes) {
  const trie = new Trie();
  const handlerData = [];
  if (routes.length === 0) {
    return nullMatcher;
  }
  const routesWithStaticPathFlag = routes.map(
    (route) => [!/\*|\/:/.test(route[0]), ...route]
  ).sort(
    ([isStaticA, pathA], [isStaticB, pathB]) => isStaticA ? 1 : isStaticB ? -1 : pathA.length - pathB.length
  );
  const staticMap = /* @__PURE__ */ Object.create(null);
  for (let i = 0, j = -1, len = routesWithStaticPathFlag.length; i < len; i++) {
    const [pathErrorCheckOnly, path, handlers] = routesWithStaticPathFlag[i];
    if (pathErrorCheckOnly) {
      staticMap[path] = [handlers.map(([h]) => [h, /* @__PURE__ */ Object.create(null)]), emptyParam];
    } else {
      j++;
    }
    let paramAssoc;
    try {
      paramAssoc = trie.insert(path, j, pathErrorCheckOnly);
    } catch (e) {
      throw e === PATH_ERROR ? new UnsupportedPathError(path) : e;
    }
    if (pathErrorCheckOnly) {
      continue;
    }
    handlerData[j] = handlers.map(([h, paramCount]) => {
      const paramIndexMap = /* @__PURE__ */ Object.create(null);
      paramCount -= 1;
      for (; paramCount >= 0; paramCount--) {
        const [key, value] = paramAssoc[paramCount];
        paramIndexMap[key] = value;
      }
      return [h, paramIndexMap];
    });
  }
  const [regexp, indexReplacementMap, paramReplacementMap] = trie.buildRegExp();
  for (let i = 0, len = handlerData.length; i < len; i++) {
    for (let j = 0, len2 = handlerData[i].length; j < len2; j++) {
      const map = handlerData[i][j]?.[1];
      if (!map) {
        continue;
      }
      const keys = Object.keys(map);
      for (let k = 0, len3 = keys.length; k < len3; k++) {
        map[keys[k]] = paramReplacementMap[map[keys[k]]];
      }
    }
  }
  const handlerMap = [];
  for (const i in indexReplacementMap) {
    handlerMap[i] = handlerData[indexReplacementMap[i]];
  }
  return [regexp, handlerMap, staticMap];
}
__name(buildMatcherFromPreprocessedRoutes, "buildMatcherFromPreprocessedRoutes");
function findMiddleware(middleware, path) {
  if (!middleware) {
    return void 0;
  }
  for (const k of Object.keys(middleware).sort((a, b) => b.length - a.length)) {
    if (buildWildcardRegExp(k).test(path)) {
      return [...middleware[k]];
    }
  }
  return void 0;
}
__name(findMiddleware, "findMiddleware");
var RegExpRouter = class {
  static {
    __name(this, "RegExpRouter");
  }
  name = "RegExpRouter";
  #middleware;
  #routes;
  constructor() {
    this.#middleware = { [METHOD_NAME_ALL]: /* @__PURE__ */ Object.create(null) };
    this.#routes = { [METHOD_NAME_ALL]: /* @__PURE__ */ Object.create(null) };
  }
  add(method, path, handler) {
    const middleware = this.#middleware;
    const routes = this.#routes;
    if (!middleware || !routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    if (!middleware[method]) {
      ;
      [middleware, routes].forEach((handlerMap) => {
        handlerMap[method] = /* @__PURE__ */ Object.create(null);
        Object.keys(handlerMap[METHOD_NAME_ALL]).forEach((p) => {
          handlerMap[method][p] = [...handlerMap[METHOD_NAME_ALL][p]];
        });
      });
    }
    if (path === "/*") {
      path = "*";
    }
    const paramCount = (path.match(/\/:/g) || []).length;
    if (/\*$/.test(path)) {
      const re = buildWildcardRegExp(path);
      if (method === METHOD_NAME_ALL) {
        Object.keys(middleware).forEach((m) => {
          middleware[m][path] ||= findMiddleware(middleware[m], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
        });
      } else {
        middleware[method][path] ||= findMiddleware(middleware[method], path) || findMiddleware(middleware[METHOD_NAME_ALL], path) || [];
      }
      Object.keys(middleware).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(middleware[m]).forEach((p) => {
            re.test(p) && middleware[m][p].push([handler, paramCount]);
          });
        }
      });
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          Object.keys(routes[m]).forEach(
            (p) => re.test(p) && routes[m][p].push([handler, paramCount])
          );
        }
      });
      return;
    }
    const paths = checkOptionalParameter(path) || [path];
    for (let i = 0, len = paths.length; i < len; i++) {
      const path2 = paths[i];
      Object.keys(routes).forEach((m) => {
        if (method === METHOD_NAME_ALL || method === m) {
          routes[m][path2] ||= [
            ...findMiddleware(middleware[m], path2) || findMiddleware(middleware[METHOD_NAME_ALL], path2) || []
          ];
          routes[m][path2].push([handler, paramCount - len + i + 1]);
        }
      });
    }
  }
  match(method, path) {
    clearWildcardRegExpCache();
    const matchers = this.#buildAllMatchers();
    this.match = (method2, path2) => {
      const matcher = matchers[method2] || matchers[METHOD_NAME_ALL];
      const staticMatch = matcher[2][path2];
      if (staticMatch) {
        return staticMatch;
      }
      const match = path2.match(matcher[0]);
      if (!match) {
        return [[], emptyParam];
      }
      const index = match.indexOf("", 1);
      return [matcher[1][index], match];
    };
    return this.match(method, path);
  }
  #buildAllMatchers() {
    const matchers = /* @__PURE__ */ Object.create(null);
    Object.keys(this.#routes).concat(Object.keys(this.#middleware)).forEach((method) => {
      matchers[method] ||= this.#buildMatcher(method);
    });
    this.#middleware = this.#routes = void 0;
    return matchers;
  }
  #buildMatcher(method) {
    const routes = [];
    let hasOwnRoute = method === METHOD_NAME_ALL;
    [this.#middleware, this.#routes].forEach((r) => {
      const ownRoute = r[method] ? Object.keys(r[method]).map((path) => [path, r[method][path]]) : [];
      if (ownRoute.length !== 0) {
        hasOwnRoute ||= true;
        routes.push(...ownRoute);
      } else if (method !== METHOD_NAME_ALL) {
        routes.push(
          ...Object.keys(r[METHOD_NAME_ALL]).map((path) => [path, r[METHOD_NAME_ALL][path]])
        );
      }
    });
    if (!hasOwnRoute) {
      return null;
    } else {
      return buildMatcherFromPreprocessedRoutes(routes);
    }
  }
};

// node_modules/hono/dist/router/smart-router/index.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/router/smart-router/router.js
init_checked_fetch();
init_modules_watch_stub();
var SmartRouter = class {
  static {
    __name(this, "SmartRouter");
  }
  name = "SmartRouter";
  #routers = [];
  #routes = [];
  constructor(init) {
    this.#routers = init.routers;
  }
  add(method, path, handler) {
    if (!this.#routes) {
      throw new Error(MESSAGE_MATCHER_IS_ALREADY_BUILT);
    }
    this.#routes.push([method, path, handler]);
  }
  match(method, path) {
    if (!this.#routes) {
      throw new Error("Fatal error");
    }
    const routers = this.#routers;
    const routes = this.#routes;
    const len = routers.length;
    let i = 0;
    let res;
    for (; i < len; i++) {
      const router2 = routers[i];
      try {
        for (let i2 = 0, len2 = routes.length; i2 < len2; i2++) {
          router2.add(...routes[i2]);
        }
        res = router2.match(method, path);
      } catch (e) {
        if (e instanceof UnsupportedPathError) {
          continue;
        }
        throw e;
      }
      this.match = router2.match.bind(router2);
      this.#routers = [router2];
      this.#routes = void 0;
      break;
    }
    if (i === len) {
      throw new Error("Fatal error");
    }
    this.name = `SmartRouter + ${this.activeRouter.name}`;
    return res;
  }
  get activeRouter() {
    if (this.#routes || this.#routers.length !== 1) {
      throw new Error("No active router has been determined yet.");
    }
    return this.#routers[0];
  }
};

// node_modules/hono/dist/router/trie-router/index.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/router/trie-router/router.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/hono/dist/router/trie-router/node.js
init_checked_fetch();
init_modules_watch_stub();
var emptyParams = /* @__PURE__ */ Object.create(null);
var Node2 = class {
  static {
    __name(this, "Node");
  }
  #methods;
  #children;
  #patterns;
  #order = 0;
  #params = emptyParams;
  constructor(method, handler, children) {
    this.#children = children || /* @__PURE__ */ Object.create(null);
    this.#methods = [];
    if (method && handler) {
      const m = /* @__PURE__ */ Object.create(null);
      m[method] = { handler, possibleKeys: [], score: 0 };
      this.#methods = [m];
    }
    this.#patterns = [];
  }
  insert(method, path, handler) {
    this.#order = ++this.#order;
    let curNode = this;
    const parts = splitRoutingPath(path);
    const possibleKeys = [];
    for (let i = 0, len = parts.length; i < len; i++) {
      const p = parts[i];
      const nextP = parts[i + 1];
      const pattern = getPattern(p, nextP);
      const key = Array.isArray(pattern) ? pattern[0] : p;
      if (key in curNode.#children) {
        curNode = curNode.#children[key];
        if (pattern) {
          possibleKeys.push(pattern[1]);
        }
        continue;
      }
      curNode.#children[key] = new Node2();
      if (pattern) {
        curNode.#patterns.push(pattern);
        possibleKeys.push(pattern[1]);
      }
      curNode = curNode.#children[key];
    }
    curNode.#methods.push({
      [method]: {
        handler,
        possibleKeys: possibleKeys.filter((v, i, a) => a.indexOf(v) === i),
        score: this.#order
      }
    });
    return curNode;
  }
  #getHandlerSets(node, method, nodeParams, params) {
    const handlerSets = [];
    for (let i = 0, len = node.#methods.length; i < len; i++) {
      const m = node.#methods[i];
      const handlerSet = m[method] || m[METHOD_NAME_ALL];
      const processedSet = {};
      if (handlerSet !== void 0) {
        handlerSet.params = /* @__PURE__ */ Object.create(null);
        handlerSets.push(handlerSet);
        if (nodeParams !== emptyParams || params && params !== emptyParams) {
          for (let i2 = 0, len2 = handlerSet.possibleKeys.length; i2 < len2; i2++) {
            const key = handlerSet.possibleKeys[i2];
            const processed = processedSet[handlerSet.score];
            handlerSet.params[key] = params?.[key] && !processed ? params[key] : nodeParams[key] ?? params?.[key];
            processedSet[handlerSet.score] = true;
          }
        }
      }
    }
    return handlerSets;
  }
  search(method, path) {
    const handlerSets = [];
    this.#params = emptyParams;
    const curNode = this;
    let curNodes = [curNode];
    const parts = splitPath(path);
    const curNodesQueue = [];
    for (let i = 0, len = parts.length; i < len; i++) {
      const part = parts[i];
      const isLast = i === len - 1;
      const tempNodes = [];
      for (let j = 0, len2 = curNodes.length; j < len2; j++) {
        const node = curNodes[j];
        const nextNode = node.#children[part];
        if (nextNode) {
          nextNode.#params = node.#params;
          if (isLast) {
            if (nextNode.#children["*"]) {
              handlerSets.push(
                ...this.#getHandlerSets(nextNode.#children["*"], method, node.#params)
              );
            }
            handlerSets.push(...this.#getHandlerSets(nextNode, method, node.#params));
          } else {
            tempNodes.push(nextNode);
          }
        }
        for (let k = 0, len3 = node.#patterns.length; k < len3; k++) {
          const pattern = node.#patterns[k];
          const params = node.#params === emptyParams ? {} : { ...node.#params };
          if (pattern === "*") {
            const astNode = node.#children["*"];
            if (astNode) {
              handlerSets.push(...this.#getHandlerSets(astNode, method, node.#params));
              astNode.#params = params;
              tempNodes.push(astNode);
            }
            continue;
          }
          const [key, name, matcher] = pattern;
          if (!part && !(matcher instanceof RegExp)) {
            continue;
          }
          const child = node.#children[key];
          const restPathString = parts.slice(i).join("/");
          if (matcher instanceof RegExp) {
            const m = matcher.exec(restPathString);
            if (m) {
              params[name] = m[0];
              handlerSets.push(...this.#getHandlerSets(child, method, node.#params, params));
              if (Object.keys(child.#children).length) {
                child.#params = params;
                const componentCount = m[0].match(/\//)?.length ?? 0;
                const targetCurNodes = curNodesQueue[componentCount] ||= [];
                targetCurNodes.push(child);
              }
              continue;
            }
          }
          if (matcher === true || matcher.test(part)) {
            params[name] = part;
            if (isLast) {
              handlerSets.push(...this.#getHandlerSets(child, method, params, node.#params));
              if (child.#children["*"]) {
                handlerSets.push(
                  ...this.#getHandlerSets(child.#children["*"], method, params, node.#params)
                );
              }
            } else {
              child.#params = params;
              tempNodes.push(child);
            }
          }
        }
      }
      curNodes = tempNodes.concat(curNodesQueue.shift() ?? []);
    }
    if (handlerSets.length > 1) {
      handlerSets.sort((a, b) => {
        return a.score - b.score;
      });
    }
    return [handlerSets.map(({ handler, params }) => [handler, params])];
  }
};

// node_modules/hono/dist/router/trie-router/router.js
var TrieRouter = class {
  static {
    __name(this, "TrieRouter");
  }
  name = "TrieRouter";
  #node;
  constructor() {
    this.#node = new Node2();
  }
  add(method, path, handler) {
    const results = checkOptionalParameter(path);
    if (results) {
      for (let i = 0, len = results.length; i < len; i++) {
        this.#node.insert(method, results[i], handler);
      }
      return;
    }
    this.#node.insert(method, path, handler);
  }
  match(method, path) {
    return this.#node.search(method, path);
  }
};

// node_modules/hono/dist/hono.js
var Hono2 = class extends Hono {
  static {
    __name(this, "Hono");
  }
  constructor(options = {}) {
    super(options);
    this.router = options.router ?? new SmartRouter({
      routers: [new RegExpRouter(), new TrieRouter()]
    });
  }
};

// src/routes/timeEntries.ts
init_checked_fetch();
init_modules_watch_stub();

// node_modules/zod/index.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/zod/v3/external.js
var external_exports = {};
__export(external_exports, {
  BRAND: () => BRAND,
  DIRTY: () => DIRTY,
  EMPTY_PATH: () => EMPTY_PATH,
  INVALID: () => INVALID,
  NEVER: () => NEVER,
  OK: () => OK,
  ParseStatus: () => ParseStatus,
  Schema: () => ZodType,
  ZodAny: () => ZodAny,
  ZodArray: () => ZodArray,
  ZodBigInt: () => ZodBigInt,
  ZodBoolean: () => ZodBoolean,
  ZodBranded: () => ZodBranded,
  ZodCatch: () => ZodCatch,
  ZodDate: () => ZodDate,
  ZodDefault: () => ZodDefault,
  ZodDiscriminatedUnion: () => ZodDiscriminatedUnion,
  ZodEffects: () => ZodEffects,
  ZodEnum: () => ZodEnum,
  ZodError: () => ZodError,
  ZodFirstPartyTypeKind: () => ZodFirstPartyTypeKind,
  ZodFunction: () => ZodFunction,
  ZodIntersection: () => ZodIntersection,
  ZodIssueCode: () => ZodIssueCode,
  ZodLazy: () => ZodLazy,
  ZodLiteral: () => ZodLiteral,
  ZodMap: () => ZodMap,
  ZodNaN: () => ZodNaN,
  ZodNativeEnum: () => ZodNativeEnum,
  ZodNever: () => ZodNever,
  ZodNull: () => ZodNull,
  ZodNullable: () => ZodNullable,
  ZodNumber: () => ZodNumber,
  ZodObject: () => ZodObject,
  ZodOptional: () => ZodOptional,
  ZodParsedType: () => ZodParsedType,
  ZodPipeline: () => ZodPipeline,
  ZodPromise: () => ZodPromise,
  ZodReadonly: () => ZodReadonly,
  ZodRecord: () => ZodRecord,
  ZodSchema: () => ZodType,
  ZodSet: () => ZodSet,
  ZodString: () => ZodString,
  ZodSymbol: () => ZodSymbol,
  ZodTransformer: () => ZodEffects,
  ZodTuple: () => ZodTuple,
  ZodType: () => ZodType,
  ZodUndefined: () => ZodUndefined,
  ZodUnion: () => ZodUnion,
  ZodUnknown: () => ZodUnknown,
  ZodVoid: () => ZodVoid,
  addIssueToContext: () => addIssueToContext,
  any: () => anyType,
  array: () => arrayType,
  bigint: () => bigIntType,
  boolean: () => booleanType,
  coerce: () => coerce,
  custom: () => custom,
  date: () => dateType,
  datetimeRegex: () => datetimeRegex,
  defaultErrorMap: () => en_default,
  discriminatedUnion: () => discriminatedUnionType,
  effect: () => effectsType,
  enum: () => enumType,
  function: () => functionType,
  getErrorMap: () => getErrorMap,
  getParsedType: () => getParsedType,
  instanceof: () => instanceOfType,
  intersection: () => intersectionType,
  isAborted: () => isAborted,
  isAsync: () => isAsync,
  isDirty: () => isDirty,
  isValid: () => isValid,
  late: () => late,
  lazy: () => lazyType,
  literal: () => literalType,
  makeIssue: () => makeIssue,
  map: () => mapType,
  nan: () => nanType,
  nativeEnum: () => nativeEnumType,
  never: () => neverType,
  null: () => nullType,
  nullable: () => nullableType,
  number: () => numberType,
  object: () => objectType,
  objectUtil: () => objectUtil,
  oboolean: () => oboolean,
  onumber: () => onumber,
  optional: () => optionalType,
  ostring: () => ostring,
  pipeline: () => pipelineType,
  preprocess: () => preprocessType,
  promise: () => promiseType,
  quotelessJson: () => quotelessJson,
  record: () => recordType,
  set: () => setType,
  setErrorMap: () => setErrorMap,
  strictObject: () => strictObjectType,
  string: () => stringType,
  symbol: () => symbolType,
  transformer: () => effectsType,
  tuple: () => tupleType,
  undefined: () => undefinedType,
  union: () => unionType,
  unknown: () => unknownType,
  util: () => util,
  void: () => voidType
});
init_checked_fetch();
init_modules_watch_stub();

// node_modules/zod/v3/errors.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/zod/v3/locales/en.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/zod/v3/ZodError.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/zod/v3/helpers/util.js
init_checked_fetch();
init_modules_watch_stub();
var util;
(function(util2) {
  util2.assertEqual = (_) => {
  };
  function assertIs(_arg) {
  }
  __name(assertIs, "assertIs");
  util2.assertIs = assertIs;
  function assertNever(_x) {
    throw new Error();
  }
  __name(assertNever, "assertNever");
  util2.assertNever = assertNever;
  util2.arrayToEnum = (items) => {
    const obj = {};
    for (const item of items) {
      obj[item] = item;
    }
    return obj;
  };
  util2.getValidEnumValues = (obj) => {
    const validKeys = util2.objectKeys(obj).filter((k) => typeof obj[obj[k]] !== "number");
    const filtered = {};
    for (const k of validKeys) {
      filtered[k] = obj[k];
    }
    return util2.objectValues(filtered);
  };
  util2.objectValues = (obj) => {
    return util2.objectKeys(obj).map(function(e) {
      return obj[e];
    });
  };
  util2.objectKeys = typeof Object.keys === "function" ? (obj) => Object.keys(obj) : (object) => {
    const keys = [];
    for (const key in object) {
      if (Object.prototype.hasOwnProperty.call(object, key)) {
        keys.push(key);
      }
    }
    return keys;
  };
  util2.find = (arr, checker) => {
    for (const item of arr) {
      if (checker(item))
        return item;
    }
    return void 0;
  };
  util2.isInteger = typeof Number.isInteger === "function" ? (val) => Number.isInteger(val) : (val) => typeof val === "number" && Number.isFinite(val) && Math.floor(val) === val;
  function joinValues(array, separator = " | ") {
    return array.map((val) => typeof val === "string" ? `'${val}'` : val).join(separator);
  }
  __name(joinValues, "joinValues");
  util2.joinValues = joinValues;
  util2.jsonStringifyReplacer = (_, value) => {
    if (typeof value === "bigint") {
      return value.toString();
    }
    return value;
  };
})(util || (util = {}));
var objectUtil;
(function(objectUtil2) {
  objectUtil2.mergeShapes = (first, second) => {
    return {
      ...first,
      ...second
      // second overwrites first
    };
  };
})(objectUtil || (objectUtil = {}));
var ZodParsedType = util.arrayToEnum([
  "string",
  "nan",
  "number",
  "integer",
  "float",
  "boolean",
  "date",
  "bigint",
  "symbol",
  "function",
  "undefined",
  "null",
  "array",
  "object",
  "unknown",
  "promise",
  "void",
  "never",
  "map",
  "set"
]);
var getParsedType = /* @__PURE__ */ __name((data) => {
  const t = typeof data;
  switch (t) {
    case "undefined":
      return ZodParsedType.undefined;
    case "string":
      return ZodParsedType.string;
    case "number":
      return Number.isNaN(data) ? ZodParsedType.nan : ZodParsedType.number;
    case "boolean":
      return ZodParsedType.boolean;
    case "function":
      return ZodParsedType.function;
    case "bigint":
      return ZodParsedType.bigint;
    case "symbol":
      return ZodParsedType.symbol;
    case "object":
      if (Array.isArray(data)) {
        return ZodParsedType.array;
      }
      if (data === null) {
        return ZodParsedType.null;
      }
      if (data.then && typeof data.then === "function" && data.catch && typeof data.catch === "function") {
        return ZodParsedType.promise;
      }
      if (typeof Map !== "undefined" && data instanceof Map) {
        return ZodParsedType.map;
      }
      if (typeof Set !== "undefined" && data instanceof Set) {
        return ZodParsedType.set;
      }
      if (typeof Date !== "undefined" && data instanceof Date) {
        return ZodParsedType.date;
      }
      return ZodParsedType.object;
    default:
      return ZodParsedType.unknown;
  }
}, "getParsedType");

// node_modules/zod/v3/ZodError.js
var ZodIssueCode = util.arrayToEnum([
  "invalid_type",
  "invalid_literal",
  "custom",
  "invalid_union",
  "invalid_union_discriminator",
  "invalid_enum_value",
  "unrecognized_keys",
  "invalid_arguments",
  "invalid_return_type",
  "invalid_date",
  "invalid_string",
  "too_small",
  "too_big",
  "invalid_intersection_types",
  "not_multiple_of",
  "not_finite"
]);
var quotelessJson = /* @__PURE__ */ __name((obj) => {
  const json = JSON.stringify(obj, null, 2);
  return json.replace(/"([^"]+)":/g, "$1:");
}, "quotelessJson");
var ZodError = class _ZodError extends Error {
  static {
    __name(this, "ZodError");
  }
  get errors() {
    return this.issues;
  }
  constructor(issues) {
    super();
    this.issues = [];
    this.addIssue = (sub) => {
      this.issues = [...this.issues, sub];
    };
    this.addIssues = (subs = []) => {
      this.issues = [...this.issues, ...subs];
    };
    const actualProto = new.target.prototype;
    if (Object.setPrototypeOf) {
      Object.setPrototypeOf(this, actualProto);
    } else {
      this.__proto__ = actualProto;
    }
    this.name = "ZodError";
    this.issues = issues;
  }
  format(_mapper) {
    const mapper = _mapper || function(issue) {
      return issue.message;
    };
    const fieldErrors = { _errors: [] };
    const processError = /* @__PURE__ */ __name((error) => {
      for (const issue of error.issues) {
        if (issue.code === "invalid_union") {
          issue.unionErrors.map(processError);
        } else if (issue.code === "invalid_return_type") {
          processError(issue.returnTypeError);
        } else if (issue.code === "invalid_arguments") {
          processError(issue.argumentsError);
        } else if (issue.path.length === 0) {
          fieldErrors._errors.push(mapper(issue));
        } else {
          let curr = fieldErrors;
          let i = 0;
          while (i < issue.path.length) {
            const el = issue.path[i];
            const terminal = i === issue.path.length - 1;
            if (!terminal) {
              curr[el] = curr[el] || { _errors: [] };
            } else {
              curr[el] = curr[el] || { _errors: [] };
              curr[el]._errors.push(mapper(issue));
            }
            curr = curr[el];
            i++;
          }
        }
      }
    }, "processError");
    processError(this);
    return fieldErrors;
  }
  static assert(value) {
    if (!(value instanceof _ZodError)) {
      throw new Error(`Not a ZodError: ${value}`);
    }
  }
  toString() {
    return this.message;
  }
  get message() {
    return JSON.stringify(this.issues, util.jsonStringifyReplacer, 2);
  }
  get isEmpty() {
    return this.issues.length === 0;
  }
  flatten(mapper = (issue) => issue.message) {
    const fieldErrors = {};
    const formErrors = [];
    for (const sub of this.issues) {
      if (sub.path.length > 0) {
        const firstEl = sub.path[0];
        fieldErrors[firstEl] = fieldErrors[firstEl] || [];
        fieldErrors[firstEl].push(mapper(sub));
      } else {
        formErrors.push(mapper(sub));
      }
    }
    return { formErrors, fieldErrors };
  }
  get formErrors() {
    return this.flatten();
  }
};
ZodError.create = (issues) => {
  const error = new ZodError(issues);
  return error;
};

// node_modules/zod/v3/locales/en.js
var errorMap = /* @__PURE__ */ __name((issue, _ctx) => {
  let message;
  switch (issue.code) {
    case ZodIssueCode.invalid_type:
      if (issue.received === ZodParsedType.undefined) {
        message = "Required";
      } else {
        message = `Expected ${issue.expected}, received ${issue.received}`;
      }
      break;
    case ZodIssueCode.invalid_literal:
      message = `Invalid literal value, expected ${JSON.stringify(issue.expected, util.jsonStringifyReplacer)}`;
      break;
    case ZodIssueCode.unrecognized_keys:
      message = `Unrecognized key(s) in object: ${util.joinValues(issue.keys, ", ")}`;
      break;
    case ZodIssueCode.invalid_union:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_union_discriminator:
      message = `Invalid discriminator value. Expected ${util.joinValues(issue.options)}`;
      break;
    case ZodIssueCode.invalid_enum_value:
      message = `Invalid enum value. Expected ${util.joinValues(issue.options)}, received '${issue.received}'`;
      break;
    case ZodIssueCode.invalid_arguments:
      message = `Invalid function arguments`;
      break;
    case ZodIssueCode.invalid_return_type:
      message = `Invalid function return type`;
      break;
    case ZodIssueCode.invalid_date:
      message = `Invalid date`;
      break;
    case ZodIssueCode.invalid_string:
      if (typeof issue.validation === "object") {
        if ("includes" in issue.validation) {
          message = `Invalid input: must include "${issue.validation.includes}"`;
          if (typeof issue.validation.position === "number") {
            message = `${message} at one or more positions greater than or equal to ${issue.validation.position}`;
          }
        } else if ("startsWith" in issue.validation) {
          message = `Invalid input: must start with "${issue.validation.startsWith}"`;
        } else if ("endsWith" in issue.validation) {
          message = `Invalid input: must end with "${issue.validation.endsWith}"`;
        } else {
          util.assertNever(issue.validation);
        }
      } else if (issue.validation !== "regex") {
        message = `Invalid ${issue.validation}`;
      } else {
        message = "Invalid";
      }
      break;
    case ZodIssueCode.too_small:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `more than`} ${issue.minimum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? "exactly" : issue.inclusive ? `at least` : `over`} ${issue.minimum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "bigint")
        message = `Number must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${issue.minimum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly equal to ` : issue.inclusive ? `greater than or equal to ` : `greater than `}${new Date(Number(issue.minimum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.too_big:
      if (issue.type === "array")
        message = `Array must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `less than`} ${issue.maximum} element(s)`;
      else if (issue.type === "string")
        message = `String must contain ${issue.exact ? `exactly` : issue.inclusive ? `at most` : `under`} ${issue.maximum} character(s)`;
      else if (issue.type === "number")
        message = `Number must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "bigint")
        message = `BigInt must be ${issue.exact ? `exactly` : issue.inclusive ? `less than or equal to` : `less than`} ${issue.maximum}`;
      else if (issue.type === "date")
        message = `Date must be ${issue.exact ? `exactly` : issue.inclusive ? `smaller than or equal to` : `smaller than`} ${new Date(Number(issue.maximum))}`;
      else
        message = "Invalid input";
      break;
    case ZodIssueCode.custom:
      message = `Invalid input`;
      break;
    case ZodIssueCode.invalid_intersection_types:
      message = `Intersection results could not be merged`;
      break;
    case ZodIssueCode.not_multiple_of:
      message = `Number must be a multiple of ${issue.multipleOf}`;
      break;
    case ZodIssueCode.not_finite:
      message = "Number must be finite";
      break;
    default:
      message = _ctx.defaultError;
      util.assertNever(issue);
  }
  return { message };
}, "errorMap");
var en_default = errorMap;

// node_modules/zod/v3/errors.js
var overrideErrorMap = en_default;
function setErrorMap(map) {
  overrideErrorMap = map;
}
__name(setErrorMap, "setErrorMap");
function getErrorMap() {
  return overrideErrorMap;
}
__name(getErrorMap, "getErrorMap");

// node_modules/zod/v3/helpers/parseUtil.js
init_checked_fetch();
init_modules_watch_stub();
var makeIssue = /* @__PURE__ */ __name((params) => {
  const { data, path, errorMaps, issueData } = params;
  const fullPath = [...path, ...issueData.path || []];
  const fullIssue = {
    ...issueData,
    path: fullPath
  };
  if (issueData.message !== void 0) {
    return {
      ...issueData,
      path: fullPath,
      message: issueData.message
    };
  }
  let errorMessage = "";
  const maps = errorMaps.filter((m) => !!m).slice().reverse();
  for (const map of maps) {
    errorMessage = map(fullIssue, { data, defaultError: errorMessage }).message;
  }
  return {
    ...issueData,
    path: fullPath,
    message: errorMessage
  };
}, "makeIssue");
var EMPTY_PATH = [];
function addIssueToContext(ctx, issueData) {
  const overrideMap = getErrorMap();
  const issue = makeIssue({
    issueData,
    data: ctx.data,
    path: ctx.path,
    errorMaps: [
      ctx.common.contextualErrorMap,
      // contextual error map is first priority
      ctx.schemaErrorMap,
      // then schema-bound map if available
      overrideMap,
      // then global override map
      overrideMap === en_default ? void 0 : en_default
      // then global default map
    ].filter((x) => !!x)
  });
  ctx.common.issues.push(issue);
}
__name(addIssueToContext, "addIssueToContext");
var ParseStatus = class _ParseStatus {
  static {
    __name(this, "ParseStatus");
  }
  constructor() {
    this.value = "valid";
  }
  dirty() {
    if (this.value === "valid")
      this.value = "dirty";
  }
  abort() {
    if (this.value !== "aborted")
      this.value = "aborted";
  }
  static mergeArray(status, results) {
    const arrayValue = [];
    for (const s of results) {
      if (s.status === "aborted")
        return INVALID;
      if (s.status === "dirty")
        status.dirty();
      arrayValue.push(s.value);
    }
    return { status: status.value, value: arrayValue };
  }
  static async mergeObjectAsync(status, pairs) {
    const syncPairs = [];
    for (const pair of pairs) {
      const key = await pair.key;
      const value = await pair.value;
      syncPairs.push({
        key,
        value
      });
    }
    return _ParseStatus.mergeObjectSync(status, syncPairs);
  }
  static mergeObjectSync(status, pairs) {
    const finalObject = {};
    for (const pair of pairs) {
      const { key, value } = pair;
      if (key.status === "aborted")
        return INVALID;
      if (value.status === "aborted")
        return INVALID;
      if (key.status === "dirty")
        status.dirty();
      if (value.status === "dirty")
        status.dirty();
      if (key.value !== "__proto__" && (typeof value.value !== "undefined" || pair.alwaysSet)) {
        finalObject[key.value] = value.value;
      }
    }
    return { status: status.value, value: finalObject };
  }
};
var INVALID = Object.freeze({
  status: "aborted"
});
var DIRTY = /* @__PURE__ */ __name((value) => ({ status: "dirty", value }), "DIRTY");
var OK = /* @__PURE__ */ __name((value) => ({ status: "valid", value }), "OK");
var isAborted = /* @__PURE__ */ __name((x) => x.status === "aborted", "isAborted");
var isDirty = /* @__PURE__ */ __name((x) => x.status === "dirty", "isDirty");
var isValid = /* @__PURE__ */ __name((x) => x.status === "valid", "isValid");
var isAsync = /* @__PURE__ */ __name((x) => typeof Promise !== "undefined" && x instanceof Promise, "isAsync");

// node_modules/zod/v3/types.js
init_checked_fetch();
init_modules_watch_stub();

// node_modules/zod/v3/helpers/errorUtil.js
init_checked_fetch();
init_modules_watch_stub();
var errorUtil;
(function(errorUtil2) {
  errorUtil2.errToObj = (message) => typeof message === "string" ? { message } : message || {};
  errorUtil2.toString = (message) => typeof message === "string" ? message : message?.message;
})(errorUtil || (errorUtil = {}));

// node_modules/zod/v3/types.js
var ParseInputLazyPath = class {
  static {
    __name(this, "ParseInputLazyPath");
  }
  constructor(parent, value, path, key) {
    this._cachedPath = [];
    this.parent = parent;
    this.data = value;
    this._path = path;
    this._key = key;
  }
  get path() {
    if (!this._cachedPath.length) {
      if (Array.isArray(this._key)) {
        this._cachedPath.push(...this._path, ...this._key);
      } else {
        this._cachedPath.push(...this._path, this._key);
      }
    }
    return this._cachedPath;
  }
};
var handleResult = /* @__PURE__ */ __name((ctx, result) => {
  if (isValid(result)) {
    return { success: true, data: result.value };
  } else {
    if (!ctx.common.issues.length) {
      throw new Error("Validation failed but no issues detected.");
    }
    return {
      success: false,
      get error() {
        if (this._error)
          return this._error;
        const error = new ZodError(ctx.common.issues);
        this._error = error;
        return this._error;
      }
    };
  }
}, "handleResult");
function processCreateParams(params) {
  if (!params)
    return {};
  const { errorMap: errorMap2, invalid_type_error, required_error, description } = params;
  if (errorMap2 && (invalid_type_error || required_error)) {
    throw new Error(`Can't use "invalid_type_error" or "required_error" in conjunction with custom error map.`);
  }
  if (errorMap2)
    return { errorMap: errorMap2, description };
  const customMap = /* @__PURE__ */ __name((iss, ctx) => {
    const { message } = params;
    if (iss.code === "invalid_enum_value") {
      return { message: message ?? ctx.defaultError };
    }
    if (typeof ctx.data === "undefined") {
      return { message: message ?? required_error ?? ctx.defaultError };
    }
    if (iss.code !== "invalid_type")
      return { message: ctx.defaultError };
    return { message: message ?? invalid_type_error ?? ctx.defaultError };
  }, "customMap");
  return { errorMap: customMap, description };
}
__name(processCreateParams, "processCreateParams");
var ZodType = class {
  static {
    __name(this, "ZodType");
  }
  get description() {
    return this._def.description;
  }
  _getType(input) {
    return getParsedType(input.data);
  }
  _getOrReturnCtx(input, ctx) {
    return ctx || {
      common: input.parent.common,
      data: input.data,
      parsedType: getParsedType(input.data),
      schemaErrorMap: this._def.errorMap,
      path: input.path,
      parent: input.parent
    };
  }
  _processInputParams(input) {
    return {
      status: new ParseStatus(),
      ctx: {
        common: input.parent.common,
        data: input.data,
        parsedType: getParsedType(input.data),
        schemaErrorMap: this._def.errorMap,
        path: input.path,
        parent: input.parent
      }
    };
  }
  _parseSync(input) {
    const result = this._parse(input);
    if (isAsync(result)) {
      throw new Error("Synchronous parse encountered promise.");
    }
    return result;
  }
  _parseAsync(input) {
    const result = this._parse(input);
    return Promise.resolve(result);
  }
  parse(data, params) {
    const result = this.safeParse(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  safeParse(data, params) {
    const ctx = {
      common: {
        issues: [],
        async: params?.async ?? false,
        contextualErrorMap: params?.errorMap
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const result = this._parseSync({ data, path: ctx.path, parent: ctx });
    return handleResult(ctx, result);
  }
  "~validate"(data) {
    const ctx = {
      common: {
        issues: [],
        async: !!this["~standard"].async
      },
      path: [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    if (!this["~standard"].async) {
      try {
        const result = this._parseSync({ data, path: [], parent: ctx });
        return isValid(result) ? {
          value: result.value
        } : {
          issues: ctx.common.issues
        };
      } catch (err) {
        if (err?.message?.toLowerCase()?.includes("encountered")) {
          this["~standard"].async = true;
        }
        ctx.common = {
          issues: [],
          async: true
        };
      }
    }
    return this._parseAsync({ data, path: [], parent: ctx }).then((result) => isValid(result) ? {
      value: result.value
    } : {
      issues: ctx.common.issues
    });
  }
  async parseAsync(data, params) {
    const result = await this.safeParseAsync(data, params);
    if (result.success)
      return result.data;
    throw result.error;
  }
  async safeParseAsync(data, params) {
    const ctx = {
      common: {
        issues: [],
        contextualErrorMap: params?.errorMap,
        async: true
      },
      path: params?.path || [],
      schemaErrorMap: this._def.errorMap,
      parent: null,
      data,
      parsedType: getParsedType(data)
    };
    const maybeAsyncResult = this._parse({ data, path: ctx.path, parent: ctx });
    const result = await (isAsync(maybeAsyncResult) ? maybeAsyncResult : Promise.resolve(maybeAsyncResult));
    return handleResult(ctx, result);
  }
  refine(check, message) {
    const getIssueProperties = /* @__PURE__ */ __name((val) => {
      if (typeof message === "string" || typeof message === "undefined") {
        return { message };
      } else if (typeof message === "function") {
        return message(val);
      } else {
        return message;
      }
    }, "getIssueProperties");
    return this._refinement((val, ctx) => {
      const result = check(val);
      const setError = /* @__PURE__ */ __name(() => ctx.addIssue({
        code: ZodIssueCode.custom,
        ...getIssueProperties(val)
      }), "setError");
      if (typeof Promise !== "undefined" && result instanceof Promise) {
        return result.then((data) => {
          if (!data) {
            setError();
            return false;
          } else {
            return true;
          }
        });
      }
      if (!result) {
        setError();
        return false;
      } else {
        return true;
      }
    });
  }
  refinement(check, refinementData) {
    return this._refinement((val, ctx) => {
      if (!check(val)) {
        ctx.addIssue(typeof refinementData === "function" ? refinementData(val, ctx) : refinementData);
        return false;
      } else {
        return true;
      }
    });
  }
  _refinement(refinement) {
    return new ZodEffects({
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "refinement", refinement }
    });
  }
  superRefine(refinement) {
    return this._refinement(refinement);
  }
  constructor(def) {
    this.spa = this.safeParseAsync;
    this._def = def;
    this.parse = this.parse.bind(this);
    this.safeParse = this.safeParse.bind(this);
    this.parseAsync = this.parseAsync.bind(this);
    this.safeParseAsync = this.safeParseAsync.bind(this);
    this.spa = this.spa.bind(this);
    this.refine = this.refine.bind(this);
    this.refinement = this.refinement.bind(this);
    this.superRefine = this.superRefine.bind(this);
    this.optional = this.optional.bind(this);
    this.nullable = this.nullable.bind(this);
    this.nullish = this.nullish.bind(this);
    this.array = this.array.bind(this);
    this.promise = this.promise.bind(this);
    this.or = this.or.bind(this);
    this.and = this.and.bind(this);
    this.transform = this.transform.bind(this);
    this.brand = this.brand.bind(this);
    this.default = this.default.bind(this);
    this.catch = this.catch.bind(this);
    this.describe = this.describe.bind(this);
    this.pipe = this.pipe.bind(this);
    this.readonly = this.readonly.bind(this);
    this.isNullable = this.isNullable.bind(this);
    this.isOptional = this.isOptional.bind(this);
    this["~standard"] = {
      version: 1,
      vendor: "zod",
      validate: /* @__PURE__ */ __name((data) => this["~validate"](data), "validate")
    };
  }
  optional() {
    return ZodOptional.create(this, this._def);
  }
  nullable() {
    return ZodNullable.create(this, this._def);
  }
  nullish() {
    return this.nullable().optional();
  }
  array() {
    return ZodArray.create(this);
  }
  promise() {
    return ZodPromise.create(this, this._def);
  }
  or(option) {
    return ZodUnion.create([this, option], this._def);
  }
  and(incoming) {
    return ZodIntersection.create(this, incoming, this._def);
  }
  transform(transform) {
    return new ZodEffects({
      ...processCreateParams(this._def),
      schema: this,
      typeName: ZodFirstPartyTypeKind.ZodEffects,
      effect: { type: "transform", transform }
    });
  }
  default(def) {
    const defaultValueFunc = typeof def === "function" ? def : () => def;
    return new ZodDefault({
      ...processCreateParams(this._def),
      innerType: this,
      defaultValue: defaultValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodDefault
    });
  }
  brand() {
    return new ZodBranded({
      typeName: ZodFirstPartyTypeKind.ZodBranded,
      type: this,
      ...processCreateParams(this._def)
    });
  }
  catch(def) {
    const catchValueFunc = typeof def === "function" ? def : () => def;
    return new ZodCatch({
      ...processCreateParams(this._def),
      innerType: this,
      catchValue: catchValueFunc,
      typeName: ZodFirstPartyTypeKind.ZodCatch
    });
  }
  describe(description) {
    const This = this.constructor;
    return new This({
      ...this._def,
      description
    });
  }
  pipe(target) {
    return ZodPipeline.create(this, target);
  }
  readonly() {
    return ZodReadonly.create(this);
  }
  isOptional() {
    return this.safeParse(void 0).success;
  }
  isNullable() {
    return this.safeParse(null).success;
  }
};
var cuidRegex = /^c[^\s-]{8,}$/i;
var cuid2Regex = /^[0-9a-z]+$/;
var ulidRegex = /^[0-9A-HJKMNP-TV-Z]{26}$/i;
var uuidRegex = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/i;
var nanoidRegex = /^[a-z0-9_-]{21}$/i;
var jwtRegex = /^[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*$/;
var durationRegex = /^[-+]?P(?!$)(?:(?:[-+]?\d+Y)|(?:[-+]?\d+[.,]\d+Y$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:(?:[-+]?\d+W)|(?:[-+]?\d+[.,]\d+W$))?(?:(?:[-+]?\d+D)|(?:[-+]?\d+[.,]\d+D$))?(?:T(?=[\d+-])(?:(?:[-+]?\d+H)|(?:[-+]?\d+[.,]\d+H$))?(?:(?:[-+]?\d+M)|(?:[-+]?\d+[.,]\d+M$))?(?:[-+]?\d+(?:[.,]\d+)?S)?)??$/;
var emailRegex = /^(?!\.)(?!.*\.\.)([A-Z0-9_'+\-\.]*)[A-Z0-9_+-]@([A-Z0-9][A-Z0-9\-]*\.)+[A-Z]{2,}$/i;
var _emojiRegex = `^(\\p{Extended_Pictographic}|\\p{Emoji_Component})+$`;
var emojiRegex;
var ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])$/;
var ipv4CidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])\/(3[0-2]|[12]?[0-9])$/;
var ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;
var ipv6CidrRegex = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))\/(12[0-8]|1[01][0-9]|[1-9]?[0-9])$/;
var base64Regex = /^([0-9a-zA-Z+/]{4})*(([0-9a-zA-Z+/]{2}==)|([0-9a-zA-Z+/]{3}=))?$/;
var base64urlRegex = /^([0-9a-zA-Z-_]{4})*(([0-9a-zA-Z-_]{2}(==)?)|([0-9a-zA-Z-_]{3}(=)?))?$/;
var dateRegexSource = `((\\d\\d[2468][048]|\\d\\d[13579][26]|\\d\\d0[48]|[02468][048]00|[13579][26]00)-02-29|\\d{4}-((0[13578]|1[02])-(0[1-9]|[12]\\d|3[01])|(0[469]|11)-(0[1-9]|[12]\\d|30)|(02)-(0[1-9]|1\\d|2[0-8])))`;
var dateRegex = new RegExp(`^${dateRegexSource}$`);
function timeRegexSource(args) {
  let secondsRegexSource = `[0-5]\\d`;
  if (args.precision) {
    secondsRegexSource = `${secondsRegexSource}\\.\\d{${args.precision}}`;
  } else if (args.precision == null) {
    secondsRegexSource = `${secondsRegexSource}(\\.\\d+)?`;
  }
  const secondsQuantifier = args.precision ? "+" : "?";
  return `([01]\\d|2[0-3]):[0-5]\\d(:${secondsRegexSource})${secondsQuantifier}`;
}
__name(timeRegexSource, "timeRegexSource");
function timeRegex(args) {
  return new RegExp(`^${timeRegexSource(args)}$`);
}
__name(timeRegex, "timeRegex");
function datetimeRegex(args) {
  let regex = `${dateRegexSource}T${timeRegexSource(args)}`;
  const opts = [];
  opts.push(args.local ? `Z?` : `Z`);
  if (args.offset)
    opts.push(`([+-]\\d{2}:?\\d{2})`);
  regex = `${regex}(${opts.join("|")})`;
  return new RegExp(`^${regex}$`);
}
__name(datetimeRegex, "datetimeRegex");
function isValidIP(ip, version) {
  if ((version === "v4" || !version) && ipv4Regex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6Regex.test(ip)) {
    return true;
  }
  return false;
}
__name(isValidIP, "isValidIP");
function isValidJWT(jwt, alg) {
  if (!jwtRegex.test(jwt))
    return false;
  try {
    const [header] = jwt.split(".");
    if (!header)
      return false;
    const base64 = header.replace(/-/g, "+").replace(/_/g, "/").padEnd(header.length + (4 - header.length % 4) % 4, "=");
    const decoded = JSON.parse(atob(base64));
    if (typeof decoded !== "object" || decoded === null)
      return false;
    if ("typ" in decoded && decoded?.typ !== "JWT")
      return false;
    if (!decoded.alg)
      return false;
    if (alg && decoded.alg !== alg)
      return false;
    return true;
  } catch {
    return false;
  }
}
__name(isValidJWT, "isValidJWT");
function isValidCidr(ip, version) {
  if ((version === "v4" || !version) && ipv4CidrRegex.test(ip)) {
    return true;
  }
  if ((version === "v6" || !version) && ipv6CidrRegex.test(ip)) {
    return true;
  }
  return false;
}
__name(isValidCidr, "isValidCidr");
var ZodString = class _ZodString extends ZodType {
  static {
    __name(this, "ZodString");
  }
  _parse(input) {
    if (this._def.coerce) {
      input.data = String(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.string) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.string,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    const status = new ParseStatus();
    let ctx = void 0;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.length < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.length > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "string",
            inclusive: true,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "length") {
        const tooBig = input.data.length > check.value;
        const tooSmall = input.data.length < check.value;
        if (tooBig || tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          if (tooBig) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_big,
              maximum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          } else if (tooSmall) {
            addIssueToContext(ctx, {
              code: ZodIssueCode.too_small,
              minimum: check.value,
              type: "string",
              inclusive: true,
              exact: true,
              message: check.message
            });
          }
          status.dirty();
        }
      } else if (check.kind === "email") {
        if (!emailRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "email",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "emoji") {
        if (!emojiRegex) {
          emojiRegex = new RegExp(_emojiRegex, "u");
        }
        if (!emojiRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "emoji",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "uuid") {
        if (!uuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "uuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "nanoid") {
        if (!nanoidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "nanoid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid") {
        if (!cuidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cuid2") {
        if (!cuid2Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cuid2",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ulid") {
        if (!ulidRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ulid",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "url") {
        try {
          new URL(input.data);
        } catch {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "regex") {
        check.regex.lastIndex = 0;
        const testResult = check.regex.test(input.data);
        if (!testResult) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "regex",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "trim") {
        input.data = input.data.trim();
      } else if (check.kind === "includes") {
        if (!input.data.includes(check.value, check.position)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { includes: check.value, position: check.position },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "toLowerCase") {
        input.data = input.data.toLowerCase();
      } else if (check.kind === "toUpperCase") {
        input.data = input.data.toUpperCase();
      } else if (check.kind === "startsWith") {
        if (!input.data.startsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { startsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "endsWith") {
        if (!input.data.endsWith(check.value)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: { endsWith: check.value },
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "datetime") {
        const regex = datetimeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "datetime",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "date") {
        const regex = dateRegex;
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "date",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "time") {
        const regex = timeRegex(check);
        if (!regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_string,
            validation: "time",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "duration") {
        if (!durationRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "duration",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "ip") {
        if (!isValidIP(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "ip",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "jwt") {
        if (!isValidJWT(input.data, check.alg)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "jwt",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "cidr") {
        if (!isValidCidr(input.data, check.version)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "cidr",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64") {
        if (!base64Regex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "base64url") {
        if (!base64urlRegex.test(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            validation: "base64url",
            code: ZodIssueCode.invalid_string,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _regex(regex, validation, message) {
    return this.refinement((data) => regex.test(data), {
      validation,
      code: ZodIssueCode.invalid_string,
      ...errorUtil.errToObj(message)
    });
  }
  _addCheck(check) {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  email(message) {
    return this._addCheck({ kind: "email", ...errorUtil.errToObj(message) });
  }
  url(message) {
    return this._addCheck({ kind: "url", ...errorUtil.errToObj(message) });
  }
  emoji(message) {
    return this._addCheck({ kind: "emoji", ...errorUtil.errToObj(message) });
  }
  uuid(message) {
    return this._addCheck({ kind: "uuid", ...errorUtil.errToObj(message) });
  }
  nanoid(message) {
    return this._addCheck({ kind: "nanoid", ...errorUtil.errToObj(message) });
  }
  cuid(message) {
    return this._addCheck({ kind: "cuid", ...errorUtil.errToObj(message) });
  }
  cuid2(message) {
    return this._addCheck({ kind: "cuid2", ...errorUtil.errToObj(message) });
  }
  ulid(message) {
    return this._addCheck({ kind: "ulid", ...errorUtil.errToObj(message) });
  }
  base64(message) {
    return this._addCheck({ kind: "base64", ...errorUtil.errToObj(message) });
  }
  base64url(message) {
    return this._addCheck({
      kind: "base64url",
      ...errorUtil.errToObj(message)
    });
  }
  jwt(options) {
    return this._addCheck({ kind: "jwt", ...errorUtil.errToObj(options) });
  }
  ip(options) {
    return this._addCheck({ kind: "ip", ...errorUtil.errToObj(options) });
  }
  cidr(options) {
    return this._addCheck({ kind: "cidr", ...errorUtil.errToObj(options) });
  }
  datetime(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "datetime",
        precision: null,
        offset: false,
        local: false,
        message: options
      });
    }
    return this._addCheck({
      kind: "datetime",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      offset: options?.offset ?? false,
      local: options?.local ?? false,
      ...errorUtil.errToObj(options?.message)
    });
  }
  date(message) {
    return this._addCheck({ kind: "date", message });
  }
  time(options) {
    if (typeof options === "string") {
      return this._addCheck({
        kind: "time",
        precision: null,
        message: options
      });
    }
    return this._addCheck({
      kind: "time",
      precision: typeof options?.precision === "undefined" ? null : options?.precision,
      ...errorUtil.errToObj(options?.message)
    });
  }
  duration(message) {
    return this._addCheck({ kind: "duration", ...errorUtil.errToObj(message) });
  }
  regex(regex, message) {
    return this._addCheck({
      kind: "regex",
      regex,
      ...errorUtil.errToObj(message)
    });
  }
  includes(value, options) {
    return this._addCheck({
      kind: "includes",
      value,
      position: options?.position,
      ...errorUtil.errToObj(options?.message)
    });
  }
  startsWith(value, message) {
    return this._addCheck({
      kind: "startsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  endsWith(value, message) {
    return this._addCheck({
      kind: "endsWith",
      value,
      ...errorUtil.errToObj(message)
    });
  }
  min(minLength, message) {
    return this._addCheck({
      kind: "min",
      value: minLength,
      ...errorUtil.errToObj(message)
    });
  }
  max(maxLength, message) {
    return this._addCheck({
      kind: "max",
      value: maxLength,
      ...errorUtil.errToObj(message)
    });
  }
  length(len, message) {
    return this._addCheck({
      kind: "length",
      value: len,
      ...errorUtil.errToObj(message)
    });
  }
  /**
   * Equivalent to `.min(1)`
   */
  nonempty(message) {
    return this.min(1, errorUtil.errToObj(message));
  }
  trim() {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "trim" }]
    });
  }
  toLowerCase() {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toLowerCase" }]
    });
  }
  toUpperCase() {
    return new _ZodString({
      ...this._def,
      checks: [...this._def.checks, { kind: "toUpperCase" }]
    });
  }
  get isDatetime() {
    return !!this._def.checks.find((ch) => ch.kind === "datetime");
  }
  get isDate() {
    return !!this._def.checks.find((ch) => ch.kind === "date");
  }
  get isTime() {
    return !!this._def.checks.find((ch) => ch.kind === "time");
  }
  get isDuration() {
    return !!this._def.checks.find((ch) => ch.kind === "duration");
  }
  get isEmail() {
    return !!this._def.checks.find((ch) => ch.kind === "email");
  }
  get isURL() {
    return !!this._def.checks.find((ch) => ch.kind === "url");
  }
  get isEmoji() {
    return !!this._def.checks.find((ch) => ch.kind === "emoji");
  }
  get isUUID() {
    return !!this._def.checks.find((ch) => ch.kind === "uuid");
  }
  get isNANOID() {
    return !!this._def.checks.find((ch) => ch.kind === "nanoid");
  }
  get isCUID() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid");
  }
  get isCUID2() {
    return !!this._def.checks.find((ch) => ch.kind === "cuid2");
  }
  get isULID() {
    return !!this._def.checks.find((ch) => ch.kind === "ulid");
  }
  get isIP() {
    return !!this._def.checks.find((ch) => ch.kind === "ip");
  }
  get isCIDR() {
    return !!this._def.checks.find((ch) => ch.kind === "cidr");
  }
  get isBase64() {
    return !!this._def.checks.find((ch) => ch.kind === "base64");
  }
  get isBase64url() {
    return !!this._def.checks.find((ch) => ch.kind === "base64url");
  }
  get minLength() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxLength() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
};
ZodString.create = (params) => {
  return new ZodString({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodString,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};
function floatSafeRemainder(val, step) {
  const valDecCount = (val.toString().split(".")[1] || "").length;
  const stepDecCount = (step.toString().split(".")[1] || "").length;
  const decCount = valDecCount > stepDecCount ? valDecCount : stepDecCount;
  const valInt = Number.parseInt(val.toFixed(decCount).replace(".", ""));
  const stepInt = Number.parseInt(step.toFixed(decCount).replace(".", ""));
  return valInt % stepInt / 10 ** decCount;
}
__name(floatSafeRemainder, "floatSafeRemainder");
var ZodNumber = class _ZodNumber extends ZodType {
  static {
    __name(this, "ZodNumber");
  }
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
    this.step = this.multipleOf;
  }
  _parse(input) {
    if (this._def.coerce) {
      input.data = Number(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.number) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.number,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    let ctx = void 0;
    const status = new ParseStatus();
    for (const check of this._def.checks) {
      if (check.kind === "int") {
        if (!util.isInteger(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.invalid_type,
            expected: "integer",
            received: "float",
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            minimum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            maximum: check.value,
            type: "number",
            inclusive: check.inclusive,
            exact: false,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (floatSafeRemainder(input.data, check.value) !== 0) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "finite") {
        if (!Number.isFinite(input.data)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_finite,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new _ZodNumber({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new _ZodNumber({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  int(message) {
    return this._addCheck({
      kind: "int",
      message: errorUtil.toString(message)
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: 0,
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  finite(message) {
    return this._addCheck({
      kind: "finite",
      message: errorUtil.toString(message)
    });
  }
  safe(message) {
    return this._addCheck({
      kind: "min",
      inclusive: true,
      value: Number.MIN_SAFE_INTEGER,
      message: errorUtil.toString(message)
    })._addCheck({
      kind: "max",
      inclusive: true,
      value: Number.MAX_SAFE_INTEGER,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
  get isInt() {
    return !!this._def.checks.find((ch) => ch.kind === "int" || ch.kind === "multipleOf" && util.isInteger(ch.value));
  }
  get isFinite() {
    let max = null;
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "finite" || ch.kind === "int" || ch.kind === "multipleOf") {
        return true;
      } else if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      } else if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return Number.isFinite(min) && Number.isFinite(max);
  }
};
ZodNumber.create = (params) => {
  return new ZodNumber({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodNumber,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};
var ZodBigInt = class _ZodBigInt extends ZodType {
  static {
    __name(this, "ZodBigInt");
  }
  constructor() {
    super(...arguments);
    this.min = this.gte;
    this.max = this.lte;
  }
  _parse(input) {
    if (this._def.coerce) {
      try {
        input.data = BigInt(input.data);
      } catch {
        return this._getInvalidInput(input);
      }
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.bigint) {
      return this._getInvalidInput(input);
    }
    let ctx = void 0;
    const status = new ParseStatus();
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        const tooSmall = check.inclusive ? input.data < check.value : input.data <= check.value;
        if (tooSmall) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            type: "bigint",
            minimum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        const tooBig = check.inclusive ? input.data > check.value : input.data >= check.value;
        if (tooBig) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            type: "bigint",
            maximum: check.value,
            inclusive: check.inclusive,
            message: check.message
          });
          status.dirty();
        }
      } else if (check.kind === "multipleOf") {
        if (input.data % check.value !== BigInt(0)) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.not_multiple_of,
            multipleOf: check.value,
            message: check.message
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return { status: status.value, value: input.data };
  }
  _getInvalidInput(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.bigint,
      received: ctx.parsedType
    });
    return INVALID;
  }
  gte(value, message) {
    return this.setLimit("min", value, true, errorUtil.toString(message));
  }
  gt(value, message) {
    return this.setLimit("min", value, false, errorUtil.toString(message));
  }
  lte(value, message) {
    return this.setLimit("max", value, true, errorUtil.toString(message));
  }
  lt(value, message) {
    return this.setLimit("max", value, false, errorUtil.toString(message));
  }
  setLimit(kind, value, inclusive, message) {
    return new _ZodBigInt({
      ...this._def,
      checks: [
        ...this._def.checks,
        {
          kind,
          value,
          inclusive,
          message: errorUtil.toString(message)
        }
      ]
    });
  }
  _addCheck(check) {
    return new _ZodBigInt({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  positive(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  negative(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: false,
      message: errorUtil.toString(message)
    });
  }
  nonpositive(message) {
    return this._addCheck({
      kind: "max",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  nonnegative(message) {
    return this._addCheck({
      kind: "min",
      value: BigInt(0),
      inclusive: true,
      message: errorUtil.toString(message)
    });
  }
  multipleOf(value, message) {
    return this._addCheck({
      kind: "multipleOf",
      value,
      message: errorUtil.toString(message)
    });
  }
  get minValue() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min;
  }
  get maxValue() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max;
  }
};
ZodBigInt.create = (params) => {
  return new ZodBigInt({
    checks: [],
    typeName: ZodFirstPartyTypeKind.ZodBigInt,
    coerce: params?.coerce ?? false,
    ...processCreateParams(params)
  });
};
var ZodBoolean = class extends ZodType {
  static {
    __name(this, "ZodBoolean");
  }
  _parse(input) {
    if (this._def.coerce) {
      input.data = Boolean(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.boolean) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.boolean,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodBoolean.create = (params) => {
  return new ZodBoolean({
    typeName: ZodFirstPartyTypeKind.ZodBoolean,
    coerce: params?.coerce || false,
    ...processCreateParams(params)
  });
};
var ZodDate = class _ZodDate extends ZodType {
  static {
    __name(this, "ZodDate");
  }
  _parse(input) {
    if (this._def.coerce) {
      input.data = new Date(input.data);
    }
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.date) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.date,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    if (Number.isNaN(input.data.getTime())) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_date
      });
      return INVALID;
    }
    const status = new ParseStatus();
    let ctx = void 0;
    for (const check of this._def.checks) {
      if (check.kind === "min") {
        if (input.data.getTime() < check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_small,
            message: check.message,
            inclusive: true,
            exact: false,
            minimum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else if (check.kind === "max") {
        if (input.data.getTime() > check.value) {
          ctx = this._getOrReturnCtx(input, ctx);
          addIssueToContext(ctx, {
            code: ZodIssueCode.too_big,
            message: check.message,
            inclusive: true,
            exact: false,
            maximum: check.value,
            type: "date"
          });
          status.dirty();
        }
      } else {
        util.assertNever(check);
      }
    }
    return {
      status: status.value,
      value: new Date(input.data.getTime())
    };
  }
  _addCheck(check) {
    return new _ZodDate({
      ...this._def,
      checks: [...this._def.checks, check]
    });
  }
  min(minDate, message) {
    return this._addCheck({
      kind: "min",
      value: minDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  max(maxDate, message) {
    return this._addCheck({
      kind: "max",
      value: maxDate.getTime(),
      message: errorUtil.toString(message)
    });
  }
  get minDate() {
    let min = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "min") {
        if (min === null || ch.value > min)
          min = ch.value;
      }
    }
    return min != null ? new Date(min) : null;
  }
  get maxDate() {
    let max = null;
    for (const ch of this._def.checks) {
      if (ch.kind === "max") {
        if (max === null || ch.value < max)
          max = ch.value;
      }
    }
    return max != null ? new Date(max) : null;
  }
};
ZodDate.create = (params) => {
  return new ZodDate({
    checks: [],
    coerce: params?.coerce || false,
    typeName: ZodFirstPartyTypeKind.ZodDate,
    ...processCreateParams(params)
  });
};
var ZodSymbol = class extends ZodType {
  static {
    __name(this, "ZodSymbol");
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.symbol) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.symbol,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodSymbol.create = (params) => {
  return new ZodSymbol({
    typeName: ZodFirstPartyTypeKind.ZodSymbol,
    ...processCreateParams(params)
  });
};
var ZodUndefined = class extends ZodType {
  static {
    __name(this, "ZodUndefined");
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.undefined,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodUndefined.create = (params) => {
  return new ZodUndefined({
    typeName: ZodFirstPartyTypeKind.ZodUndefined,
    ...processCreateParams(params)
  });
};
var ZodNull = class extends ZodType {
  static {
    __name(this, "ZodNull");
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.null) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.null,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodNull.create = (params) => {
  return new ZodNull({
    typeName: ZodFirstPartyTypeKind.ZodNull,
    ...processCreateParams(params)
  });
};
var ZodAny = class extends ZodType {
  static {
    __name(this, "ZodAny");
  }
  constructor() {
    super(...arguments);
    this._any = true;
  }
  _parse(input) {
    return OK(input.data);
  }
};
ZodAny.create = (params) => {
  return new ZodAny({
    typeName: ZodFirstPartyTypeKind.ZodAny,
    ...processCreateParams(params)
  });
};
var ZodUnknown = class extends ZodType {
  static {
    __name(this, "ZodUnknown");
  }
  constructor() {
    super(...arguments);
    this._unknown = true;
  }
  _parse(input) {
    return OK(input.data);
  }
};
ZodUnknown.create = (params) => {
  return new ZodUnknown({
    typeName: ZodFirstPartyTypeKind.ZodUnknown,
    ...processCreateParams(params)
  });
};
var ZodNever = class extends ZodType {
  static {
    __name(this, "ZodNever");
  }
  _parse(input) {
    const ctx = this._getOrReturnCtx(input);
    addIssueToContext(ctx, {
      code: ZodIssueCode.invalid_type,
      expected: ZodParsedType.never,
      received: ctx.parsedType
    });
    return INVALID;
  }
};
ZodNever.create = (params) => {
  return new ZodNever({
    typeName: ZodFirstPartyTypeKind.ZodNever,
    ...processCreateParams(params)
  });
};
var ZodVoid = class extends ZodType {
  static {
    __name(this, "ZodVoid");
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.undefined) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.void,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return OK(input.data);
  }
};
ZodVoid.create = (params) => {
  return new ZodVoid({
    typeName: ZodFirstPartyTypeKind.ZodVoid,
    ...processCreateParams(params)
  });
};
var ZodArray = class _ZodArray extends ZodType {
  static {
    __name(this, "ZodArray");
  }
  _parse(input) {
    const { ctx, status } = this._processInputParams(input);
    const def = this._def;
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (def.exactLength !== null) {
      const tooBig = ctx.data.length > def.exactLength.value;
      const tooSmall = ctx.data.length < def.exactLength.value;
      if (tooBig || tooSmall) {
        addIssueToContext(ctx, {
          code: tooBig ? ZodIssueCode.too_big : ZodIssueCode.too_small,
          minimum: tooSmall ? def.exactLength.value : void 0,
          maximum: tooBig ? def.exactLength.value : void 0,
          type: "array",
          inclusive: true,
          exact: true,
          message: def.exactLength.message
        });
        status.dirty();
      }
    }
    if (def.minLength !== null) {
      if (ctx.data.length < def.minLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.minLength.message
        });
        status.dirty();
      }
    }
    if (def.maxLength !== null) {
      if (ctx.data.length > def.maxLength.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxLength.value,
          type: "array",
          inclusive: true,
          exact: false,
          message: def.maxLength.message
        });
        status.dirty();
      }
    }
    if (ctx.common.async) {
      return Promise.all([...ctx.data].map((item, i) => {
        return def.type._parseAsync(new ParseInputLazyPath(ctx, item, ctx.path, i));
      })).then((result2) => {
        return ParseStatus.mergeArray(status, result2);
      });
    }
    const result = [...ctx.data].map((item, i) => {
      return def.type._parseSync(new ParseInputLazyPath(ctx, item, ctx.path, i));
    });
    return ParseStatus.mergeArray(status, result);
  }
  get element() {
    return this._def.type;
  }
  min(minLength, message) {
    return new _ZodArray({
      ...this._def,
      minLength: { value: minLength, message: errorUtil.toString(message) }
    });
  }
  max(maxLength, message) {
    return new _ZodArray({
      ...this._def,
      maxLength: { value: maxLength, message: errorUtil.toString(message) }
    });
  }
  length(len, message) {
    return new _ZodArray({
      ...this._def,
      exactLength: { value: len, message: errorUtil.toString(message) }
    });
  }
  nonempty(message) {
    return this.min(1, message);
  }
};
ZodArray.create = (schema, params) => {
  return new ZodArray({
    type: schema,
    minLength: null,
    maxLength: null,
    exactLength: null,
    typeName: ZodFirstPartyTypeKind.ZodArray,
    ...processCreateParams(params)
  });
};
function deepPartialify(schema) {
  if (schema instanceof ZodObject) {
    const newShape = {};
    for (const key in schema.shape) {
      const fieldSchema = schema.shape[key];
      newShape[key] = ZodOptional.create(deepPartialify(fieldSchema));
    }
    return new ZodObject({
      ...schema._def,
      shape: /* @__PURE__ */ __name(() => newShape, "shape")
    });
  } else if (schema instanceof ZodArray) {
    return new ZodArray({
      ...schema._def,
      type: deepPartialify(schema.element)
    });
  } else if (schema instanceof ZodOptional) {
    return ZodOptional.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodNullable) {
    return ZodNullable.create(deepPartialify(schema.unwrap()));
  } else if (schema instanceof ZodTuple) {
    return ZodTuple.create(schema.items.map((item) => deepPartialify(item)));
  } else {
    return schema;
  }
}
__name(deepPartialify, "deepPartialify");
var ZodObject = class _ZodObject extends ZodType {
  static {
    __name(this, "ZodObject");
  }
  constructor() {
    super(...arguments);
    this._cached = null;
    this.nonstrict = this.passthrough;
    this.augment = this.extend;
  }
  _getCached() {
    if (this._cached !== null)
      return this._cached;
    const shape = this._def.shape();
    const keys = util.objectKeys(shape);
    this._cached = { shape, keys };
    return this._cached;
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.object) {
      const ctx2 = this._getOrReturnCtx(input);
      addIssueToContext(ctx2, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx2.parsedType
      });
      return INVALID;
    }
    const { status, ctx } = this._processInputParams(input);
    const { shape, keys: shapeKeys } = this._getCached();
    const extraKeys = [];
    if (!(this._def.catchall instanceof ZodNever && this._def.unknownKeys === "strip")) {
      for (const key in ctx.data) {
        if (!shapeKeys.includes(key)) {
          extraKeys.push(key);
        }
      }
    }
    const pairs = [];
    for (const key of shapeKeys) {
      const keyValidator = shape[key];
      const value = ctx.data[key];
      pairs.push({
        key: { status: "valid", value: key },
        value: keyValidator._parse(new ParseInputLazyPath(ctx, value, ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (this._def.catchall instanceof ZodNever) {
      const unknownKeys = this._def.unknownKeys;
      if (unknownKeys === "passthrough") {
        for (const key of extraKeys) {
          pairs.push({
            key: { status: "valid", value: key },
            value: { status: "valid", value: ctx.data[key] }
          });
        }
      } else if (unknownKeys === "strict") {
        if (extraKeys.length > 0) {
          addIssueToContext(ctx, {
            code: ZodIssueCode.unrecognized_keys,
            keys: extraKeys
          });
          status.dirty();
        }
      } else if (unknownKeys === "strip") {
      } else {
        throw new Error(`Internal ZodObject error: invalid unknownKeys value.`);
      }
    } else {
      const catchall = this._def.catchall;
      for (const key of extraKeys) {
        const value = ctx.data[key];
        pairs.push({
          key: { status: "valid", value: key },
          value: catchall._parse(
            new ParseInputLazyPath(ctx, value, ctx.path, key)
            //, ctx.child(key), value, getParsedType(value)
          ),
          alwaysSet: key in ctx.data
        });
      }
    }
    if (ctx.common.async) {
      return Promise.resolve().then(async () => {
        const syncPairs = [];
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          syncPairs.push({
            key,
            value,
            alwaysSet: pair.alwaysSet
          });
        }
        return syncPairs;
      }).then((syncPairs) => {
        return ParseStatus.mergeObjectSync(status, syncPairs);
      });
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get shape() {
    return this._def.shape();
  }
  strict(message) {
    errorUtil.errToObj;
    return new _ZodObject({
      ...this._def,
      unknownKeys: "strict",
      ...message !== void 0 ? {
        errorMap: /* @__PURE__ */ __name((issue, ctx) => {
          const defaultError = this._def.errorMap?.(issue, ctx).message ?? ctx.defaultError;
          if (issue.code === "unrecognized_keys")
            return {
              message: errorUtil.errToObj(message).message ?? defaultError
            };
          return {
            message: defaultError
          };
        }, "errorMap")
      } : {}
    });
  }
  strip() {
    return new _ZodObject({
      ...this._def,
      unknownKeys: "strip"
    });
  }
  passthrough() {
    return new _ZodObject({
      ...this._def,
      unknownKeys: "passthrough"
    });
  }
  // const AugmentFactory =
  //   <Def extends ZodObjectDef>(def: Def) =>
  //   <Augmentation extends ZodRawShape>(
  //     augmentation: Augmentation
  //   ): ZodObject<
  //     extendShape<ReturnType<Def["shape"]>, Augmentation>,
  //     Def["unknownKeys"],
  //     Def["catchall"]
  //   > => {
  //     return new ZodObject({
  //       ...def,
  //       shape: () => ({
  //         ...def.shape(),
  //         ...augmentation,
  //       }),
  //     }) as any;
  //   };
  extend(augmentation) {
    return new _ZodObject({
      ...this._def,
      shape: /* @__PURE__ */ __name(() => ({
        ...this._def.shape(),
        ...augmentation
      }), "shape")
    });
  }
  /**
   * Prior to zod@1.0.12 there was a bug in the
   * inferred type of merged objects. Please
   * upgrade if you are experiencing issues.
   */
  merge(merging) {
    const merged = new _ZodObject({
      unknownKeys: merging._def.unknownKeys,
      catchall: merging._def.catchall,
      shape: /* @__PURE__ */ __name(() => ({
        ...this._def.shape(),
        ...merging._def.shape()
      }), "shape"),
      typeName: ZodFirstPartyTypeKind.ZodObject
    });
    return merged;
  }
  // merge<
  //   Incoming extends AnyZodObject,
  //   Augmentation extends Incoming["shape"],
  //   NewOutput extends {
  //     [k in keyof Augmentation | keyof Output]: k extends keyof Augmentation
  //       ? Augmentation[k]["_output"]
  //       : k extends keyof Output
  //       ? Output[k]
  //       : never;
  //   },
  //   NewInput extends {
  //     [k in keyof Augmentation | keyof Input]: k extends keyof Augmentation
  //       ? Augmentation[k]["_input"]
  //       : k extends keyof Input
  //       ? Input[k]
  //       : never;
  //   }
  // >(
  //   merging: Incoming
  // ): ZodObject<
  //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
  //   Incoming["_def"]["unknownKeys"],
  //   Incoming["_def"]["catchall"],
  //   NewOutput,
  //   NewInput
  // > {
  //   const merged: any = new ZodObject({
  //     unknownKeys: merging._def.unknownKeys,
  //     catchall: merging._def.catchall,
  //     shape: () =>
  //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
  //     typeName: ZodFirstPartyTypeKind.ZodObject,
  //   }) as any;
  //   return merged;
  // }
  setKey(key, schema) {
    return this.augment({ [key]: schema });
  }
  // merge<Incoming extends AnyZodObject>(
  //   merging: Incoming
  // ): //ZodObject<T & Incoming["_shape"], UnknownKeys, Catchall> = (merging) => {
  // ZodObject<
  //   extendShape<T, ReturnType<Incoming["_def"]["shape"]>>,
  //   Incoming["_def"]["unknownKeys"],
  //   Incoming["_def"]["catchall"]
  // > {
  //   // const mergedShape = objectUtil.mergeShapes(
  //   //   this._def.shape(),
  //   //   merging._def.shape()
  //   // );
  //   const merged: any = new ZodObject({
  //     unknownKeys: merging._def.unknownKeys,
  //     catchall: merging._def.catchall,
  //     shape: () =>
  //       objectUtil.mergeShapes(this._def.shape(), merging._def.shape()),
  //     typeName: ZodFirstPartyTypeKind.ZodObject,
  //   }) as any;
  //   return merged;
  // }
  catchall(index) {
    return new _ZodObject({
      ...this._def,
      catchall: index
    });
  }
  pick(mask) {
    const shape = {};
    for (const key of util.objectKeys(mask)) {
      if (mask[key] && this.shape[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: /* @__PURE__ */ __name(() => shape, "shape")
    });
  }
  omit(mask) {
    const shape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (!mask[key]) {
        shape[key] = this.shape[key];
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: /* @__PURE__ */ __name(() => shape, "shape")
    });
  }
  /**
   * @deprecated
   */
  deepPartial() {
    return deepPartialify(this);
  }
  partial(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      const fieldSchema = this.shape[key];
      if (mask && !mask[key]) {
        newShape[key] = fieldSchema;
      } else {
        newShape[key] = fieldSchema.optional();
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: /* @__PURE__ */ __name(() => newShape, "shape")
    });
  }
  required(mask) {
    const newShape = {};
    for (const key of util.objectKeys(this.shape)) {
      if (mask && !mask[key]) {
        newShape[key] = this.shape[key];
      } else {
        const fieldSchema = this.shape[key];
        let newField = fieldSchema;
        while (newField instanceof ZodOptional) {
          newField = newField._def.innerType;
        }
        newShape[key] = newField;
      }
    }
    return new _ZodObject({
      ...this._def,
      shape: /* @__PURE__ */ __name(() => newShape, "shape")
    });
  }
  keyof() {
    return createZodEnum(util.objectKeys(this.shape));
  }
};
ZodObject.create = (shape, params) => {
  return new ZodObject({
    shape: /* @__PURE__ */ __name(() => shape, "shape"),
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.strictCreate = (shape, params) => {
  return new ZodObject({
    shape: /* @__PURE__ */ __name(() => shape, "shape"),
    unknownKeys: "strict",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
ZodObject.lazycreate = (shape, params) => {
  return new ZodObject({
    shape,
    unknownKeys: "strip",
    catchall: ZodNever.create(),
    typeName: ZodFirstPartyTypeKind.ZodObject,
    ...processCreateParams(params)
  });
};
var ZodUnion = class extends ZodType {
  static {
    __name(this, "ZodUnion");
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const options = this._def.options;
    function handleResults(results) {
      for (const result of results) {
        if (result.result.status === "valid") {
          return result.result;
        }
      }
      for (const result of results) {
        if (result.result.status === "dirty") {
          ctx.common.issues.push(...result.ctx.common.issues);
          return result.result;
        }
      }
      const unionErrors = results.map((result) => new ZodError(result.ctx.common.issues));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
    __name(handleResults, "handleResults");
    if (ctx.common.async) {
      return Promise.all(options.map(async (option) => {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        return {
          result: await option._parseAsync({
            data: ctx.data,
            path: ctx.path,
            parent: childCtx
          }),
          ctx: childCtx
        };
      })).then(handleResults);
    } else {
      let dirty = void 0;
      const issues = [];
      for (const option of options) {
        const childCtx = {
          ...ctx,
          common: {
            ...ctx.common,
            issues: []
          },
          parent: null
        };
        const result = option._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: childCtx
        });
        if (result.status === "valid") {
          return result;
        } else if (result.status === "dirty" && !dirty) {
          dirty = { result, ctx: childCtx };
        }
        if (childCtx.common.issues.length) {
          issues.push(childCtx.common.issues);
        }
      }
      if (dirty) {
        ctx.common.issues.push(...dirty.ctx.common.issues);
        return dirty.result;
      }
      const unionErrors = issues.map((issues2) => new ZodError(issues2));
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union,
        unionErrors
      });
      return INVALID;
    }
  }
  get options() {
    return this._def.options;
  }
};
ZodUnion.create = (types, params) => {
  return new ZodUnion({
    options: types,
    typeName: ZodFirstPartyTypeKind.ZodUnion,
    ...processCreateParams(params)
  });
};
var getDiscriminator = /* @__PURE__ */ __name((type) => {
  if (type instanceof ZodLazy) {
    return getDiscriminator(type.schema);
  } else if (type instanceof ZodEffects) {
    return getDiscriminator(type.innerType());
  } else if (type instanceof ZodLiteral) {
    return [type.value];
  } else if (type instanceof ZodEnum) {
    return type.options;
  } else if (type instanceof ZodNativeEnum) {
    return util.objectValues(type.enum);
  } else if (type instanceof ZodDefault) {
    return getDiscriminator(type._def.innerType);
  } else if (type instanceof ZodUndefined) {
    return [void 0];
  } else if (type instanceof ZodNull) {
    return [null];
  } else if (type instanceof ZodOptional) {
    return [void 0, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodNullable) {
    return [null, ...getDiscriminator(type.unwrap())];
  } else if (type instanceof ZodBranded) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodReadonly) {
    return getDiscriminator(type.unwrap());
  } else if (type instanceof ZodCatch) {
    return getDiscriminator(type._def.innerType);
  } else {
    return [];
  }
}, "getDiscriminator");
var ZodDiscriminatedUnion = class _ZodDiscriminatedUnion extends ZodType {
  static {
    __name(this, "ZodDiscriminatedUnion");
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const discriminator = this.discriminator;
    const discriminatorValue = ctx.data[discriminator];
    const option = this.optionsMap.get(discriminatorValue);
    if (!option) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_union_discriminator,
        options: Array.from(this.optionsMap.keys()),
        path: [discriminator]
      });
      return INVALID;
    }
    if (ctx.common.async) {
      return option._parseAsync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    } else {
      return option._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
    }
  }
  get discriminator() {
    return this._def.discriminator;
  }
  get options() {
    return this._def.options;
  }
  get optionsMap() {
    return this._def.optionsMap;
  }
  /**
   * The constructor of the discriminated union schema. Its behaviour is very similar to that of the normal z.union() constructor.
   * However, it only allows a union of objects, all of which need to share a discriminator property. This property must
   * have a different value for each object in the union.
   * @param discriminator the name of the discriminator property
   * @param types an array of object schemas
   * @param params
   */
  static create(discriminator, options, params) {
    const optionsMap = /* @__PURE__ */ new Map();
    for (const type of options) {
      const discriminatorValues = getDiscriminator(type.shape[discriminator]);
      if (!discriminatorValues.length) {
        throw new Error(`A discriminator value for key \`${discriminator}\` could not be extracted from all schema options`);
      }
      for (const value of discriminatorValues) {
        if (optionsMap.has(value)) {
          throw new Error(`Discriminator property ${String(discriminator)} has duplicate value ${String(value)}`);
        }
        optionsMap.set(value, type);
      }
    }
    return new _ZodDiscriminatedUnion({
      typeName: ZodFirstPartyTypeKind.ZodDiscriminatedUnion,
      discriminator,
      options,
      optionsMap,
      ...processCreateParams(params)
    });
  }
};
function mergeValues(a, b) {
  const aType = getParsedType(a);
  const bType = getParsedType(b);
  if (a === b) {
    return { valid: true, data: a };
  } else if (aType === ZodParsedType.object && bType === ZodParsedType.object) {
    const bKeys = util.objectKeys(b);
    const sharedKeys = util.objectKeys(a).filter((key) => bKeys.indexOf(key) !== -1);
    const newObj = { ...a, ...b };
    for (const key of sharedKeys) {
      const sharedValue = mergeValues(a[key], b[key]);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newObj[key] = sharedValue.data;
    }
    return { valid: true, data: newObj };
  } else if (aType === ZodParsedType.array && bType === ZodParsedType.array) {
    if (a.length !== b.length) {
      return { valid: false };
    }
    const newArray = [];
    for (let index = 0; index < a.length; index++) {
      const itemA = a[index];
      const itemB = b[index];
      const sharedValue = mergeValues(itemA, itemB);
      if (!sharedValue.valid) {
        return { valid: false };
      }
      newArray.push(sharedValue.data);
    }
    return { valid: true, data: newArray };
  } else if (aType === ZodParsedType.date && bType === ZodParsedType.date && +a === +b) {
    return { valid: true, data: a };
  } else {
    return { valid: false };
  }
}
__name(mergeValues, "mergeValues");
var ZodIntersection = class extends ZodType {
  static {
    __name(this, "ZodIntersection");
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const handleParsed = /* @__PURE__ */ __name((parsedLeft, parsedRight) => {
      if (isAborted(parsedLeft) || isAborted(parsedRight)) {
        return INVALID;
      }
      const merged = mergeValues(parsedLeft.value, parsedRight.value);
      if (!merged.valid) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.invalid_intersection_types
        });
        return INVALID;
      }
      if (isDirty(parsedLeft) || isDirty(parsedRight)) {
        status.dirty();
      }
      return { status: status.value, value: merged.data };
    }, "handleParsed");
    if (ctx.common.async) {
      return Promise.all([
        this._def.left._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        }),
        this._def.right._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        })
      ]).then(([left, right]) => handleParsed(left, right));
    } else {
      return handleParsed(this._def.left._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }), this._def.right._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      }));
    }
  }
};
ZodIntersection.create = (left, right, params) => {
  return new ZodIntersection({
    left,
    right,
    typeName: ZodFirstPartyTypeKind.ZodIntersection,
    ...processCreateParams(params)
  });
};
var ZodTuple = class _ZodTuple extends ZodType {
  static {
    __name(this, "ZodTuple");
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.array) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.array,
        received: ctx.parsedType
      });
      return INVALID;
    }
    if (ctx.data.length < this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_small,
        minimum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      return INVALID;
    }
    const rest = this._def.rest;
    if (!rest && ctx.data.length > this._def.items.length) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.too_big,
        maximum: this._def.items.length,
        inclusive: true,
        exact: false,
        type: "array"
      });
      status.dirty();
    }
    const items = [...ctx.data].map((item, itemIndex) => {
      const schema = this._def.items[itemIndex] || this._def.rest;
      if (!schema)
        return null;
      return schema._parse(new ParseInputLazyPath(ctx, item, ctx.path, itemIndex));
    }).filter((x) => !!x);
    if (ctx.common.async) {
      return Promise.all(items).then((results) => {
        return ParseStatus.mergeArray(status, results);
      });
    } else {
      return ParseStatus.mergeArray(status, items);
    }
  }
  get items() {
    return this._def.items;
  }
  rest(rest) {
    return new _ZodTuple({
      ...this._def,
      rest
    });
  }
};
ZodTuple.create = (schemas, params) => {
  if (!Array.isArray(schemas)) {
    throw new Error("You must pass an array of schemas to z.tuple([ ... ])");
  }
  return new ZodTuple({
    items: schemas,
    typeName: ZodFirstPartyTypeKind.ZodTuple,
    rest: null,
    ...processCreateParams(params)
  });
};
var ZodRecord = class _ZodRecord extends ZodType {
  static {
    __name(this, "ZodRecord");
  }
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.object) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.object,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const pairs = [];
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    for (const key in ctx.data) {
      pairs.push({
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, key)),
        value: valueType._parse(new ParseInputLazyPath(ctx, ctx.data[key], ctx.path, key)),
        alwaysSet: key in ctx.data
      });
    }
    if (ctx.common.async) {
      return ParseStatus.mergeObjectAsync(status, pairs);
    } else {
      return ParseStatus.mergeObjectSync(status, pairs);
    }
  }
  get element() {
    return this._def.valueType;
  }
  static create(first, second, third) {
    if (second instanceof ZodType) {
      return new _ZodRecord({
        keyType: first,
        valueType: second,
        typeName: ZodFirstPartyTypeKind.ZodRecord,
        ...processCreateParams(third)
      });
    }
    return new _ZodRecord({
      keyType: ZodString.create(),
      valueType: first,
      typeName: ZodFirstPartyTypeKind.ZodRecord,
      ...processCreateParams(second)
    });
  }
};
var ZodMap = class extends ZodType {
  static {
    __name(this, "ZodMap");
  }
  get keySchema() {
    return this._def.keyType;
  }
  get valueSchema() {
    return this._def.valueType;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.map) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.map,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const keyType = this._def.keyType;
    const valueType = this._def.valueType;
    const pairs = [...ctx.data.entries()].map(([key, value], index) => {
      return {
        key: keyType._parse(new ParseInputLazyPath(ctx, key, ctx.path, [index, "key"])),
        value: valueType._parse(new ParseInputLazyPath(ctx, value, ctx.path, [index, "value"]))
      };
    });
    if (ctx.common.async) {
      const finalMap = /* @__PURE__ */ new Map();
      return Promise.resolve().then(async () => {
        for (const pair of pairs) {
          const key = await pair.key;
          const value = await pair.value;
          if (key.status === "aborted" || value.status === "aborted") {
            return INVALID;
          }
          if (key.status === "dirty" || value.status === "dirty") {
            status.dirty();
          }
          finalMap.set(key.value, value.value);
        }
        return { status: status.value, value: finalMap };
      });
    } else {
      const finalMap = /* @__PURE__ */ new Map();
      for (const pair of pairs) {
        const key = pair.key;
        const value = pair.value;
        if (key.status === "aborted" || value.status === "aborted") {
          return INVALID;
        }
        if (key.status === "dirty" || value.status === "dirty") {
          status.dirty();
        }
        finalMap.set(key.value, value.value);
      }
      return { status: status.value, value: finalMap };
    }
  }
};
ZodMap.create = (keyType, valueType, params) => {
  return new ZodMap({
    valueType,
    keyType,
    typeName: ZodFirstPartyTypeKind.ZodMap,
    ...processCreateParams(params)
  });
};
var ZodSet = class _ZodSet extends ZodType {
  static {
    __name(this, "ZodSet");
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.set) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.set,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const def = this._def;
    if (def.minSize !== null) {
      if (ctx.data.size < def.minSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_small,
          minimum: def.minSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.minSize.message
        });
        status.dirty();
      }
    }
    if (def.maxSize !== null) {
      if (ctx.data.size > def.maxSize.value) {
        addIssueToContext(ctx, {
          code: ZodIssueCode.too_big,
          maximum: def.maxSize.value,
          type: "set",
          inclusive: true,
          exact: false,
          message: def.maxSize.message
        });
        status.dirty();
      }
    }
    const valueType = this._def.valueType;
    function finalizeSet(elements2) {
      const parsedSet = /* @__PURE__ */ new Set();
      for (const element of elements2) {
        if (element.status === "aborted")
          return INVALID;
        if (element.status === "dirty")
          status.dirty();
        parsedSet.add(element.value);
      }
      return { status: status.value, value: parsedSet };
    }
    __name(finalizeSet, "finalizeSet");
    const elements = [...ctx.data.values()].map((item, i) => valueType._parse(new ParseInputLazyPath(ctx, item, ctx.path, i)));
    if (ctx.common.async) {
      return Promise.all(elements).then((elements2) => finalizeSet(elements2));
    } else {
      return finalizeSet(elements);
    }
  }
  min(minSize, message) {
    return new _ZodSet({
      ...this._def,
      minSize: { value: minSize, message: errorUtil.toString(message) }
    });
  }
  max(maxSize, message) {
    return new _ZodSet({
      ...this._def,
      maxSize: { value: maxSize, message: errorUtil.toString(message) }
    });
  }
  size(size, message) {
    return this.min(size, message).max(size, message);
  }
  nonempty(message) {
    return this.min(1, message);
  }
};
ZodSet.create = (valueType, params) => {
  return new ZodSet({
    valueType,
    minSize: null,
    maxSize: null,
    typeName: ZodFirstPartyTypeKind.ZodSet,
    ...processCreateParams(params)
  });
};
var ZodFunction = class _ZodFunction extends ZodType {
  static {
    __name(this, "ZodFunction");
  }
  constructor() {
    super(...arguments);
    this.validate = this.implement;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.function) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.function,
        received: ctx.parsedType
      });
      return INVALID;
    }
    function makeArgsIssue(args, error) {
      return makeIssue({
        data: args,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_arguments,
          argumentsError: error
        }
      });
    }
    __name(makeArgsIssue, "makeArgsIssue");
    function makeReturnsIssue(returns, error) {
      return makeIssue({
        data: returns,
        path: ctx.path,
        errorMaps: [ctx.common.contextualErrorMap, ctx.schemaErrorMap, getErrorMap(), en_default].filter((x) => !!x),
        issueData: {
          code: ZodIssueCode.invalid_return_type,
          returnTypeError: error
        }
      });
    }
    __name(makeReturnsIssue, "makeReturnsIssue");
    const params = { errorMap: ctx.common.contextualErrorMap };
    const fn = ctx.data;
    if (this._def.returns instanceof ZodPromise) {
      const me = this;
      return OK(async function(...args) {
        const error = new ZodError([]);
        const parsedArgs = await me._def.args.parseAsync(args, params).catch((e) => {
          error.addIssue(makeArgsIssue(args, e));
          throw error;
        });
        const result = await Reflect.apply(fn, this, parsedArgs);
        const parsedReturns = await me._def.returns._def.type.parseAsync(result, params).catch((e) => {
          error.addIssue(makeReturnsIssue(result, e));
          throw error;
        });
        return parsedReturns;
      });
    } else {
      const me = this;
      return OK(function(...args) {
        const parsedArgs = me._def.args.safeParse(args, params);
        if (!parsedArgs.success) {
          throw new ZodError([makeArgsIssue(args, parsedArgs.error)]);
        }
        const result = Reflect.apply(fn, this, parsedArgs.data);
        const parsedReturns = me._def.returns.safeParse(result, params);
        if (!parsedReturns.success) {
          throw new ZodError([makeReturnsIssue(result, parsedReturns.error)]);
        }
        return parsedReturns.data;
      });
    }
  }
  parameters() {
    return this._def.args;
  }
  returnType() {
    return this._def.returns;
  }
  args(...items) {
    return new _ZodFunction({
      ...this._def,
      args: ZodTuple.create(items).rest(ZodUnknown.create())
    });
  }
  returns(returnType) {
    return new _ZodFunction({
      ...this._def,
      returns: returnType
    });
  }
  implement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  strictImplement(func) {
    const validatedFunc = this.parse(func);
    return validatedFunc;
  }
  static create(args, returns, params) {
    return new _ZodFunction({
      args: args ? args : ZodTuple.create([]).rest(ZodUnknown.create()),
      returns: returns || ZodUnknown.create(),
      typeName: ZodFirstPartyTypeKind.ZodFunction,
      ...processCreateParams(params)
    });
  }
};
var ZodLazy = class extends ZodType {
  static {
    __name(this, "ZodLazy");
  }
  get schema() {
    return this._def.getter();
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const lazySchema = this._def.getter();
    return lazySchema._parse({ data: ctx.data, path: ctx.path, parent: ctx });
  }
};
ZodLazy.create = (getter, params) => {
  return new ZodLazy({
    getter,
    typeName: ZodFirstPartyTypeKind.ZodLazy,
    ...processCreateParams(params)
  });
};
var ZodLiteral = class extends ZodType {
  static {
    __name(this, "ZodLiteral");
  }
  _parse(input) {
    if (input.data !== this._def.value) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_literal,
        expected: this._def.value
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
  get value() {
    return this._def.value;
  }
};
ZodLiteral.create = (value, params) => {
  return new ZodLiteral({
    value,
    typeName: ZodFirstPartyTypeKind.ZodLiteral,
    ...processCreateParams(params)
  });
};
function createZodEnum(values, params) {
  return new ZodEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodEnum,
    ...processCreateParams(params)
  });
}
__name(createZodEnum, "createZodEnum");
var ZodEnum = class _ZodEnum extends ZodType {
  static {
    __name(this, "ZodEnum");
  }
  _parse(input) {
    if (typeof input.data !== "string") {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(this._def.values);
    }
    if (!this._cache.has(input.data)) {
      const ctx = this._getOrReturnCtx(input);
      const expectedValues = this._def.values;
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get options() {
    return this._def.values;
  }
  get enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Values() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  get Enum() {
    const enumValues = {};
    for (const val of this._def.values) {
      enumValues[val] = val;
    }
    return enumValues;
  }
  extract(values, newDef = this._def) {
    return _ZodEnum.create(values, {
      ...this._def,
      ...newDef
    });
  }
  exclude(values, newDef = this._def) {
    return _ZodEnum.create(this.options.filter((opt) => !values.includes(opt)), {
      ...this._def,
      ...newDef
    });
  }
};
ZodEnum.create = createZodEnum;
var ZodNativeEnum = class extends ZodType {
  static {
    __name(this, "ZodNativeEnum");
  }
  _parse(input) {
    const nativeEnumValues = util.getValidEnumValues(this._def.values);
    const ctx = this._getOrReturnCtx(input);
    if (ctx.parsedType !== ZodParsedType.string && ctx.parsedType !== ZodParsedType.number) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        expected: util.joinValues(expectedValues),
        received: ctx.parsedType,
        code: ZodIssueCode.invalid_type
      });
      return INVALID;
    }
    if (!this._cache) {
      this._cache = new Set(util.getValidEnumValues(this._def.values));
    }
    if (!this._cache.has(input.data)) {
      const expectedValues = util.objectValues(nativeEnumValues);
      addIssueToContext(ctx, {
        received: ctx.data,
        code: ZodIssueCode.invalid_enum_value,
        options: expectedValues
      });
      return INVALID;
    }
    return OK(input.data);
  }
  get enum() {
    return this._def.values;
  }
};
ZodNativeEnum.create = (values, params) => {
  return new ZodNativeEnum({
    values,
    typeName: ZodFirstPartyTypeKind.ZodNativeEnum,
    ...processCreateParams(params)
  });
};
var ZodPromise = class extends ZodType {
  static {
    __name(this, "ZodPromise");
  }
  unwrap() {
    return this._def.type;
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    if (ctx.parsedType !== ZodParsedType.promise && ctx.common.async === false) {
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.promise,
        received: ctx.parsedType
      });
      return INVALID;
    }
    const promisified = ctx.parsedType === ZodParsedType.promise ? ctx.data : Promise.resolve(ctx.data);
    return OK(promisified.then((data) => {
      return this._def.type.parseAsync(data, {
        path: ctx.path,
        errorMap: ctx.common.contextualErrorMap
      });
    }));
  }
};
ZodPromise.create = (schema, params) => {
  return new ZodPromise({
    type: schema,
    typeName: ZodFirstPartyTypeKind.ZodPromise,
    ...processCreateParams(params)
  });
};
var ZodEffects = class extends ZodType {
  static {
    __name(this, "ZodEffects");
  }
  innerType() {
    return this._def.schema;
  }
  sourceType() {
    return this._def.schema._def.typeName === ZodFirstPartyTypeKind.ZodEffects ? this._def.schema.sourceType() : this._def.schema;
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    const effect = this._def.effect || null;
    const checkCtx = {
      addIssue: /* @__PURE__ */ __name((arg) => {
        addIssueToContext(ctx, arg);
        if (arg.fatal) {
          status.abort();
        } else {
          status.dirty();
        }
      }, "addIssue"),
      get path() {
        return ctx.path;
      }
    };
    checkCtx.addIssue = checkCtx.addIssue.bind(checkCtx);
    if (effect.type === "preprocess") {
      const processed = effect.transform(ctx.data, checkCtx);
      if (ctx.common.async) {
        return Promise.resolve(processed).then(async (processed2) => {
          if (status.value === "aborted")
            return INVALID;
          const result = await this._def.schema._parseAsync({
            data: processed2,
            path: ctx.path,
            parent: ctx
          });
          if (result.status === "aborted")
            return INVALID;
          if (result.status === "dirty")
            return DIRTY(result.value);
          if (status.value === "dirty")
            return DIRTY(result.value);
          return result;
        });
      } else {
        if (status.value === "aborted")
          return INVALID;
        const result = this._def.schema._parseSync({
          data: processed,
          path: ctx.path,
          parent: ctx
        });
        if (result.status === "aborted")
          return INVALID;
        if (result.status === "dirty")
          return DIRTY(result.value);
        if (status.value === "dirty")
          return DIRTY(result.value);
        return result;
      }
    }
    if (effect.type === "refinement") {
      const executeRefinement = /* @__PURE__ */ __name((acc) => {
        const result = effect.refinement(acc, checkCtx);
        if (ctx.common.async) {
          return Promise.resolve(result);
        }
        if (result instanceof Promise) {
          throw new Error("Async refinement encountered during synchronous parse operation. Use .parseAsync instead.");
        }
        return acc;
      }, "executeRefinement");
      if (ctx.common.async === false) {
        const inner = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inner.status === "aborted")
          return INVALID;
        if (inner.status === "dirty")
          status.dirty();
        executeRefinement(inner.value);
        return { status: status.value, value: inner.value };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((inner) => {
          if (inner.status === "aborted")
            return INVALID;
          if (inner.status === "dirty")
            status.dirty();
          return executeRefinement(inner.value).then(() => {
            return { status: status.value, value: inner.value };
          });
        });
      }
    }
    if (effect.type === "transform") {
      if (ctx.common.async === false) {
        const base = this._def.schema._parseSync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (!isValid(base))
          return INVALID;
        const result = effect.transform(base.value, checkCtx);
        if (result instanceof Promise) {
          throw new Error(`Asynchronous transform encountered during synchronous parse operation. Use .parseAsync instead.`);
        }
        return { status: status.value, value: result };
      } else {
        return this._def.schema._parseAsync({ data: ctx.data, path: ctx.path, parent: ctx }).then((base) => {
          if (!isValid(base))
            return INVALID;
          return Promise.resolve(effect.transform(base.value, checkCtx)).then((result) => ({
            status: status.value,
            value: result
          }));
        });
      }
    }
    util.assertNever(effect);
  }
};
ZodEffects.create = (schema, effect, params) => {
  return new ZodEffects({
    schema,
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    effect,
    ...processCreateParams(params)
  });
};
ZodEffects.createWithPreprocess = (preprocess, schema, params) => {
  return new ZodEffects({
    schema,
    effect: { type: "preprocess", transform: preprocess },
    typeName: ZodFirstPartyTypeKind.ZodEffects,
    ...processCreateParams(params)
  });
};
var ZodOptional = class extends ZodType {
  static {
    __name(this, "ZodOptional");
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.undefined) {
      return OK(void 0);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
};
ZodOptional.create = (type, params) => {
  return new ZodOptional({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodOptional,
    ...processCreateParams(params)
  });
};
var ZodNullable = class extends ZodType {
  static {
    __name(this, "ZodNullable");
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType === ZodParsedType.null) {
      return OK(null);
    }
    return this._def.innerType._parse(input);
  }
  unwrap() {
    return this._def.innerType;
  }
};
ZodNullable.create = (type, params) => {
  return new ZodNullable({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodNullable,
    ...processCreateParams(params)
  });
};
var ZodDefault = class extends ZodType {
  static {
    __name(this, "ZodDefault");
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    let data = ctx.data;
    if (ctx.parsedType === ZodParsedType.undefined) {
      data = this._def.defaultValue();
    }
    return this._def.innerType._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  removeDefault() {
    return this._def.innerType;
  }
};
ZodDefault.create = (type, params) => {
  return new ZodDefault({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodDefault,
    defaultValue: typeof params.default === "function" ? params.default : () => params.default,
    ...processCreateParams(params)
  });
};
var ZodCatch = class extends ZodType {
  static {
    __name(this, "ZodCatch");
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const newCtx = {
      ...ctx,
      common: {
        ...ctx.common,
        issues: []
      }
    };
    const result = this._def.innerType._parse({
      data: newCtx.data,
      path: newCtx.path,
      parent: {
        ...newCtx
      }
    });
    if (isAsync(result)) {
      return result.then((result2) => {
        return {
          status: "valid",
          value: result2.status === "valid" ? result2.value : this._def.catchValue({
            get error() {
              return new ZodError(newCtx.common.issues);
            },
            input: newCtx.data
          })
        };
      });
    } else {
      return {
        status: "valid",
        value: result.status === "valid" ? result.value : this._def.catchValue({
          get error() {
            return new ZodError(newCtx.common.issues);
          },
          input: newCtx.data
        })
      };
    }
  }
  removeCatch() {
    return this._def.innerType;
  }
};
ZodCatch.create = (type, params) => {
  return new ZodCatch({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodCatch,
    catchValue: typeof params.catch === "function" ? params.catch : () => params.catch,
    ...processCreateParams(params)
  });
};
var ZodNaN = class extends ZodType {
  static {
    __name(this, "ZodNaN");
  }
  _parse(input) {
    const parsedType = this._getType(input);
    if (parsedType !== ZodParsedType.nan) {
      const ctx = this._getOrReturnCtx(input);
      addIssueToContext(ctx, {
        code: ZodIssueCode.invalid_type,
        expected: ZodParsedType.nan,
        received: ctx.parsedType
      });
      return INVALID;
    }
    return { status: "valid", value: input.data };
  }
};
ZodNaN.create = (params) => {
  return new ZodNaN({
    typeName: ZodFirstPartyTypeKind.ZodNaN,
    ...processCreateParams(params)
  });
};
var BRAND = Symbol("zod_brand");
var ZodBranded = class extends ZodType {
  static {
    __name(this, "ZodBranded");
  }
  _parse(input) {
    const { ctx } = this._processInputParams(input);
    const data = ctx.data;
    return this._def.type._parse({
      data,
      path: ctx.path,
      parent: ctx
    });
  }
  unwrap() {
    return this._def.type;
  }
};
var ZodPipeline = class _ZodPipeline extends ZodType {
  static {
    __name(this, "ZodPipeline");
  }
  _parse(input) {
    const { status, ctx } = this._processInputParams(input);
    if (ctx.common.async) {
      const handleAsync = /* @__PURE__ */ __name(async () => {
        const inResult = await this._def.in._parseAsync({
          data: ctx.data,
          path: ctx.path,
          parent: ctx
        });
        if (inResult.status === "aborted")
          return INVALID;
        if (inResult.status === "dirty") {
          status.dirty();
          return DIRTY(inResult.value);
        } else {
          return this._def.out._parseAsync({
            data: inResult.value,
            path: ctx.path,
            parent: ctx
          });
        }
      }, "handleAsync");
      return handleAsync();
    } else {
      const inResult = this._def.in._parseSync({
        data: ctx.data,
        path: ctx.path,
        parent: ctx
      });
      if (inResult.status === "aborted")
        return INVALID;
      if (inResult.status === "dirty") {
        status.dirty();
        return {
          status: "dirty",
          value: inResult.value
        };
      } else {
        return this._def.out._parseSync({
          data: inResult.value,
          path: ctx.path,
          parent: ctx
        });
      }
    }
  }
  static create(a, b) {
    return new _ZodPipeline({
      in: a,
      out: b,
      typeName: ZodFirstPartyTypeKind.ZodPipeline
    });
  }
};
var ZodReadonly = class extends ZodType {
  static {
    __name(this, "ZodReadonly");
  }
  _parse(input) {
    const result = this._def.innerType._parse(input);
    const freeze = /* @__PURE__ */ __name((data) => {
      if (isValid(data)) {
        data.value = Object.freeze(data.value);
      }
      return data;
    }, "freeze");
    return isAsync(result) ? result.then((data) => freeze(data)) : freeze(result);
  }
  unwrap() {
    return this._def.innerType;
  }
};
ZodReadonly.create = (type, params) => {
  return new ZodReadonly({
    innerType: type,
    typeName: ZodFirstPartyTypeKind.ZodReadonly,
    ...processCreateParams(params)
  });
};
function cleanParams(params, data) {
  const p = typeof params === "function" ? params(data) : typeof params === "string" ? { message: params } : params;
  const p2 = typeof p === "string" ? { message: p } : p;
  return p2;
}
__name(cleanParams, "cleanParams");
function custom(check, _params = {}, fatal) {
  if (check)
    return ZodAny.create().superRefine((data, ctx) => {
      const r = check(data);
      if (r instanceof Promise) {
        return r.then((r2) => {
          if (!r2) {
            const params = cleanParams(_params, data);
            const _fatal = params.fatal ?? fatal ?? true;
            ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
          }
        });
      }
      if (!r) {
        const params = cleanParams(_params, data);
        const _fatal = params.fatal ?? fatal ?? true;
        ctx.addIssue({ code: "custom", ...params, fatal: _fatal });
      }
      return;
    });
  return ZodAny.create();
}
__name(custom, "custom");
var late = {
  object: ZodObject.lazycreate
};
var ZodFirstPartyTypeKind;
(function(ZodFirstPartyTypeKind2) {
  ZodFirstPartyTypeKind2["ZodString"] = "ZodString";
  ZodFirstPartyTypeKind2["ZodNumber"] = "ZodNumber";
  ZodFirstPartyTypeKind2["ZodNaN"] = "ZodNaN";
  ZodFirstPartyTypeKind2["ZodBigInt"] = "ZodBigInt";
  ZodFirstPartyTypeKind2["ZodBoolean"] = "ZodBoolean";
  ZodFirstPartyTypeKind2["ZodDate"] = "ZodDate";
  ZodFirstPartyTypeKind2["ZodSymbol"] = "ZodSymbol";
  ZodFirstPartyTypeKind2["ZodUndefined"] = "ZodUndefined";
  ZodFirstPartyTypeKind2["ZodNull"] = "ZodNull";
  ZodFirstPartyTypeKind2["ZodAny"] = "ZodAny";
  ZodFirstPartyTypeKind2["ZodUnknown"] = "ZodUnknown";
  ZodFirstPartyTypeKind2["ZodNever"] = "ZodNever";
  ZodFirstPartyTypeKind2["ZodVoid"] = "ZodVoid";
  ZodFirstPartyTypeKind2["ZodArray"] = "ZodArray";
  ZodFirstPartyTypeKind2["ZodObject"] = "ZodObject";
  ZodFirstPartyTypeKind2["ZodUnion"] = "ZodUnion";
  ZodFirstPartyTypeKind2["ZodDiscriminatedUnion"] = "ZodDiscriminatedUnion";
  ZodFirstPartyTypeKind2["ZodIntersection"] = "ZodIntersection";
  ZodFirstPartyTypeKind2["ZodTuple"] = "ZodTuple";
  ZodFirstPartyTypeKind2["ZodRecord"] = "ZodRecord";
  ZodFirstPartyTypeKind2["ZodMap"] = "ZodMap";
  ZodFirstPartyTypeKind2["ZodSet"] = "ZodSet";
  ZodFirstPartyTypeKind2["ZodFunction"] = "ZodFunction";
  ZodFirstPartyTypeKind2["ZodLazy"] = "ZodLazy";
  ZodFirstPartyTypeKind2["ZodLiteral"] = "ZodLiteral";
  ZodFirstPartyTypeKind2["ZodEnum"] = "ZodEnum";
  ZodFirstPartyTypeKind2["ZodEffects"] = "ZodEffects";
  ZodFirstPartyTypeKind2["ZodNativeEnum"] = "ZodNativeEnum";
  ZodFirstPartyTypeKind2["ZodOptional"] = "ZodOptional";
  ZodFirstPartyTypeKind2["ZodNullable"] = "ZodNullable";
  ZodFirstPartyTypeKind2["ZodDefault"] = "ZodDefault";
  ZodFirstPartyTypeKind2["ZodCatch"] = "ZodCatch";
  ZodFirstPartyTypeKind2["ZodPromise"] = "ZodPromise";
  ZodFirstPartyTypeKind2["ZodBranded"] = "ZodBranded";
  ZodFirstPartyTypeKind2["ZodPipeline"] = "ZodPipeline";
  ZodFirstPartyTypeKind2["ZodReadonly"] = "ZodReadonly";
})(ZodFirstPartyTypeKind || (ZodFirstPartyTypeKind = {}));
var instanceOfType = /* @__PURE__ */ __name((cls, params = {
  message: `Input not instance of ${cls.name}`
}) => custom((data) => data instanceof cls, params), "instanceOfType");
var stringType = ZodString.create;
var numberType = ZodNumber.create;
var nanType = ZodNaN.create;
var bigIntType = ZodBigInt.create;
var booleanType = ZodBoolean.create;
var dateType = ZodDate.create;
var symbolType = ZodSymbol.create;
var undefinedType = ZodUndefined.create;
var nullType = ZodNull.create;
var anyType = ZodAny.create;
var unknownType = ZodUnknown.create;
var neverType = ZodNever.create;
var voidType = ZodVoid.create;
var arrayType = ZodArray.create;
var objectType = ZodObject.create;
var strictObjectType = ZodObject.strictCreate;
var unionType = ZodUnion.create;
var discriminatedUnionType = ZodDiscriminatedUnion.create;
var intersectionType = ZodIntersection.create;
var tupleType = ZodTuple.create;
var recordType = ZodRecord.create;
var mapType = ZodMap.create;
var setType = ZodSet.create;
var functionType = ZodFunction.create;
var lazyType = ZodLazy.create;
var literalType = ZodLiteral.create;
var enumType = ZodEnum.create;
var nativeEnumType = ZodNativeEnum.create;
var promiseType = ZodPromise.create;
var effectsType = ZodEffects.create;
var optionalType = ZodOptional.create;
var nullableType = ZodNullable.create;
var preprocessType = ZodEffects.createWithPreprocess;
var pipelineType = ZodPipeline.create;
var ostring = /* @__PURE__ */ __name(() => stringType().optional(), "ostring");
var onumber = /* @__PURE__ */ __name(() => numberType().optional(), "onumber");
var oboolean = /* @__PURE__ */ __name(() => booleanType().optional(), "oboolean");
var coerce = {
  string: /* @__PURE__ */ __name(((arg) => ZodString.create({ ...arg, coerce: true })), "string"),
  number: /* @__PURE__ */ __name(((arg) => ZodNumber.create({ ...arg, coerce: true })), "number"),
  boolean: /* @__PURE__ */ __name(((arg) => ZodBoolean.create({
    ...arg,
    coerce: true
  })), "boolean"),
  bigint: /* @__PURE__ */ __name(((arg) => ZodBigInt.create({ ...arg, coerce: true })), "bigint"),
  date: /* @__PURE__ */ __name(((arg) => ZodDate.create({ ...arg, coerce: true })), "date")
};
var NEVER = INVALID;

// src/utils/validation.ts
init_checked_fetch();
init_modules_watch_stub();
var emailSchema = external_exports.string().email("Invalid email address");
var phoneSchema = external_exports.string().regex(/^\+?[\d\s\-\(\)]+$/, "Invalid phone number");
var currencySchema = external_exports.number().min(0, "Amount must be positive");
var dateSchema = external_exports.string().regex(/^\d{4}-\d{2}-\d{2}$/, "Invalid date format (YYYY-MM-DD)");
var tenantIdSchema = external_exports.string().regex(/^[a-zA-Z0-9_-]+$/, "Invalid tenant ID").max(50);
var userIdSchema = external_exports.string().regex(/^[a-zA-Z0-9_-]+$/, "Invalid user ID").max(50);
var TimeEntrySchema = external_exports.object({
  tenantId: tenantIdSchema,
  id: external_exports.string().uuid(),
  date: dateSchema,
  client: external_exports.string().min(1, "Client is required").max(255),
  project: external_exports.string().min(1, "Project is required").max(255),
  service: external_exports.string().min(1, "Service is required").max(255),
  durationMin: external_exports.number().int().min(1, "Duration must be at least 1 minute").max(1440, "Duration cannot exceed 24 hours"),
  notes: external_exports.string().max(1e4, "Notes too long").optional(),
  isRnD: external_exports.boolean().default(true),
  employeeId: external_exports.string().optional(),
  employeeName: external_exports.string().max(255).optional(),
  projectId: external_exports.string().optional(),
  projectName: external_exports.string().max(255).optional(),
  status: external_exports.enum(["active", "completed", "paused"]).optional(),
  createdAt: external_exports.string().datetime().optional(),
  updatedAt: external_exports.string().datetime().optional(),
  createdBy: external_exports.string().optional()
});
var TimeEntryCreateSchema = external_exports.object({
  date: dateSchema,
  client: external_exports.string().min(1, "Client is required").max(255),
  project: external_exports.string().min(1, "Project is required").max(255),
  service: external_exports.string().min(1, "Service is required").max(255),
  durationMin: external_exports.number().int().min(1, "Duration must be at least 1 minute").max(1440, "Duration cannot exceed 24 hours"),
  notes: external_exports.string().max(1e4, "Notes too long").optional(),
  isRnD: external_exports.boolean().default(true)
});
var TimeEntryListResponseSchema = external_exports.object({
  items: external_exports.array(TimeEntrySchema),
  paging: external_exports.object({
    limit: external_exports.number().int().min(1).max(200),
    offset: external_exports.number().int().min(0),
    nextOffset: external_exports.number().int().min(0).nullable(),
    prevOffset: external_exports.number().int().min(0).nullable(),
    from: external_exports.string().optional(),
    to: external_exports.string().optional()
  }),
  total: external_exports.number().int().min(0)
});
var ApiErrorSchema = external_exports.object({
  error: external_exports.string(),
  details: external_exports.string().optional(),
  code: external_exports.string().optional(),
  timestamp: external_exports.string().datetime().optional()
});
var paginationSchema = external_exports.object({
  limit: external_exports.number().int().min(1).max(200).default(50),
  offset: external_exports.number().int().min(0).default(0)
});
var dateRangeSchema = external_exports.object({
  from: dateSchema.optional(),
  to: dateSchema.optional()
}).refine((data) => {
  if (data.from && data.to) {
    return new Date(data.from) <= new Date(data.to);
  }
  return true;
}, "Start date must be before end date");
var clientSchema = external_exports.object({
  name: external_exports.string().min(1, "Name is required").max(255),
  industry: external_exports.string().max(255).optional(),
  contactPerson: external_exports.string().min(1, "Contact person is required").max(255),
  email: emailSchema,
  phone: phoneSchema.optional(),
  address: external_exports.string().max(500).optional(),
  taxYear: external_exports.string().regex(/^\d{4}$/, "Invalid tax year"),
  status: external_exports.enum(["active", "inactive", "pending"]),
  estimatedCredit: currencySchema.optional()
});
var projectSchema = external_exports.object({
  name: external_exports.string().min(1, "Name is required").max(255),
  description: external_exports.string().max(1e3).optional(),
  status: external_exports.enum(["active", "completed", "on-hold"]),
  isRnD: external_exports.boolean().default(true),
  budget: currencySchema.optional(),
  startDate: dateSchema,
  endDate: dateSchema.optional()
});
var expenseSchema = external_exports.object({
  description: external_exports.string().min(1, "Description is required").max(255),
  amount: currencySchema.min(0.01, "Amount must be greater than 0"),
  category: external_exports.string().min(1, "Category is required"),
  date: dateSchema,
  vendor: external_exports.string().min(1, "Vendor is required").max(255),
  isRnD: external_exports.boolean().default(true),
  justification: external_exports.string().max(1e3).optional()
});
var userSchema = external_exports.object({
  email: emailSchema,
  firstName: external_exports.string().min(1, "First name is required").max(100),
  lastName: external_exports.string().min(1, "Last name is required").max(100),
  roleId: external_exports.string().min(1, "Role is required"),
  department: external_exports.string().max(100).optional(),
  status: external_exports.enum(["active", "inactive", "pending"])
});
function sanitizeInput(input, maxLength = 1e3) {
  return input.trim().substring(0, maxLength).replace(/[<>]/g, "").replace(/\0/g, "");
}
__name(sanitizeInput, "sanitizeInput");

// src/utils/d1-queries.ts
init_checked_fetch();
init_modules_watch_stub();

// src/utils/retry.ts
init_checked_fetch();
init_modules_watch_stub();
async function withRetry(operation, maxAttempts = 3, getDelay = (attempt) => Math.min(1e3 * Math.pow(2, attempt - 1), 1e4)) {
  let lastError;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await operation();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));
      if (lastError.cause === "client_error" && lastError.cause !== "rate_limit") {
        throw lastError;
      }
      if (attempt === maxAttempts) {
        throw lastError;
      }
      const delay = getDelay(attempt, lastError);
      await new Promise((resolve) => setTimeout(resolve, delay));
      console.warn(`Retry attempt ${attempt}/${maxAttempts} after ${delay}ms delay:`, lastError.message);
    }
  }
  throw lastError;
}
__name(withRetry, "withRetry");

// src/utils/d1-queries.ts
var TimeEntriesQueries = class _TimeEntriesQueries {
  static {
    __name(this, "TimeEntriesQueries");
  }
  env;
  static MAX_LIMIT = 200;
  static DEFAULT_LIMIT = 50;
  constructor(env) {
    this.env = env;
  }
  async listWithPagination(tenantId, params) {
    const {
      limit = _TimeEntriesQueries.DEFAULT_LIMIT,
      offset = 0,
      from = "0000-01-01",
      to = "9999-12-31"
    } = params;
    const cappedLimit = Math.min(limit, _TimeEntriesQueries.MAX_LIMIT);
    const [items, totalResult] = await Promise.all([
      withRetry(async () => {
        const result = await this.env.DB.prepare(`
          SELECT
            id, date, client, project, service,
            duration_min as durationMin, notes, is_rnd as isRnD,
            employee_id as employeeId, employee_name as employeeName,
            created_at as createdAt
          FROM time_entries
          WHERE tenant_id = ? AND date BETWEEN ? AND ?
          ORDER BY date DESC, created_at DESC
          LIMIT ? OFFSET ?
        `).bind(tenantId, from, to, cappedLimit + 1, offset).all();
        return result.results;
      }, 3),
      withRetry(async () => {
        const result = await this.env.DB.prepare(`
          SELECT COUNT(*) as total
          FROM time_entries
          WHERE tenant_id = ? AND date BETWEEN ? AND ?
        `).bind(tenantId, from, to).first();
        return result?.total || 0;
      }, 3)
    ]);
    const hasMore = items.length > cappedLimit;
    const resultItems = hasMore ? items.slice(0, cappedLimit) : items;
    return {
      items: resultItems,
      total: totalResult,
      hasMore
    };
  }
  async getById(tenantId, id) {
    return withRetry(async () => {
      const result = await this.env.DB.prepare(`
        SELECT
          id, date, client, project, service,
          duration_min as durationMin, notes, is_rnd as isRnD,
          employee_id as employeeId, employee_name as employeeName,
          created_at as createdAt
        FROM time_entries
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first();
      return result || null;
    }, 3);
  }
  async create(tenantId, userId, data) {
    await withRetry(async () => {
      await this.env.DB.prepare(`
        INSERT INTO time_entries (
          id, tenant_id, date, client, project, service,
          duration_min, notes, is_rnd, created_by,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
      `).bind(
        data.id,
        tenantId,
        data.date,
        data.client,
        data.project,
        data.service,
        data.durationMin,
        data.notes || null,
        data.isRnD ? 1 : 0,
        userId
      ).run();
    }, 3);
  }
  async batchCreate(tenantId, userId, entries) {
    const BATCH_SIZE = 25;
    for (let i = 0; i < entries.length; i += BATCH_SIZE) {
      const batch = entries.slice(i, i + BATCH_SIZE);
      const statements = batch.map(
        (entry) => this.env.DB.prepare(`
          INSERT INTO time_entries (
            id, tenant_id, date, client, project, service,
            duration_min, notes, is_rnd, created_by,
            created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).bind(
          entry.id,
          tenantId,
          entry.date,
          entry.client,
          entry.project,
          entry.service,
          entry.durationMin,
          entry.notes || null,
          entry.isRnD ? 1 : 0,
          userId
        )
      );
      await withRetry(async () => {
        await this.env.DB.batch(statements);
      }, 3);
    }
  }
  async update(tenantId, id, data) {
    const fields = Object.keys(data);
    if (fields.length === 0) return false;
    const setClause = fields.map((field) => {
      const dbField = field === "durationMin" ? "duration_min" : field === "isRnD" ? "is_rnd" : field;
      return `${dbField} = ?`;
    }).join(", ");
    const result = await withRetry(async () => {
      return this.env.DB.prepare(`
        UPDATE time_entries
        SET ${setClause}, updated_at = datetime('now')
        WHERE tenant_id = ? AND id = ?
      `).bind(...Object.values(data), tenantId, id).run();
    }, 3);
    return result.meta.changes > 0;
  }
  async delete(tenantId, id) {
    const existing = await this.getById(tenantId, id);
    if (!existing) return null;
    await withRetry(async () => {
      await this.env.DB.prepare(`
        DELETE FROM time_entries
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).run();
    }, 3);
    return existing;
  }
  async getAggregatedStats(tenantId, from, to) {
    const result = await withRetry(async () => {
      return this.env.DB.prepare(`
        SELECT
          COUNT(*) as totalEntries,
          COALESCE(SUM(duration_min), 0) as totalMinutes,
          COALESCE(SUM(CASE WHEN is_rnd = 1 THEN duration_min ELSE 0 END), 0) as totalRnDMinutes,
          COUNT(DISTINCT project) as projectCount,
          COUNT(DISTINCT client) as clientCount
        FROM time_entries
        WHERE tenant_id = ? AND date BETWEEN ? AND ?
      `).bind(tenantId, from, to).first();
    }, 3);
    return result || {
      totalEntries: 0,
      totalMinutes: 0,
      totalRnDMinutes: 0,
      projectCount: 0,
      clientCount: 0
    };
  }
  async getProjectBreakdown(tenantId, from, to, limit = 20) {
    const result = await withRetry(async () => {
      return this.env.DB.prepare(`
        SELECT
          project,
          SUM(duration_min) as totalMinutes,
          COUNT(*) as entryCount
        FROM time_entries
        WHERE tenant_id = ? AND date BETWEEN ? AND ?
        GROUP BY project
        ORDER BY totalMinutes DESC
        LIMIT ?
      `).bind(tenantId, from, to, limit).all();
    }, 3);
    return result.results;
  }
};

// src/utils/d1-helpers.ts
init_checked_fetch();
init_modules_watch_stub();
async function getCachedOrCompute(kv, key, ttl, compute) {
  const cached = await kv.get(key, "json");
  if (cached !== null) {
    return cached;
  }
  const fresh = await compute();
  await kv.put(key, JSON.stringify(fresh), {
    expirationTtl: ttl
  });
  return fresh;
}
__name(getCachedOrCompute, "getCachedOrCompute");
function buildCacheKey(prefix, params) {
  const sortedParams = Object.keys(params).sort().map((key) => `${key}:${params[key]}`).join("|");
  return `${prefix}:${sortedParams}`;
}
__name(buildCacheKey, "buildCacheKey");
async function invalidateCache(kv, pattern) {
  const list = await kv.list({ prefix: pattern });
  const deletePromises = list.keys.map((key) => kv.delete(key.name));
  await Promise.all(deletePromises);
}
__name(invalidateCache, "invalidateCache");

// src/routes/timeEntries.ts
var timeEntriesRouter = new Hono2();
timeEntriesRouter.get("/", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "time_entry",
      action: "read",
      resourceId: "list"
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "time_entry",
        resourceId: "list",
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const from = c.req.query("from") ?? "0000-01-01";
    const to = c.req.query("to") ?? "9999-12-31";
    const limit = Math.min(parseInt(c.req.query("limit") ?? "50", 10), 200);
    const offset = Math.max(parseInt(c.req.query("offset") ?? "0", 10), 0);
    const dateRange = dateRangeSchema.safeParse({ from, to });
    if (!dateRange.success) {
      return c.json({
        error: "Invalid date range",
        details: dateRange.error.errors.map((e) => e.message).join(", "),
        code: "VALIDATION_ERROR"
      }, 400);
    }
    const queries = new TimeEntriesQueries(c.env);
    const result = await queries.listWithPagination(tenantId, { limit, offset, from, to });
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "time_entry",
      resourceId: "list",
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        recordCount: result.items.length,
        phiFields: ["notes", "client", "project"],
        limit,
        offset
      }
    });
    return c.json({
      items: result.items,
      paging: {
        from,
        to,
        limit,
        offset,
        prevOffset: offset > 0 ? Math.max(0, offset - limit) : null,
        nextOffset: result.hasMore ? offset + limit : null
      },
      total: result.total
    });
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "time_entry",
      resourceId: "list",
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error fetching time entries:", error);
    return c.json({
      error: "Failed to fetch time entries",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "FETCH_ERROR"
    }, 500);
  }
});
timeEntriesRouter.get("/:id", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const id = c.req.param("id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "time_entry",
      action: "read",
      resourceId: id
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "time_entry",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const queries = new TimeEntriesQueries(c.env);
    const row = await queries.getById(tenantId, id);
    if (!row) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "time_entry",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: "Time entry not found",
        phiAccessed: false
      });
      return c.json({
        error: "Time entry not found",
        code: "NOT_FOUND"
      }, 404);
    }
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "time_entry",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ["notes", "client", "project"]
      }
    });
    return c.json({ data: { ...row, tenantId } });
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "time_entry",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error fetching time entry:", error);
    return c.json({
      error: "Failed to fetch time entry",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "FETCH_ERROR"
    }, 500);
  }
});
timeEntriesRouter.post("/", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "time_entry",
      action: "create",
      resourceId: "new"
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "CREATE",
        resourceType: "time_entry",
        resourceId: "new",
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const body = await c.req.json();
    const validatedData = TimeEntryCreateSchema.parse(body);
    const sanitizedData = {
      ...validatedData,
      client: sanitizeInput(validatedData.client, 255),
      project: sanitizeInput(validatedData.project, 255),
      service: sanitizeInput(validatedData.service, 255),
      notes: validatedData.notes ? sanitizeInput(validatedData.notes, 1e4) : void 0
    };
    const id = crypto.randomUUID();
    const queries = new TimeEntriesQueries(c.env);
    await queries.create(tenantId, userId, {
      id,
      date: sanitizedData.date,
      client: sanitizedData.client,
      project: sanitizedData.project,
      service: sanitizedData.service,
      durationMin: sanitizedData.durationMin,
      notes: sanitizedData.notes,
      isRnD: sanitizedData.isRnD
    });
    await invalidateCache(c.env.KV, `analytics:${tenantId}`);
    await auditLogger2.log({
      tenantId,
      userId,
      action: "CREATE",
      resourceType: "time_entry",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ["notes", "client", "project"],
        data: sanitizedData
      }
    });
    const created = await queries.getById(tenantId, id);
    return c.json({ data: { ...created, tenantId } }, 201);
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({
        error: "Validation failed",
        details: error.errors.map((e) => e.message).join(", "),
        code: "VALIDATION_ERROR"
      }, 400);
    }
    await auditLogger2.log({
      tenantId,
      userId,
      action: "CREATE",
      resourceType: "time_entry",
      resourceId: "new",
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error creating time entry:", error);
    return c.json({
      error: "Failed to create time entry",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "CREATE_ERROR"
    }, 500);
  }
});
timeEntriesRouter.delete("/:id", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const id = c.req.param("id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "time_entry",
      action: "delete",
      resourceId: id
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "DELETE",
        resourceType: "time_entry",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const queries = new TimeEntriesQueries(c.env);
    const existing = await queries.delete(tenantId, id);
    if (!existing) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "DELETE",
        resourceType: "time_entry",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: "Time entry not found",
        phiAccessed: false
      });
      return c.json({
        error: "Time entry not found",
        code: "NOT_FOUND"
      }, 404);
    }
    await invalidateCache(c.env.KV, `analytics:${tenantId}`);
    await auditLogger2.log({
      tenantId,
      userId,
      action: "DELETE",
      resourceType: "time_entry",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        note: "Time entry with PHI data deleted",
        oldData: existing
      }
    });
    return c.json({ success: true });
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "DELETE",
      resourceType: "time_entry",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error deleting time entry:", error);
    return c.json({
      error: "Failed to delete time entry",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "DELETE_ERROR"
    }, 500);
  }
});
timeEntriesRouter.post("/batch", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "time_entry",
      action: "create",
      resourceId: "batch"
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "BATCH_CREATE",
        resourceType: "time_entry",
        resourceId: "batch",
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const body = await c.req.json();
    if (!Array.isArray(body.entries) || body.entries.length === 0) {
      return c.json({
        error: "Request must include entries array",
        code: "VALIDATION_ERROR"
      }, 400);
    }
    if (body.entries.length > 100) {
      return c.json({
        error: "Maximum 100 entries per batch",
        code: "VALIDATION_ERROR"
      }, 400);
    }
    const sanitizedEntries = body.entries.map((entry) => {
      const validatedData = TimeEntryCreateSchema.parse(entry);
      return {
        id: crypto.randomUUID(),
        date: validatedData.date,
        client: sanitizeInput(validatedData.client, 255),
        project: sanitizeInput(validatedData.project, 255),
        service: sanitizeInput(validatedData.service, 255),
        durationMin: validatedData.durationMin,
        notes: validatedData.notes ? sanitizeInput(validatedData.notes, 1e4) : void 0,
        isRnD: validatedData.isRnD
      };
    });
    const queries = new TimeEntriesQueries(c.env);
    await queries.batchCreate(tenantId, userId, sanitizedEntries);
    await invalidateCache(c.env.KV, `analytics:${tenantId}`);
    await auditLogger2.log({
      tenantId,
      userId,
      action: "BATCH_CREATE",
      resourceType: "time_entry",
      resourceId: "batch",
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ["notes", "client", "project"],
        count: sanitizedEntries.length,
        ids: sanitizedEntries.map((e) => e.id)
      }
    });
    return c.json({
      success: true,
      count: sanitizedEntries.length,
      ids: sanitizedEntries.map((e) => e.id)
    }, 201);
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({
        error: "Validation failed",
        details: error.errors.map((e) => e.message).join(", "),
        code: "VALIDATION_ERROR"
      }, 400);
    }
    await auditLogger2.log({
      tenantId,
      userId,
      action: "BATCH_CREATE",
      resourceType: "time_entry",
      resourceId: "batch",
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error creating batch time entries:", error);
    return c.json({
      error: "Failed to create batch time entries",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "CREATE_ERROR"
    }, 500);
  }
});

// src/routes/centralReach.ts
init_checked_fetch();
init_modules_watch_stub();

// src/utils/audit.ts
init_checked_fetch();
init_modules_watch_stub();
async function auditLogger(env, entry) {
  try {
    const id = crypto.randomUUID();
    const timestamp = (/* @__PURE__ */ new Date()).toISOString();
    const auditEntry = {
      id,
      ...entry,
      created_at: timestamp
    };
    const stmt = env.DB.prepare(`
      INSERT INTO audit_log (
        id, tenant_id, user_id, action, resource_type, resource_id,
        old_values, new_values, ip_address, user_agent, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    await stmt.bind(
      id,
      entry.tenant_id,
      entry.user_id,
      entry.action,
      entry.resource_type,
      entry.resource_id || null,
      entry.old_values || null,
      entry.new_values || null,
      entry.ip_address || null,
      entry.user_agent || null,
      timestamp
    ).run();
    const kvKey = `audit:${entry.tenant_id}:${id}`;
    await env.KV.put(kvKey, JSON.stringify(auditEntry), {
      expirationTtl: 60 * 60 * 24 * 30
      // 30 days
    });
  } catch (error) {
    console.error("Audit logging failed:", error);
  }
}
__name(auditLogger, "auditLogger");

// src/utils/security.ts
init_checked_fetch();
init_modules_watch_stub();
function createSecurityContext(c) {
  return {
    tenantId: c.get("tenant_id"),
    userId: c.get("user_id"),
    role: c.get("user_role"),
    permissions: c.get("user_permissions") || [],
    ipAddress: c.get("user_ip"),
    userAgent: c.req.header("User-Agent")
  };
}
__name(createSecurityContext, "createSecurityContext");
function requirePermission(context, permission) {
  if (context.role === "admin") return;
  if (!context.permissions.includes(permission) && !context.permissions.includes("*")) {
    throw new Error(`Permission denied: ${permission} required`);
  }
}
__name(requirePermission, "requirePermission");
function validateUserId(userId) {
  return /^[a-zA-Z0-9_-]+$/.test(userId) && userId.length <= 50;
}
__name(validateUserId, "validateUserId");
async function rateLimitCheck(env, key, limit = 100, windowMs = 6e4) {
  const now = Date.now();
  const windowStart = now - windowMs;
  const currentData = await env.KV.get(`ratelimit:${key}`);
  const requests = currentData ? JSON.parse(currentData) : [];
  const recentRequests = requests.filter((timestamp) => timestamp > windowStart);
  if (recentRequests.length >= limit) {
    return false;
  }
  recentRequests.push(now);
  await env.KV.put(`ratelimit:${key}`, JSON.stringify(recentRequests), {
    expirationTtl: Math.ceil(windowMs / 1e3)
  });
  return true;
}
__name(rateLimitCheck, "rateLimitCheck");

// src/routes/centralReach.ts
var centralReachRouter = new Hono2();
var syncRequestSchema = external_exports.object({
  syncType: external_exports.enum(["clients", "staff", "timeentries", "all"])
});
async function makeCentralReachRequest(env, endpoint, options = {}) {
  const { method = "GET", body } = options;
  const url = `${env.CENTRALREACH_BASE_URL}/${endpoint}`;
  return withRetry(async () => {
    const response = await fetch(url, {
      method,
      headers: {
        "Authorization": `Bearer ${env.CENTRALREACH_API_KEY}`,
        "Content-Type": "application/json",
        "Accept": "application/json"
      },
      body,
      signal: AbortSignal.timeout(3e4)
      // 30 second timeout
    });
    if (!response.ok) {
      if (response.status === 429) {
        const retryAfter = response.headers.get("Retry-After");
        const delay = retryAfter ? parseInt(retryAfter) * 1e3 : 5e3;
        const error = new Error(`Rate limited. Retry after ${delay}ms`);
        error.cause = "rate_limit";
        throw error;
      }
      if (response.status >= 400 && response.status < 500) {
        const error = new Error(`CentralReach API Error: ${response.status} ${response.statusText}`);
        error.cause = "client_error";
        throw error;
      }
      throw new Error(`CentralReach API Error: ${response.status} ${response.statusText}`);
    }
    return response;
  }, 3, (attempt, error) => {
    if (error instanceof Error && error.cause === "rate_limit") {
      const match = error.message.match(/Retry after (\d+)ms/);
      return match ? parseInt(match[1]) : 5e3;
    }
    return Math.min(1e3 * Math.pow(2, attempt - 1), 1e4);
  });
}
__name(makeCentralReachRequest, "makeCentralReachRequest");
centralReachRouter.get("/clients", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "clients:read");
    const cacheKey = `centralreach:clients:${tenantId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }
    const response = await makeCentralReachRequest(c.env, "clients");
    const data = await response.json();
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 3600 });
    return c.json(data);
  } catch (error) {
    console.error("CentralReach clients error:", error);
    const status = error instanceof Error && error.cause === "client_error" ? 400 : 500;
    return c.json({
      error: "Failed to fetch clients from CentralReach",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "CENTRALREACH_ERROR"
    }, status);
  }
});
centralReachRouter.get("/staff", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "users:read");
    const cacheKey = `centralreach:staff:${tenantId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }
    const response = await makeCentralReachRequest(c.env, "staff");
    const data = await response.json();
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 3600 });
    return c.json(data);
  } catch (error) {
    console.error("CentralReach staff error:", error);
    const status = error instanceof Error && error.cause === "client_error" ? 400 : 500;
    return c.json({
      error: "Failed to fetch staff from CentralReach",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "CENTRALREACH_ERROR"
    }, status);
  }
});
centralReachRouter.get("/timeentries", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "time:read");
    const startDate = c.req.query("startDate");
    const endDate = c.req.query("endDate");
    const clientId = c.req.query("clientId");
    const cacheKey = `centralreach:timeentries:${tenantId}:${startDate}:${endDate}:${clientId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }
    let endpoint = "timeentries";
    const params = new URLSearchParams();
    if (startDate) params.append("startDate", startDate);
    if (endDate) params.append("endDate", endDate);
    if (clientId) params.append("clientId", clientId);
    if (params.toString()) {
      endpoint += `?${params.toString()}`;
    }
    const response = await makeCentralReachRequest(c.env, endpoint);
    const data = await response.json();
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 1800 });
    return c.json(data);
  } catch (error) {
    console.error("CentralReach time entries error:", error);
    const status = error instanceof Error && error.cause === "client_error" ? 400 : 500;
    return c.json({
      error: "Failed to fetch time entries from CentralReach",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "CENTRALREACH_ERROR"
    }, status);
  }
});
centralReachRouter.post("/sync", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const userId = c.get("user_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "system:manage");
    const body = await c.req.json();
    const { syncType } = syncRequestSchema.parse(body);
    const results = [];
    if (syncType === "clients" || syncType === "all") {
      const response = await makeCentralReachRequest(c.env, "clients");
      const clients = await response.json();
      await c.env.KV.put(`centralreach:clients:${tenantId}`, JSON.stringify(clients), {
        expirationTtl: 3600
        // 1 hour cache
      });
      results.push({
        type: "clients",
        success: true,
        count: clients.length,
        message: `Synced ${clients.length} clients`
      });
    }
    if (syncType === "timeentries" || syncType === "all") {
      const startDate = /* @__PURE__ */ new Date();
      startDate.setDate(startDate.getDate() - 30);
      const endDate = /* @__PURE__ */ new Date();
      const response = await makeCentralReachRequest(
        c.env,
        `timeentries?startDate=${startDate.toISOString().split("T")[0]}&endDate=${endDate.toISOString().split("T")[0]}`
      );
      const timeEntries = await response.json();
      const batchStatements = timeEntries.map(
        (entry) => c.env.DB.prepare(`
          INSERT OR REPLACE INTO time_entries (
            id, tenant_id, date, client, project, service,
            duration_min, notes, is_rnd, external_id, external_source,
            created_by, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        `).bind(
          crypto.randomUUID(),
          tenantId,
          // TENANT ISOLATION
          entry.date || (/* @__PURE__ */ new Date()).toISOString().split("T")[0],
          entry.clientName || "Unknown Client",
          entry.serviceName || "Unknown Service",
          entry.description || "CentralReach Activity",
          entry.duration || 0,
          entry.notes || null,
          true,
          // Assume R&D for now
          entry.id,
          "centralreach",
          userId
        )
      );
      await withRetry(async () => {
        return c.env.DB.batch(batchStatements);
      }, 3);
      results.push({
        type: "timeentries",
        success: true,
        count: timeEntries.length,
        message: `Synced ${timeEntries.length} time entries`
      });
    }
    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: "sync",
      resource_type: "centralreach",
      ip_address: c.get("user_ip"),
      new_values: JSON.stringify({ syncType, results })
    });
    return c.json({
      success: true,
      results,
      syncedAt: (/* @__PURE__ */ new Date()).toISOString()
    });
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({
        error: "Invalid sync request",
        details: error.errors.map((e) => e.message).join(", "),
        code: "VALIDATION_ERROR"
      }, 400);
    }
    console.error("CentralReach sync error:", error);
    return c.json({
      error: "Sync failed",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "SYNC_ERROR"
    }, 500);
  }
});

// src/routes/quickBooks.ts
init_checked_fetch();
init_modules_watch_stub();
var quickBooksRouter = new Hono2();
var configSchema = external_exports.object({
  companyId: external_exports.string().min(1),
  accessToken: external_exports.string().min(1),
  refreshToken: external_exports.string().optional(),
  sandbox: external_exports.boolean().default(true)
});
async function makeQuickBooksRequest(env, endpoint, companyId, accessToken, options = {}) {
  const { method = "GET", body } = options;
  const baseUrl = "https://sandbox-quickbooks.api.intuit.com";
  const url = `${baseUrl}/v3/company/${companyId}/${endpoint}`;
  return withRetry(async () => {
    const response = await fetch(url, {
      method,
      headers: {
        "Authorization": `Bearer ${accessToken}`,
        "Accept": "application/json",
        "Content-Type": "application/json"
      },
      body,
      signal: AbortSignal.timeout(3e4)
      // 30 second timeout
    });
    if (!response.ok) {
      if (response.status === 429) {
        const retryAfter = response.headers.get("Retry-After");
        const delay = retryAfter ? parseInt(retryAfter) * 1e3 : 5e3;
        const error = new Error(`Rate limited. Retry after ${delay}ms`);
        error.cause = "rate_limit";
        throw error;
      }
      if (response.status >= 400 && response.status < 500) {
        const error = new Error(`QuickBooks API Error: ${response.status} ${response.statusText}`);
        error.cause = "client_error";
        throw error;
      }
      throw new Error(`QuickBooks API Error: ${response.status} ${response.statusText}`);
    }
    return response;
  }, 3, (attempt, error) => {
    if (error instanceof Error && error.cause === "rate_limit") {
      const match = error.message.match(/Retry after (\d+)ms/);
      return match ? parseInt(match[1]) : 5e3;
    }
    return Math.min(1e3 * Math.pow(2, attempt - 1), 1e4);
  });
}
__name(makeQuickBooksRequest, "makeQuickBooksRequest");
quickBooksRouter.get("/customers", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "clients:read");
    const configKey = `quickbooks:config:${tenantId}`;
    const configData = await c.env.KV.get(configKey);
    if (!configData) {
      return c.json({
        error: "QuickBooks not configured",
        code: "NOT_CONFIGURED"
      }, 400);
    }
    const config = configSchema.parse(JSON.parse(configData));
    const cacheKey = `quickbooks:customers:${tenantId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }
    const response = await makeQuickBooksRequest(
      c.env,
      "customers",
      config.companyId,
      config.accessToken
    );
    const data = await response.json();
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 7200 });
    return c.json(data);
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({
        error: "Invalid QuickBooks configuration",
        details: error.errors.map((e) => e.message).join(", "),
        code: "VALIDATION_ERROR"
      }, 400);
    }
    console.error("QuickBooks customers error:", error);
    const status = error instanceof Error && error.cause === "client_error" ? 400 : 500;
    return c.json({
      error: "Failed to fetch customers from QuickBooks",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "QUICKBOOKS_ERROR"
    }, status);
  }
});
quickBooksRouter.get("/employees", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "users:read");
    const configKey = `quickbooks:config:${tenantId}`;
    const configData = await c.env.KV.get(configKey);
    if (!configData) {
      return c.json({
        error: "QuickBooks not configured",
        code: "NOT_CONFIGURED"
      }, 400);
    }
    const config = configSchema.parse(JSON.parse(configData));
    const cacheKey = `quickbooks:employees:${tenantId}`;
    const cached = await c.env.KV.get(cacheKey);
    if (cached) {
      return c.json(JSON.parse(cached));
    }
    const response = await makeQuickBooksRequest(
      c.env,
      "employees",
      config.companyId,
      config.accessToken
    );
    const data = await response.json();
    await c.env.KV.put(cacheKey, JSON.stringify(data), { expirationTtl: 14400 });
    return c.json(data);
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({
        error: "Invalid QuickBooks configuration",
        details: error.errors.map((e) => e.message).join(", "),
        code: "VALIDATION_ERROR"
      }, 400);
    }
    console.error("QuickBooks employees error:", error);
    const status = error instanceof Error && error.cause === "client_error" ? 400 : 500;
    return c.json({
      error: "Failed to fetch employees from QuickBooks",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "QUICKBOOKS_ERROR"
    }, status);
  }
});
quickBooksRouter.post("/config", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const userId = c.get("user_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "system:manage");
    const body = await c.req.json();
    const config = configSchema.parse(body);
    const configKey = `quickbooks:config:${tenantId}`;
    await c.env.KV.put(configKey, JSON.stringify(config));
    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: "update",
      resource_type: "quickbooks_config",
      ip_address: c.get("user_ip"),
      new_values: JSON.stringify({ companyId: config.companyId, sandbox: config.sandbox })
    });
    return c.json({ success: true });
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({
        error: "Invalid configuration",
        details: error.errors.map((e) => e.message).join(", "),
        code: "VALIDATION_ERROR"
      }, 400);
    }
    console.error("QuickBooks config error:", error);
    return c.json({
      error: "Failed to save configuration",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "CONFIG_ERROR"
    }, 500);
  }
});

// src/routes/auth.ts
init_checked_fetch();
init_modules_watch_stub();

// src/utils/auth.ts
init_checked_fetch();
init_modules_watch_stub();
async function base64UrlEncode(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
}
__name(base64UrlEncode, "base64UrlEncode");
function base64UrlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}
__name(base64UrlDecode, "base64UrlDecode");
async function importKey(secret) {
  const enc = new TextEncoder();
  return await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}
__name(importKey, "importKey");
async function signJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const enc = new TextEncoder();
  const encodedHeader = await base64UrlEncode(enc.encode(JSON.stringify(header)));
  const encodedPayload = await base64UrlEncode(enc.encode(JSON.stringify(payload)));
  const key = await importKey(secret);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(`${encodedHeader}.${encodedPayload}`)
  );
  const encodedSignature = await base64UrlEncode(signature);
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}
__name(signJWT, "signJWT");
async function verifyJWT(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token format");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const enc = new TextEncoder();
  const key = await importKey(secret);
  const signature = base64UrlDecode(encodedSignature);
  const isValid2 = await crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    enc.encode(`${encodedHeader}.${encodedPayload}`)
  );
  if (!isValid2) {
    throw new Error("Invalid signature");
  }
  const payload = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(encodedPayload))
  );
  if (payload.exp && payload.exp < Date.now() / 1e3) {
    throw new Error("Token expired");
  }
  return payload;
}
__name(verifyJWT, "verifyJWT");
async function signRefreshToken(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const enc = new TextEncoder();
  const encodedHeader = await base64UrlEncode(enc.encode(JSON.stringify(header)));
  const encodedPayload = await base64UrlEncode(enc.encode(JSON.stringify(payload)));
  const key = await importKey(secret);
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    enc.encode(`${encodedHeader}.${encodedPayload}`)
  );
  const encodedSignature = await base64UrlEncode(signature);
  return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
}
__name(signRefreshToken, "signRefreshToken");
async function verifyRefreshToken(token, secret) {
  const parts = token.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid token format");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const enc = new TextEncoder();
  const key = await importKey(secret);
  const signature = base64UrlDecode(encodedSignature);
  const isValid2 = await crypto.subtle.verify(
    "HMAC",
    key,
    signature,
    enc.encode(`${encodedHeader}.${encodedPayload}`)
  );
  if (!isValid2) {
    throw new Error("Invalid signature");
  }
  const payload = JSON.parse(
    new TextDecoder().decode(base64UrlDecode(encodedPayload))
  );
  if (payload.exp && payload.exp < Date.now() / 1e3) {
    throw new Error("Token expired");
  }
  return payload;
}
__name(verifyRefreshToken, "verifyRefreshToken");
async function hashPassword(password) {
  const enc = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", enc.encode(password));
  return await base64UrlEncode(hash);
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, hash) {
  const passwordHash = await hashPassword(password);
  return passwordHash === hash;
}
__name(verifyPassword, "verifyPassword");
function generateTokenId() {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join("");
}
__name(generateTokenId, "generateTokenId");
async function createScopedToken(userId, email, role, userType, tenantId, secret, readOnly = false, expiryMinutes = 30) {
  const now = Math.floor(Date.now() / 1e3);
  const payload = {
    user_id: userId,
    email,
    role,
    user_type: userType,
    tenant_id: tenantId,
    acting_as: "tenant",
    read_only: readOnly,
    exp: now + expiryMinutes * 60,
    iat: now
  };
  return signJWT(payload, secret);
}
__name(createScopedToken, "createScopedToken");
function determinUserType(email) {
  const lowercaseEmail = email.toLowerCase();
  return lowercaseEmail.endsWith("@roiblueprint.com") ? "platform" : "tenant";
}
__name(determinUserType, "determinUserType");

// src/routes/auth.ts
init_hipaa_security();
var authRouter = new Hono2();
var registerSchema = external_exports.object({
  email: external_exports.string().email(),
  password: external_exports.string().min(8),
  name: external_exports.string().optional()
});
var loginSchema = external_exports.object({
  email: external_exports.string().email(),
  password: external_exports.string().min(6)
});
var refreshTokenSchema = external_exports.object({
  refreshToken: external_exports.string()
});
authRouter.post("/register", async (c) => {
  try {
    const body = await c.req.json();
    const { email, password, name } = registerSchema.parse(body);
    const passwordValidation = validatePassword(password, { name, email });
    if (!passwordValidation.valid) {
      return c.json({
        error: "Password does not meet security requirements",
        details: passwordValidation.errors
      }, 400);
    }
    const existingUser = await c.env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(email).first();
    if (existingUser) {
      return c.json({ error: "Email already registered" }, 400);
    }
    const passwordHash = await hashPassword(password);
    const userId = generateTokenId();
    const userType = determinUserType(email);
    const tenantId = userType === "tenant" ? "default" : null;
    const now = Math.floor(Date.now() / 1e3);
    await c.env.DB.prepare(
      "INSERT INTO users (id, email, password_hash, name, role, user_type, tenant_id, password_last_changed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(userId, email, passwordHash, name || "", "user", userType, tenantId, now).run();
    await c.env.DB.prepare(
      "INSERT INTO password_history (user_id, password_hash) VALUES (?, ?)"
    ).bind(userId, passwordHash).run();
    if (userType === "platform") {
      await auditLogger(c.env, {
        tenant_id: "platform",
        user_id: userId,
        action: "register",
        resource_type: "auth",
        ip_address: c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown",
        user_agent: c.req.header("User-Agent")
      });
      return c.json({
        success: true,
        requiresTenantSelection: true,
        user: {
          id: userId,
          email,
          name: name || "",
          role: "user",
          user_type: userType
        }
      });
    }
    const accessTokenPayload = {
      user_id: userId,
      email,
      role: "user",
      user_type: userType,
      tenant_id: tenantId,
      exp: now + 60 * 60,
      iat: now
    };
    const accessToken = await signJWT(accessTokenPayload, c.env.JWT_SECRET);
    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: "register",
      resource_type: "auth",
      ip_address: c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown",
      user_agent: c.req.header("User-Agent")
    });
    return c.json({
      success: true,
      accessToken,
      user: {
        id: userId,
        email,
        name: name || "",
        role: "user",
        user_type: userType,
        tenant_id: tenantId
      }
    });
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({ error: "Invalid request data", details: error.errors }, 400);
    }
    console.error("Registration error:", error);
    return c.json({ error: "Registration failed" }, 500);
  }
});
authRouter.post("/login", async (c) => {
  try {
    const body = await c.req.json();
    const { email, password } = loginSchema.parse(body);
    const now = Math.floor(Date.now() / 1e3);
    const user = await c.env.DB.prepare(
      "SELECT id, email, password_hash, name, role, user_type, tenant_id, status, failed_login_attempts, account_locked_until, mfa_enabled, mfa_secret FROM users WHERE email = ?"
    ).bind(email).first();
    if (!user) {
      await auditLogger(c.env, {
        tenant_id: "system",
        user_id: "anonymous",
        action: "login_failed",
        resource_type: "auth",
        ip_address: c.req.header("CF-Connecting-IP") || "unknown",
        user_agent: c.req.header("User-Agent"),
        details: JSON.stringify({ reason: "user_not_found", email })
      });
      return c.json({ error: "Invalid email or password" }, 401);
    }
    if (user.status !== "active") {
      return c.json({ error: "Account is not active" }, 403);
    }
    if (isAccountLocked(user.account_locked_until)) {
      const lockedUntil = new Date(user.account_locked_until * 1e3);
      await auditLogger(c.env, {
        tenant_id: user.tenant_id || "platform",
        user_id: user.id,
        action: "login_blocked",
        resource_type: "auth",
        ip_address: c.req.header("CF-Connecting-IP") || "unknown",
        user_agent: c.req.header("User-Agent"),
        details: JSON.stringify({ reason: "account_locked", locked_until: lockedUntil.toISOString() })
      });
      return c.json({
        error: "Account is temporarily locked due to multiple failed login attempts",
        locked_until: lockedUntil.toISOString()
      }, 403);
    }
    const isValidPassword = await verifyPassword(password, user.password_hash);
    if (!isValidPassword) {
      const currentAttempts = (user.failed_login_attempts || 0) + 1;
      const shouldLock = currentAttempts >= HIPAA_LOCKOUT_POLICY.maxFailedAttempts;
      const lockedUntil = shouldLock ? calculateLockoutEnd() : null;
      await c.env.DB.prepare(
        "UPDATE users SET failed_login_attempts = ?, account_locked_until = ? WHERE id = ?"
      ).bind(currentAttempts, lockedUntil, user.id).run();
      await auditLogger(c.env, {
        tenant_id: user.tenant_id || "platform",
        user_id: user.id,
        action: "login_failed",
        resource_type: "auth",
        ip_address: c.req.header("CF-Connecting-IP") || "unknown",
        user_agent: c.req.header("User-Agent"),
        details: JSON.stringify({
          reason: "invalid_password",
          attempts: currentAttempts,
          locked: shouldLock
        })
      });
      if (shouldLock) {
        return c.json({
          error: "Account has been locked due to multiple failed login attempts",
          locked_until: new Date(lockedUntil * 1e3).toISOString()
        }, 403);
      }
      return c.json({
        error: "Invalid email or password",
        attempts_remaining: HIPAA_LOCKOUT_POLICY.maxFailedAttempts - currentAttempts
      }, 401);
    }
    await c.env.DB.prepare(
      "UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL, last_login_at = ?, last_login_ip = ? WHERE id = ?"
    ).bind(now, c.req.header("CF-Connecting-IP") || "unknown", user.id).run();
    const userType = user.user_type;
    if (user.mfa_enabled) {
      return c.json({
        success: true,
        requiresMFA: true,
        userId: user.id,
        email: user.email
      });
    }
    if (userType === "platform") {
      await auditLogger(c.env, {
        tenant_id: "platform",
        user_id: user.id,
        action: "login",
        resource_type: "auth",
        ip_address: c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown",
        user_agent: c.req.header("User-Agent")
      });
      return c.json({
        success: true,
        requiresTenantSelection: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          user_type: userType
        }
      });
    }
    const sessionId = generateTokenId();
    const accessTokenPayload = {
      user_id: user.id,
      email: user.email,
      role: user.role,
      user_type: userType,
      tenant_id: user.tenant_id,
      exp: now + 60 * 60,
      iat: now
    };
    const refreshTokenPayload = {
      user_id: user.id,
      session_id: sessionId,
      exp: now + 60 * 60 * 24 * 7,
      iat: now
    };
    const accessToken = await signJWT(accessTokenPayload, c.env.JWT_SECRET);
    const refreshToken = await signRefreshToken(refreshTokenPayload, c.env.JWT_SECRET);
    await c.env.DB.prepare(
      "INSERT INTO sessions (id, user_id, refresh_token, expires_at, last_activity, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      sessionId,
      user.id,
      refreshToken,
      now + 60 * 60 * 24 * 7,
      now,
      c.req.header("CF-Connecting-IP") || "unknown",
      c.req.header("User-Agent")
    ).run();
    await auditLogger(c.env, {
      tenant_id: user.tenant_id,
      user_id: user.id,
      action: "login",
      resource_type: "auth",
      ip_address: c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown",
      user_agent: c.req.header("User-Agent")
    });
    return c.json({
      success: true,
      accessToken,
      refreshToken,
      sessionId,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        user_type: userType,
        tenant_id: user.tenant_id
      }
    });
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({ error: "Invalid request data", details: error.errors }, 400);
    }
    console.error("Login error:", error);
    return c.json({ error: "Login failed" }, 500);
  }
});
authRouter.post("/refresh", async (c) => {
  try {
    const body = await c.req.json();
    const { refreshToken } = refreshTokenSchema.parse(body);
    const payload = await verifyRefreshToken(refreshToken, c.env.JWT_SECRET);
    const session = await c.env.DB.prepare(
      "SELECT id, user_id, expires_at, last_activity, created_at FROM sessions WHERE id = ? AND refresh_token = ?"
    ).bind(payload.session_id, refreshToken).first();
    if (!session) {
      return c.json({ error: "Invalid refresh token" }, 401);
    }
    const now = Math.floor(Date.now() / 1e3);
    if (session.expires_at < now) {
      await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(session.id).run();
      return c.json({ error: "Refresh token expired" }, 401);
    }
    const sessionExpiry = isSessionExpired(
      session.last_activity,
      session.created_at
    );
    if (sessionExpiry.expired) {
      await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(session.id).run();
      await auditLogger(c.env, {
        tenant_id: "system",
        user_id: session.user_id,
        action: "session_expired",
        resource_type: "auth",
        ip_address: c.req.header("CF-Connecting-IP") || "unknown",
        user_agent: c.req.header("User-Agent"),
        details: JSON.stringify({ reason: sessionExpiry.reason })
      });
      return c.json({
        error: `Session expired due to ${sessionExpiry.reason}`,
        reason: sessionExpiry.reason
      }, 401);
    }
    await c.env.DB.prepare(
      "UPDATE sessions SET last_activity = ? WHERE id = ?"
    ).bind(now, session.id).run();
    const user = await c.env.DB.prepare(
      "SELECT id, email, role FROM users WHERE id = ?"
    ).bind(session.user_id).first();
    if (!user) {
      return c.json({ error: "User not found" }, 401);
    }
    const accessTokenPayload = {
      user_id: user.id,
      email: user.email,
      role: user.role,
      exp: now + 60 * 60,
      iat: now
    };
    const newAccessToken = await signJWT(accessTokenPayload, c.env.JWT_SECRET);
    return c.json({
      success: true,
      accessToken: newAccessToken
    });
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({ error: "Invalid request data", details: error.errors }, 400);
    }
    console.error("Token refresh error:", error);
    return c.json({ error: "Token refresh failed" }, 401);
  }
});
authRouter.post("/logout", async (c) => {
  try {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Missing authorization header" }, 401);
    }
    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    await c.env.DB.prepare(
      "DELETE FROM sessions WHERE user_id = ?"
    ).bind(payload.user_id).run();
    await auditLogger(c.env, {
      tenant_id: "default",
      user_id: payload.user_id,
      action: "logout",
      resource_type: "auth",
      ip_address: c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown",
      user_agent: c.req.header("User-Agent")
    });
    return c.json({ success: true });
  } catch (error) {
    console.error("Logout error:", error);
    return c.json({ error: "Logout failed" }, 500);
  }
});
authRouter.get("/me", async (c) => {
  try {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Missing authorization header" }, 401);
    }
    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    const user = await c.env.DB.prepare(
      "SELECT id, email, name, role, user_type, tenant_id FROM users WHERE id = ?"
    ).bind(payload.user_id).first();
    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }
    return c.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        user_type: user.user_type,
        tenant_id: user.tenant_id,
        current_tenant_id: payload.tenant_id,
        read_only: payload.read_only || false
      }
    });
  } catch (error) {
    console.error("Get user error:", error);
    return c.json({ error: "Failed to get user info" }, 401);
  }
});
var tenantSelectionSchema = external_exports.object({
  userId: external_exports.string(),
  tenantId: external_exports.string(),
  readOnly: external_exports.boolean().optional()
});
authRouter.get("/tenants", async (c) => {
  try {
    const authHeader = c.req.header("Authorization");
    if (authHeader && authHeader.startsWith("Bearer ")) {
      const token = authHeader.substring(7);
      const payload = await verifyJWT(token, c.env.JWT_SECRET);
      if (payload.user_type !== "platform") {
        return c.json({ error: "Only platform admins can list tenants" }, 403);
      }
    }
    const result = await c.env.DB.prepare(
      "SELECT id, name, domain, active, created_at FROM tenants WHERE active = 1 ORDER BY name"
    ).all();
    return c.json({
      success: true,
      tenants: result.results || []
    });
  } catch (error) {
    console.error("List tenants error:", error);
    return c.json({ error: "Failed to list tenants" }, 500);
  }
});
authRouter.post("/select-tenant", async (c) => {
  try {
    const body = await c.req.json();
    const { userId, tenantId, readOnly } = tenantSelectionSchema.parse(body);
    const user = await c.env.DB.prepare(
      "SELECT id, email, name, role, user_type FROM users WHERE id = ?"
    ).bind(userId).first();
    if (!user) {
      return c.json({ error: "User not found" }, 404);
    }
    if (user.user_type !== "platform") {
      return c.json({ error: "Only platform admins can select tenants" }, 403);
    }
    const tenant = await c.env.DB.prepare(
      "SELECT id, name FROM tenants WHERE id = ?"
    ).bind(tenantId).first();
    if (!tenant) {
      return c.json({ error: "Tenant not found" }, 404);
    }
    const previousTenant = await c.env.DB.prepare(
      "SELECT to_tenant_id FROM tenant_switches WHERE admin_id = ? ORDER BY switched_at DESC LIMIT 1"
    ).bind(userId).first();
    await c.env.DB.prepare(
      "INSERT INTO tenant_switches (admin_id, from_tenant_id, to_tenant_id, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)"
    ).bind(
      userId,
      previousTenant?.to_tenant_id || null,
      tenantId,
      c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown",
      c.req.header("User-Agent")
    ).run();
    const scopedToken = await createScopedToken(
      user.id,
      user.email,
      user.role,
      "platform",
      tenantId,
      c.env.JWT_SECRET,
      readOnly || false,
      30
    );
    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: userId,
      action: "tenant_selected",
      resource_type: "auth",
      resource_id: tenantId,
      ip_address: c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown",
      user_agent: c.req.header("User-Agent"),
      details: JSON.stringify({
        tenant_name: tenant.name,
        read_only: readOnly || false,
        from_tenant: previousTenant?.to_tenant_id
      })
    });
    return c.json({
      success: true,
      accessToken: scopedToken,
      tenant: {
        id: tenant.id,
        name: tenant.name
      },
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        user_type: user.user_type
      }
    });
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({ error: "Invalid request data", details: error.errors }, 400);
    }
    console.error("Tenant selection error:", error);
    return c.json({ error: "Tenant selection failed" }, 500);
  }
});
authRouter.post("/switch-tenant", async (c) => {
  try {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Missing authorization header" }, 401);
    }
    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    if (payload.user_type !== "platform") {
      return c.json({ error: "Only platform admins can switch tenants" }, 403);
    }
    const body = await c.req.json();
    const { tenantId, readOnly } = external_exports.object({
      tenantId: external_exports.string(),
      readOnly: external_exports.boolean().optional()
    }).parse(body);
    const tenant = await c.env.DB.prepare(
      "SELECT id, name FROM tenants WHERE id = ?"
    ).bind(tenantId).first();
    if (!tenant) {
      return c.json({ error: "Tenant not found" }, 404);
    }
    await c.env.DB.prepare(
      "INSERT INTO tenant_switches (admin_id, from_tenant_id, to_tenant_id, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)"
    ).bind(
      payload.user_id,
      payload.tenant_id || null,
      tenantId,
      c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown",
      c.req.header("User-Agent")
    ).run();
    const scopedToken = await createScopedToken(
      payload.user_id,
      payload.email,
      payload.role,
      "platform",
      tenantId,
      c.env.JWT_SECRET,
      readOnly || false,
      30
    );
    await auditLogger(c.env, {
      tenant_id: tenantId,
      user_id: payload.user_id,
      action: "tenant_switched",
      resource_type: "auth",
      resource_id: tenantId,
      ip_address: c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown",
      user_agent: c.req.header("User-Agent"),
      details: JSON.stringify({
        tenant_name: tenant.name,
        read_only: readOnly || false,
        from_tenant: payload.tenant_id
      })
    });
    return c.json({
      success: true,
      accessToken: scopedToken,
      tenant: {
        id: tenant.id,
        name: tenant.name
      }
    });
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({ error: "Invalid request data", details: error.errors }, 400);
    }
    console.error("Tenant switch error:", error);
    return c.json({ error: "Tenant switch failed" }, 500);
  }
});
var mfaSetupSchema = external_exports.object({
  userId: external_exports.string()
});
var mfaVerifySchema = external_exports.object({
  userId: external_exports.string(),
  token: external_exports.string().length(6)
});
var mfaLoginSchema = external_exports.object({
  userId: external_exports.string(),
  token: external_exports.string().length(6)
});
authRouter.post("/mfa/setup", async (c) => {
  try {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Missing authorization header" }, 401);
    }
    const jwtToken = authHeader.substring(7);
    const payload = await verifyJWT(jwtToken, c.env.JWT_SECRET);
    const { generateMFASecret: generateMFASecret2, generateMFABackupCodes: generateMFABackupCodes2 } = await Promise.resolve().then(() => (init_hipaa_security(), hipaa_security_exports));
    const secret = generateMFASecret2();
    const backupCodes = generateMFABackupCodes2();
    await c.env.DB.prepare(
      "UPDATE users SET mfa_secret = ?, mfa_backup_codes = ? WHERE id = ?"
    ).bind(secret, JSON.stringify(backupCodes), payload.user_id).run();
    const user = await c.env.DB.prepare(
      "SELECT email FROM users WHERE id = ?"
    ).bind(payload.user_id).first();
    const otpauthUrl = `otpauth://totp/ROI%20Blueprint:${encodeURIComponent(user?.email)}?secret=${secret}&issuer=ROI%20Blueprint`;
    await auditLogger(c.env, {
      tenant_id: payload.tenant_id || "platform",
      user_id: payload.user_id,
      action: "mfa_setup_initiated",
      resource_type: "auth",
      ip_address: c.req.header("CF-Connecting-IP") || "unknown",
      user_agent: c.req.header("User-Agent")
    });
    return c.json({
      success: true,
      secret,
      otpauthUrl,
      backupCodes
    });
  } catch (error) {
    console.error("MFA setup error:", error);
    return c.json({ error: "Failed to setup MFA" }, 500);
  }
});
authRouter.post("/mfa/verify-setup", async (c) => {
  try {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Missing authorization header" }, 401);
    }
    const jwtToken = authHeader.substring(7);
    const payload = await verifyJWT(jwtToken, c.env.JWT_SECRET);
    const body = await c.req.json();
    const { token } = external_exports.object({ token: external_exports.string().length(6) }).parse(body);
    const user = await c.env.DB.prepare(
      "SELECT mfa_secret FROM users WHERE id = ?"
    ).bind(payload.user_id).first();
    if (!user || !user.mfa_secret) {
      return c.json({ error: "MFA not set up" }, 400);
    }
    const { verifyTOTP: verifyTOTP2 } = await Promise.resolve().then(() => (init_hipaa_security(), hipaa_security_exports));
    const isValid2 = verifyTOTP2(user.mfa_secret, token);
    if (!isValid2) {
      return c.json({ error: "Invalid MFA token" }, 401);
    }
    const now = Math.floor(Date.now() / 1e3);
    await c.env.DB.prepare(
      "UPDATE users SET mfa_enabled = 1, mfa_enabled_at = ? WHERE id = ?"
    ).bind(now, payload.user_id).run();
    await auditLogger(c.env, {
      tenant_id: payload.tenant_id || "platform",
      user_id: payload.user_id,
      action: "mfa_enabled",
      resource_type: "auth",
      ip_address: c.req.header("CF-Connecting-IP") || "unknown",
      user_agent: c.req.header("User-Agent")
    });
    return c.json({
      success: true,
      message: "MFA enabled successfully"
    });
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({ error: "Invalid request data", details: error.errors }, 400);
    }
    console.error("MFA verification error:", error);
    return c.json({ error: "Failed to verify MFA" }, 500);
  }
});
authRouter.post("/mfa/verify-login", async (c) => {
  try {
    const body = await c.req.json();
    const { userId, token } = mfaLoginSchema.parse(body);
    const user = await c.env.DB.prepare(
      "SELECT id, email, name, role, user_type, tenant_id, mfa_secret, mfa_backup_codes, mfa_enabled FROM users WHERE id = ?"
    ).bind(userId).first();
    if (!user || !user.mfa_enabled) {
      return c.json({ error: "MFA not enabled for this account" }, 400);
    }
    const { verifyTOTP: verifyTOTP2 } = await Promise.resolve().then(() => (init_hipaa_security(), hipaa_security_exports));
    let isValid2 = verifyTOTP2(user.mfa_secret, token);
    if (!isValid2 && user.mfa_backup_codes) {
      const backupCodes = JSON.parse(user.mfa_backup_codes);
      const codeIndex = backupCodes.indexOf(token);
      if (codeIndex !== -1) {
        isValid2 = true;
        backupCodes.splice(codeIndex, 1);
        await c.env.DB.prepare(
          "UPDATE users SET mfa_backup_codes = ? WHERE id = ?"
        ).bind(JSON.stringify(backupCodes), userId).run();
      }
    }
    if (!isValid2) {
      await auditLogger(c.env, {
        tenant_id: user.tenant_id || "platform",
        user_id: userId,
        action: "mfa_verification_failed",
        resource_type: "auth",
        ip_address: c.req.header("CF-Connecting-IP") || "unknown",
        user_agent: c.req.header("User-Agent")
      });
      return c.json({ error: "Invalid MFA token" }, 401);
    }
    const now = Math.floor(Date.now() / 1e3);
    const userType = user.user_type;
    if (userType === "platform") {
      await auditLogger(c.env, {
        tenant_id: "platform",
        user_id: user.id,
        action: "mfa_login_success",
        resource_type: "auth",
        ip_address: c.req.header("CF-Connecting-IP") || "unknown",
        user_agent: c.req.header("User-Agent")
      });
      return c.json({
        success: true,
        requiresTenantSelection: true,
        user: {
          id: user.id,
          email: user.email,
          name: user.name,
          role: user.role,
          user_type: userType
        }
      });
    }
    const sessionId = generateTokenId();
    const accessTokenPayload = {
      user_id: user.id,
      email: user.email,
      role: user.role,
      user_type: userType,
      tenant_id: user.tenant_id,
      exp: now + 60 * 60,
      iat: now
    };
    const refreshTokenPayload = {
      user_id: user.id,
      session_id: sessionId,
      exp: now + 60 * 60 * 24 * 7,
      iat: now
    };
    const accessToken = await signJWT(accessTokenPayload, c.env.JWT_SECRET);
    const refreshToken = await signRefreshToken(refreshTokenPayload, c.env.JWT_SECRET);
    await c.env.DB.prepare(
      "INSERT INTO sessions (id, user_id, refresh_token, expires_at, last_activity, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      sessionId,
      user.id,
      refreshToken,
      now + 60 * 60 * 24 * 7,
      now,
      c.req.header("CF-Connecting-IP") || "unknown",
      c.req.header("User-Agent")
    ).run();
    await auditLogger(c.env, {
      tenant_id: user.tenant_id,
      user_id: user.id,
      action: "mfa_login_success",
      resource_type: "auth",
      ip_address: c.req.header("CF-Connecting-IP") || "unknown",
      user_agent: c.req.header("User-Agent")
    });
    return c.json({
      success: true,
      accessToken,
      refreshToken,
      sessionId,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
        user_type: userType,
        tenant_id: user.tenant_id
      }
    });
  } catch (error) {
    if (error instanceof external_exports.ZodError) {
      return c.json({ error: "Invalid request data", details: error.errors }, 400);
    }
    console.error("MFA login verification error:", error);
    return c.json({ error: "MFA verification failed" }, 500);
  }
});
authRouter.post("/mfa/disable", async (c) => {
  try {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Missing authorization header" }, 401);
    }
    const jwtToken = authHeader.substring(7);
    const payload = await verifyJWT(jwtToken, c.env.JWT_SECRET);
    await c.env.DB.prepare(
      "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_backup_codes = NULL, mfa_enabled_at = NULL WHERE id = ?"
    ).bind(payload.user_id).run();
    await auditLogger(c.env, {
      tenant_id: payload.tenant_id || "platform",
      user_id: payload.user_id,
      action: "mfa_disabled",
      resource_type: "auth",
      ip_address: c.req.header("CF-Connecting-IP") || "unknown",
      user_agent: c.req.header("User-Agent")
    });
    return c.json({
      success: true,
      message: "MFA disabled successfully"
    });
  } catch (error) {
    console.error("MFA disable error:", error);
    return c.json({ error: "Failed to disable MFA" }, 500);
  }
});
authRouter.get("/mfa/backup-codes", async (c) => {
  try {
    const authHeader = c.req.header("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Missing authorization header" }, 401);
    }
    const jwtToken = authHeader.substring(7);
    const payload = await verifyJWT(jwtToken, c.env.JWT_SECRET);
    const user = await c.env.DB.prepare(
      "SELECT mfa_backup_codes FROM users WHERE id = ?"
    ).bind(payload.user_id).first();
    if (!user || !user.mfa_backup_codes) {
      return c.json({ error: "No backup codes available" }, 404);
    }
    const backupCodes = JSON.parse(user.mfa_backup_codes);
    return c.json({
      success: true,
      backupCodes
    });
  } catch (error) {
    console.error("Get backup codes error:", error);
    return c.json({ error: "Failed to get backup codes" }, 500);
  }
});
authRouter.post("/session/ping", async (c) => {
  try {
    const sessionId = c.req.header("X-Session-ID");
    const authHeader = c.req.header("Authorization");
    if (!sessionId) {
      return c.json({ error: "Missing session ID" }, 401);
    }
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return c.json({ error: "Missing authorization header" }, 401);
    }
    const token = authHeader.substring(7);
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    const session = await c.env.DB.prepare(
      "SELECT id, user_id, expires_at, last_activity, created_at FROM sessions WHERE id = ? AND user_id = ?"
    ).bind(sessionId, payload.user_id).first();
    if (!session) {
      return c.json({ error: "Session not found" }, 404);
    }
    const now = Math.floor(Date.now() / 1e3);
    if (session.expires_at < now) {
      await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
      return c.json({ error: "Session expired" }, 401);
    }
    const sessionExpiry = isSessionExpired(
      session.last_activity,
      session.created_at
    );
    if (sessionExpiry.expired) {
      await c.env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
      return c.json({
        error: "Session expired",
        reason: sessionExpiry.reason
      }, 401);
    }
    await c.env.DB.prepare(
      "UPDATE sessions SET last_activity = ? WHERE id = ?"
    ).bind(now, sessionId).run();
    return c.json({
      success: true,
      message: "Session updated",
      expiresIn: {
        absolute: session.created_at + 8 * 60 * 60 - now,
        idle: session.last_activity + 15 * 60 - now
      }
    });
  } catch (error) {
    console.error("Session ping error:", error);
    return c.json({ error: "Failed to update session" }, 500);
  }
});

// src/routes/analytics.ts
init_checked_fetch();
init_modules_watch_stub();
var analyticsRouter = new Hono2();
analyticsRouter.get("/dashboard", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "analytics:read");
    const from = c.req.query("from") ?? "0000-01-01";
    const to = c.req.query("to") ?? "9999-12-31";
    const dateRange = dateRangeSchema.safeParse({ from, to });
    if (!dateRange.success) {
      return c.json({
        error: "Invalid date range",
        details: dateRange.error.errors.map((e) => e.message).join(", "),
        code: "VALIDATION_ERROR"
      }, 400);
    }
    const cacheKey = buildCacheKey("analytics:dashboard", {
      tenantId,
      from,
      to
    });
    const queries = new TimeEntriesQueries(c.env);
    const data = await getCachedOrCompute(
      c.env.KV,
      cacheKey,
      300,
      async () => {
        const [stats, projectBreakdown] = await Promise.all([
          queries.getAggregatedStats(tenantId, from, to),
          queries.getProjectBreakdown(tenantId, from, to, 20)
        ]);
        return {
          stats,
          projectBreakdown,
          generatedAt: (/* @__PURE__ */ new Date()).toISOString()
        };
      }
    );
    return c.json({
      data,
      cached: true,
      ttl: 300
    });
  } catch (error) {
    console.error("Error fetching analytics:", error);
    return c.json({
      error: "Failed to fetch analytics",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "ANALYTICS_ERROR"
    }, 500);
  }
});
analyticsRouter.get("/time-summary", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "analytics:read");
    const from = c.req.query("from") ?? "0000-01-01";
    const to = c.req.query("to") ?? "9999-12-31";
    const dateRange = dateRangeSchema.safeParse({ from, to });
    if (!dateRange.success) {
      return c.json({
        error: "Invalid date range",
        code: "VALIDATION_ERROR"
      }, 400);
    }
    const cacheKey = buildCacheKey("analytics:time-summary", {
      tenantId,
      from,
      to
    });
    const queries = new TimeEntriesQueries(c.env);
    const data = await getCachedOrCompute(
      c.env.KV,
      cacheKey,
      600,
      async () => {
        const stats = await queries.getAggregatedStats(tenantId, from, to);
        return {
          totalHours: Math.round(stats.totalMinutes / 60 * 100) / 100,
          totalRnDHours: Math.round(stats.totalRnDMinutes / 60 * 100) / 100,
          totalEntries: stats.totalEntries,
          projectCount: stats.projectCount,
          clientCount: stats.clientCount,
          rndPercentage: stats.totalMinutes > 0 ? Math.round(stats.totalRnDMinutes / stats.totalMinutes * 100) : 0,
          generatedAt: (/* @__PURE__ */ new Date()).toISOString()
        };
      }
    );
    return c.json({ data });
  } catch (error) {
    console.error("Error fetching time summary:", error);
    return c.json({
      error: "Failed to fetch time summary",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "ANALYTICS_ERROR"
    }, 500);
  }
});
analyticsRouter.post("/invalidate-cache", async (c) => {
  try {
    const tenantId = c.get("tenant_id");
    const securityContext = createSecurityContext(c);
    requirePermission(securityContext, "analytics:write");
    const prefix = `analytics:${tenantId}`;
    await invalidateCache(c.env.KV, prefix);
    return c.json({
      success: true,
      message: "Analytics cache invalidated"
    });
  } catch (error) {
    console.error("Error invalidating cache:", error);
    return c.json({
      error: "Failed to invalidate cache",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "CACHE_ERROR"
    }, 500);
  }
});

// src/routes/documents.ts
init_checked_fetch();
init_modules_watch_stub();
init_hipaa_security();
var documentsRouter = new Hono2();
var ALLOWED_MIME_TYPES = [
  "application/pdf",
  "image/jpeg",
  "image/png",
  "image/jpg",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "text/csv"
];
var MAX_FILE_SIZE = 10 * 1024 * 1024;
var CATEGORY_TYPES = [
  "general",
  "invoice",
  "contract",
  "report",
  "receipt",
  "tax_document",
  "financial_statement",
  "rnd_documentation"
];
documentsRouter.post("/upload", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "document",
      action: "create",
      resourceId: "new"
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "CREATE",
        resourceType: "document",
        resourceId: "new",
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const formData = await c.req.formData();
    const file = formData.get("file");
    const category = formData.get("category") || "general";
    const description = formData.get("description");
    if (!file) {
      return c.json({
        error: "No file provided",
        code: "VALIDATION_ERROR"
      }, 400);
    }
    if (!ALLOWED_MIME_TYPES.includes(file.type)) {
      return c.json({
        error: `File type not allowed. Allowed types: ${ALLOWED_MIME_TYPES.join(", ")}`,
        code: "INVALID_FILE_TYPE"
      }, 400);
    }
    if (file.size > MAX_FILE_SIZE) {
      return c.json({
        error: `File too large. Maximum size: ${MAX_FILE_SIZE / 1024 / 1024}MB`,
        code: "FILE_TOO_LARGE"
      }, 400);
    }
    if (!CATEGORY_TYPES.includes(category)) {
      return c.json({
        error: `Invalid category. Allowed: ${CATEGORY_TYPES.join(", ")}`,
        code: "INVALID_CATEGORY"
      }, 400);
    }
    const fileId = crypto.randomUUID();
    const fileExtension = file.name.split(".").pop() || "bin";
    const r2Key = `${tenantId}/documents/${fileId}.${fileExtension}`;
    const fileBuffer = await file.arrayBuffer();
    const checksum = await calculateDocumentChecksum(fileBuffer);
    const now = Math.floor(Date.now() / 1e3);
    const uploadStart = Date.now();
    await c.env.DOCUMENTS.put(r2Key, fileBuffer, {
      httpMetadata: {
        contentType: file.type
      },
      customMetadata: {
        tenantId,
        userId,
        fileName: file.name,
        uploadedAt: (/* @__PURE__ */ new Date()).toISOString(),
        checksum
      }
    });
    const uploadDuration = Date.now() - uploadStart;
    if (uploadDuration > 5e3) {
      console.warn(`Slow R2 upload: ${uploadDuration}ms for ${file.size} bytes`);
    }
    await withRetry(async () => {
      await db.prepare(`
        INSERT INTO documents (
          id, tenant_id, user_id, filename, size_bytes, mime_type,
          r2_key, category, checksum, current_version, verified_at,
          created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
      `).bind(
        fileId,
        tenantId,
        userId,
        sanitizeInput(file.name, 255),
        file.size,
        file.type,
        r2Key,
        category,
        checksum,
        now,
        now,
        now
      ).run();
      await db.prepare(`
        INSERT INTO document_versions (
          document_id, tenant_id, version, filename, mime_type,
          size_bytes, r2_key, checksum, uploaded_by, verified,
          change_description, created_at
        ) VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?, 1, 'Initial version', ?)
      `).bind(
        fileId,
        tenantId,
        sanitizeInput(file.name, 255),
        file.type,
        file.size,
        r2Key,
        checksum,
        userId,
        now
      ).run();
    }, 3);
    await auditLogger2.log({
      tenantId,
      userId,
      action: "CREATE",
      resourceType: "document",
      resourceId: fileId,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        fileName: file.name,
        fileSize: file.size,
        category,
        checksum,
        phiFields: ["filename", "category"]
      }
    });
    return c.json({
      id: fileId,
      fileName: file.name,
      fileSize: file.size,
      fileType: file.type,
      category,
      checksum,
      version: 1,
      uploadDuration
    }, 201);
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "CREATE",
      resourceType: "document",
      resourceId: "new",
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error uploading document:", error);
    return c.json({
      error: "Failed to upload document",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "UPLOAD_ERROR"
    }, 500);
  }
});
documentsRouter.get("/", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "document",
      action: "read",
      resourceId: "list"
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "document",
        resourceId: "list",
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const category = c.req.query("category");
    const limit = Math.min(parseInt(c.req.query("limit") ?? "50", 10), 200);
    const offset = Math.max(parseInt(c.req.query("offset") ?? "0", 10), 0);
    let query = `
      SELECT
        id, file_name as fileName, file_size as fileSize,
        file_type as fileType, description, category,
        uploaded_by as uploadedBy, created_at as createdAt
      FROM documents
      WHERE tenant_id = ?
    `;
    const bindings = [tenantId];
    if (category) {
      query += ` AND category = ?`;
      bindings.push(category);
    }
    query += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
    bindings.push(limit, offset);
    const [items, totalResult] = await Promise.all([
      withRetry(async () => {
        const result = await db.prepare(query).bind(...bindings).all();
        return result.results;
      }, 3),
      withRetry(async () => {
        let countQuery = `SELECT COUNT(*) as total FROM documents WHERE tenant_id = ?`;
        const countBindings = [tenantId];
        if (category) {
          countQuery += ` AND category = ?`;
          countBindings.push(category);
        }
        const result = await db.prepare(countQuery).bind(...countBindings).first();
        return result?.total || 0;
      }, 3)
    ]);
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "document",
      resourceId: "list",
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        recordCount: items.length,
        category,
        phiFields: ["fileName", "category"]
      }
    });
    return c.json({
      items,
      paging: {
        limit,
        offset,
        total: totalResult,
        hasMore: items.length === limit
      }
    });
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "document",
      resourceId: "list",
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error listing documents:", error);
    return c.json({
      error: "Failed to list documents",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "LIST_ERROR"
    }, 500);
  }
});
documentsRouter.get("/:id", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const id = c.req.param("id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "document",
      action: "read",
      resourceId: id
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "document",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const doc = await withRetry(async () => {
      return db.prepare(`
        SELECT r2_key, file_name, file_type
        FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first();
    }, 3);
    if (!doc) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "document",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: "Document not found",
        phiAccessed: false
      });
      return c.json({
        error: "Document not found",
        code: "NOT_FOUND"
      }, 404);
    }
    const object = await c.env.DOCUMENTS.get(doc.r2_key);
    if (!object) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "document",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: "File not found in storage",
        phiAccessed: false
      });
      return c.json({
        error: "File not found in storage",
        code: "FILE_NOT_FOUND"
      }, 404);
    }
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "document",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        fileName: doc.file_name,
        action: "download",
        phiFields: ["file_name", "file_content"]
      }
    });
    return new Response(object.body, {
      headers: {
        "Content-Type": doc.file_type,
        "Content-Disposition": `attachment; filename="${doc.file_name}"`,
        "Cache-Control": "private, max-age=3600"
      }
    });
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "document",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error downloading document:", error);
    return c.json({
      error: "Failed to download document",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "DOWNLOAD_ERROR"
    }, 500);
  }
});
documentsRouter.delete("/:id", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const id = c.req.param("id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "document",
      action: "delete",
      resourceId: id
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "DELETE",
        resourceType: "document",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const doc = await withRetry(async () => {
      return db.prepare(`
        SELECT r2_key, file_name
        FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first();
    }, 3);
    if (!doc) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "DELETE",
        resourceType: "document",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: "Document not found",
        phiAccessed: false
      });
      return c.json({
        error: "Document not found",
        code: "NOT_FOUND"
      }, 404);
    }
    await c.env.DOCUMENTS.delete(doc.r2_key);
    await withRetry(async () => {
      await db.prepare(`
        DELETE FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).run();
    }, 3);
    await auditLogger2.log({
      tenantId,
      userId,
      action: "DELETE",
      resourceType: "document",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        fileName: doc.file_name,
        note: "Document with PHI data deleted",
        phiFields: ["file_name", "file_content"]
      }
    });
    return c.json({ success: true });
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "DELETE",
      resourceType: "document",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error deleting document:", error);
    return c.json({
      error: "Failed to delete document",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "DELETE_ERROR"
    }, 500);
  }
});
documentsRouter.get("/:id/metadata", async (c) => {
  const tenantId = c.get("tenantId") || c.get("tenant_id");
  const userId = c.get("userId") || c.get("user_id");
  const id = c.req.param("id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "document",
      action: "read",
      resourceId: id
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "document",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const doc = await withRetry(async () => {
      return db.prepare(`
        SELECT
          id, file_name as fileName, file_size as fileSize,
          file_type as fileType, description, category,
          uploaded_by as uploadedBy, created_at as createdAt
        FROM documents
        WHERE tenant_id = ? AND id = ?
      `).bind(tenantId, id).first();
    }, 3);
    if (!doc) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "document",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: "Document not found",
        phiAccessed: false
      });
      return c.json({
        error: "Document not found",
        code: "NOT_FOUND"
      }, 404);
    }
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "document",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        action: "metadata_access",
        phiFields: ["fileName", "category"]
      }
    });
    return c.json({ data: doc });
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "document",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error instanceof Error ? error.message : "Unknown error",
      phiAccessed: false
    });
    console.error("Error fetching document metadata:", error);
    return c.json({
      error: "Failed to fetch document metadata",
      details: error instanceof Error ? error.message : "Unknown error",
      code: "METADATA_ERROR"
    }, 500);
  }
});

// src/routes/assessments.ts
init_checked_fetch();
init_modules_watch_stub();
var router = new Hono2();
router.get("/", async (c) => {
  const userId = c.get("userId") || c.get("user_id");
  const tenantId = c.get("tenantId") || c.req.query("tenant_id") || "default";
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "assessment",
      action: "read",
      resourceId: "list"
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "assessment",
        resourceId: "list",
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const result = await db.prepare(`
      SELECT
        id,
        tenant_id,
        client_id,
        status,
        responses,
        results,
        score,
        completed_at,
        created_by,
        created_at,
        updated_at
      FROM assessments
      WHERE tenant_id = ? AND created_by = ?
      ORDER BY created_at DESC
    `).bind(tenantId, userId).all();
    const assessments = result.results.map((row) => ({
      ...row,
      responses: JSON.parse(row.responses),
      results: JSON.parse(row.results),
      created_at: new Date(row.created_at * 1e3).toISOString(),
      updated_at: new Date(row.updated_at * 1e3).toISOString(),
      completed_at: row.completed_at ? new Date(row.completed_at * 1e3).toISOString() : null
    }));
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "assessment",
      resourceId: "list",
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        recordCount: assessments.length,
        phiFields: ["responses", "results"]
      }
    });
    return c.json(assessments);
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "assessment",
      resourceId: "list",
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });
    console.error("Failed to fetch assessments:", error);
    return c.json({ error: "Failed to fetch assessments" }, 500);
  }
});
router.get("/client/:clientId", async (c) => {
  const userId = c.get("userId") || c.get("user_id");
  const tenantId = c.get("tenantId") || c.req.query("tenant_id") || "default";
  const clientId = c.req.param("clientId");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "assessment",
      action: "read",
      resourceId: clientId
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "assessment",
        resourceId: clientId,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const result = await db.prepare(`
      SELECT
        id,
        tenant_id,
        client_id,
        status,
        responses,
        results,
        score,
        completed_at,
        created_by,
        created_at,
        updated_at
      FROM assessments
      WHERE tenant_id = ? AND client_id = ? AND created_by = ?
      ORDER BY created_at DESC
    `).bind(tenantId, clientId, userId).all();
    const assessments = result.results.map((row) => ({
      ...row,
      responses: JSON.parse(row.responses),
      results: JSON.parse(row.results),
      created_at: new Date(row.created_at * 1e3).toISOString(),
      updated_at: new Date(row.updated_at * 1e3).toISOString(),
      completed_at: row.completed_at ? new Date(row.completed_at * 1e3).toISOString() : null
    }));
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "assessment",
      resourceId: clientId,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        recordCount: assessments.length,
        phiFields: ["responses", "results"],
        clientId
      }
    });
    return c.json(assessments);
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "assessment",
      resourceId: clientId,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });
    console.error("Failed to fetch client assessments:", error);
    return c.json({ error: "Failed to fetch client assessments" }, 500);
  }
});
router.get("/:id", async (c) => {
  const userId = c.get("userId") || c.get("user_id");
  const id = c.req.param("id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const tenantId = c.get("tenantId");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId,
      resourceType: "assessment",
      action: "read",
      resourceId: id
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "assessment",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const result = await db.prepare(`
      SELECT
        id,
        tenant_id,
        client_id,
        status,
        responses,
        results,
        score,
        completed_at,
        created_by,
        created_at,
        updated_at
      FROM assessments
      WHERE id = ? AND created_by = ?
    `).bind(id, userId).first();
    if (!result) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "READ",
        resourceType: "assessment",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: "Assessment not found",
        phiAccessed: false
      });
      return c.json({ error: "Assessment not found" }, 404);
    }
    const assessment = {
      ...result,
      responses: JSON.parse(result.responses),
      results: JSON.parse(result.results),
      created_at: new Date(result.created_at * 1e3).toISOString(),
      updated_at: new Date(result.updated_at * 1e3).toISOString(),
      completed_at: result.completed_at ? new Date(result.completed_at * 1e3).toISOString() : null
    };
    await auditLogger2.log({
      tenantId: result.tenant_id,
      userId,
      action: "READ",
      resourceType: "assessment",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ["responses", "results"]
      }
    });
    return c.json(assessment);
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "READ",
      resourceType: "assessment",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });
    console.error("Failed to fetch assessment:", error);
    return c.json({ error: "Failed to fetch assessment" }, 500);
  }
});
router.post("/", async (c) => {
  const userId = c.get("userId") || c.get("user_id");
  const tenantId = c.get("tenantId");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  const body = await c.req.json();
  const { tenant_id, client_id, responses, results } = body;
  if (!client_id || !responses || !results) {
    return c.json({ error: "Missing required fields" }, 400);
  }
  const finalTenantId = tenant_id || tenantId || "default";
  try {
    const access = await rbacManager.checkAccess({
      userId,
      tenantId: finalTenantId,
      resourceType: "assessment",
      action: "create",
      resourceId: "new"
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId: finalTenantId,
        userId,
        action: "CREATE",
        resourceType: "assessment",
        resourceId: "new",
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const id = crypto.randomUUID().replace(/-/g, "").toLowerCase();
    const score = results.totalCredit || 0;
    const now = Math.floor(Date.now() / 1e3);
    await db.prepare(`
      INSERT INTO assessments (
        id, tenant_id, client_id, status, responses, results, score, created_by, created_at, updated_at
      ) VALUES (?, ?, ?, 'draft', ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      finalTenantId,
      client_id,
      JSON.stringify(responses),
      JSON.stringify(results),
      score,
      userId,
      now,
      now
    ).run();
    await auditLogger2.log({
      tenantId: finalTenantId,
      userId,
      action: "CREATE",
      resourceType: "assessment",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        phiFields: ["responses", "results"],
        clientId: client_id
      }
    });
    const assessment = {
      id,
      tenant_id: finalTenantId,
      client_id,
      status: "draft",
      responses,
      results,
      score,
      completed_at: null,
      created_by: userId,
      created_at: new Date(now * 1e3).toISOString(),
      updated_at: new Date(now * 1e3).toISOString()
    };
    return c.json(assessment);
  } catch (error) {
    await auditLogger2.log({
      tenantId: finalTenantId,
      userId,
      action: "CREATE",
      resourceType: "assessment",
      resourceId: "new",
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });
    console.error("Failed to create assessment:", error);
    return c.json({ error: "Failed to create assessment" }, 500);
  }
});
router.patch("/:id", async (c) => {
  const userId = c.get("userId") || c.get("user_id");
  const id = c.req.param("id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const tenantId = c.get("tenantId");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  const body = await c.req.json();
  try {
    const existing = await db.prepare(`
      SELECT tenant_id FROM assessments WHERE id = ? AND created_by = ?
    `).bind(id, userId).first();
    if (!existing) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "UPDATE",
        resourceType: "assessment",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: "Assessment not found",
        phiAccessed: false
      });
      return c.json({ error: "Assessment not found" }, 404);
    }
    const access = await rbacManager.checkAccess({
      userId,
      tenantId: existing.tenant_id,
      resourceType: "assessment",
      action: "update",
      resourceId: id
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId: existing.tenant_id,
        userId,
        action: "UPDATE",
        resourceType: "assessment",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    const updates = [];
    const bindings = [];
    const phiFieldsModified = [];
    if (body.responses !== void 0) {
      updates.push("responses = ?");
      bindings.push(JSON.stringify(body.responses));
      phiFieldsModified.push("responses");
    }
    if (body.results !== void 0) {
      updates.push("results = ?");
      bindings.push(JSON.stringify(body.results));
      updates.push("score = ?");
      bindings.push(body.results.totalCredit || 0);
      phiFieldsModified.push("results");
    }
    if (body.status !== void 0) {
      updates.push("status = ?");
      bindings.push(body.status);
      if (body.status === "completed" && !body.results) {
        updates.push("completed_at = ?");
        bindings.push(Math.floor(Date.now() / 1e3));
      }
    }
    if (updates.length === 0) {
      return c.json({ error: "No updates provided" }, 400);
    }
    const now = Math.floor(Date.now() / 1e3);
    updates.push("updated_at = ?");
    bindings.push(now);
    bindings.push(id);
    await db.prepare(`
      UPDATE assessments
      SET ${updates.join(", ")}
      WHERE id = ?
    `).bind(...bindings).run();
    await auditLogger2.log({
      tenantId: existing.tenant_id,
      userId,
      action: "UPDATE",
      resourceType: "assessment",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: phiFieldsModified.length > 0,
      metadata: {
        phiFields: phiFieldsModified.length > 0 ? phiFieldsModified : void 0,
        fieldsUpdated: updates.length
      }
    });
    const result = await db.prepare(`
      SELECT
        id,
        tenant_id,
        client_id,
        status,
        responses,
        results,
        score,
        completed_at,
        created_by,
        created_at,
        updated_at
      FROM assessments
      WHERE id = ?
    `).bind(id).first();
    const assessment = {
      ...result,
      responses: JSON.parse(result.responses),
      results: JSON.parse(result.results),
      created_at: new Date(result.created_at * 1e3).toISOString(),
      updated_at: new Date(result.updated_at * 1e3).toISOString(),
      completed_at: result.completed_at ? new Date(result.completed_at * 1e3).toISOString() : null
    };
    return c.json(assessment);
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "UPDATE",
      resourceType: "assessment",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });
    console.error("Failed to update assessment:", error);
    return c.json({ error: "Failed to update assessment" }, 500);
  }
});
router.delete("/:id", async (c) => {
  const userId = c.get("userId") || c.get("user_id");
  const id = c.req.param("id");
  const auditLogger2 = c.get("auditLogger");
  const rbacManager = c.get("rbacManager");
  const tenantId = c.get("tenantId");
  const ipAddress = c.get("ipAddress");
  const userAgent = c.get("userAgent");
  const requestId = c.get("requestId");
  const db = c.get("db");
  try {
    const existing = await db.prepare(`
      SELECT tenant_id FROM assessments WHERE id = ? AND created_by = ?
    `).bind(id, userId).first();
    if (!existing) {
      await auditLogger2.log({
        tenantId,
        userId,
        action: "DELETE",
        resourceType: "assessment",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: "Assessment not found",
        phiAccessed: false
      });
      return c.json({ error: "Assessment not found" }, 404);
    }
    const access = await rbacManager.checkAccess({
      userId,
      tenantId: existing.tenant_id,
      resourceType: "assessment",
      action: "delete",
      resourceId: id
    });
    if (!access.allowed) {
      await auditLogger2.log({
        tenantId: existing.tenant_id,
        userId,
        action: "DELETE",
        resourceType: "assessment",
        resourceId: id,
        ipAddress,
        userAgent,
        requestId,
        success: false,
        failureReason: access.reason,
        phiAccessed: false
      });
      return c.json({ error: access.reason || "Access denied" }, 403);
    }
    await db.prepare(`
      DELETE FROM assessments WHERE id = ?
    `).bind(id).run();
    await auditLogger2.log({
      tenantId: existing.tenant_id,
      userId,
      action: "DELETE",
      resourceType: "assessment",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: true,
      phiAccessed: true,
      metadata: {
        note: "Assessment with PHI data deleted"
      }
    });
    return c.json({ success: true });
  } catch (error) {
    await auditLogger2.log({
      tenantId,
      userId,
      action: "DELETE",
      resourceType: "assessment",
      resourceId: id,
      ipAddress,
      userAgent,
      requestId,
      success: false,
      failureReason: error.message,
      phiAccessed: false
    });
    console.error("Failed to delete assessment:", error);
    return c.json({ error: "Failed to delete assessment" }, 500);
  }
});
var assessmentsRouter = router;

// src/utils/cors.ts
init_checked_fetch();
init_modules_watch_stub();
function createCorsHeaders(origin, allowedOrigins) {
  const isAllowed = allowedOrigins.includes(origin);
  return {
    "Access-Control-Allow-Origin": isAllowed ? origin : allowedOrigins[0],
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}
__name(createCorsHeaders, "createCorsHeaders");
function handlePreflight(origin, allowedOrigins) {
  return new Response(null, {
    status: 200,
    headers: createCorsHeaders(origin, allowedOrigins)
  });
}
__name(handlePreflight, "handlePreflight");

// src/middleware/hipaa-security.ts
init_checked_fetch();
init_modules_watch_stub();

// src/utils/session-manager.ts
init_checked_fetch();
init_modules_watch_stub();
var DEFAULT_SESSION_CONFIG = {
  idleTimeoutSeconds: 900,
  absoluteTimeoutSeconds: 28800,
  privilegedTimeoutSeconds: 300,
  requireMFA: true
};
var SessionManager = class {
  constructor(db, config = {}) {
    this.db = db;
    this.config = { ...DEFAULT_SESSION_CONFIG, ...config };
  }
  static {
    __name(this, "SessionManager");
  }
  config;
  async createSession(userId, ipAddress, userAgent, requiresMfa = false) {
    const id = crypto.randomUUID();
    const refreshToken = this.generateSecureToken();
    const now = Math.floor(Date.now() / 1e3);
    const expiresAt = now + this.config.absoluteTimeoutSeconds;
    await this.db.prepare(
      `INSERT INTO sessions (
          id, user_id, refresh_token, expires_at, last_activity,
          ip_address, user_agent, requires_mfa, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id,
      userId,
      refreshToken,
      expiresAt,
      now,
      ipAddress || null,
      userAgent || null,
      requiresMfa ? 1 : 0,
      now
    ).run();
    await this.logActivity(id, "login", ipAddress);
    return {
      id,
      userId,
      refreshToken,
      expiresAt,
      lastActivity: now,
      ipAddress,
      userAgent,
      requiresMfa,
      privileged: false,
      createdAt: now
    };
  }
  async validateSession(sessionId, ipAddress, userAgent, expectedUserId) {
    const session = await this.getSession(sessionId);
    if (!session) {
      return {
        valid: false,
        reason: "Session not found"
      };
    }
    if (expectedUserId && session.userId !== expectedUserId) {
      await this.logActivity(sessionId, "access", ipAddress, {
        reason: "User ID mismatch",
        expected: expectedUserId,
        actual: session.userId
      });
      return {
        valid: false,
        reason: "Session does not belong to authenticated user"
      };
    }
    const now = Math.floor(Date.now() / 1e3);
    if (session.expiresAt < now) {
      await this.logActivity(sessionId, "timeout", ipAddress);
      await this.deleteSession(sessionId);
      return {
        valid: false,
        reason: "Session expired (absolute timeout)"
      };
    }
    const idleTimeout = session.lastActivity + this.config.idleTimeoutSeconds;
    if (idleTimeout < now) {
      await this.logActivity(sessionId, "timeout", ipAddress);
      await this.deleteSession(sessionId);
      return {
        valid: false,
        reason: "Session expired (idle timeout)"
      };
    }
    if (session.ipAddress && ipAddress && session.ipAddress !== ipAddress) {
      await this.logActivity(sessionId, "access", ipAddress, {
        reason: "IP address mismatch",
        expected: session.ipAddress,
        actual: ipAddress
      });
      return {
        valid: false,
        reason: "Session IP address mismatch"
      };
    }
    if (session.userAgent && userAgent && session.userAgent !== userAgent) {
      await this.logActivity(sessionId, "access", ipAddress, {
        reason: "User agent mismatch"
      });
      return {
        valid: false,
        reason: "Session user agent mismatch"
      };
    }
    if (session.requiresMfa && !session.mfaVerifiedAt) {
      return {
        valid: false,
        requiresMfa: true,
        reason: "MFA verification required"
      };
    }
    if (session.privileged && session.privilegedExpiresAt) {
      if (session.privilegedExpiresAt < now) {
        await this.revokePrivilegedAccess(sessionId);
        await this.logActivity(sessionId, "privilege_expire", ipAddress);
      }
    }
    await this.updateLastActivity(sessionId);
    await this.logActivity(sessionId, "access", ipAddress);
    return {
      valid: true
    };
  }
  async requiresReauthentication(userId, resourceType, action) {
    const result = await this.db.prepare(
      `SELECT max_age_seconds, requires_mfa
         FROM reauth_requirements
         WHERE resource_type = ? AND action = ?`
    ).bind(resourceType, action).first();
    if (!result) {
      return false;
    }
    const sessions = await this.db.prepare(
      `SELECT mfa_verified_at, created_at
         FROM sessions
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 1`
    ).bind(userId).first();
    if (!sessions) {
      return true;
    }
    const now = Math.floor(Date.now() / 1e3);
    const maxAge = result.max_age_seconds;
    if (result.requires_mfa) {
      const mfaVerifiedAt = sessions.mfa_verified_at;
      if (!mfaVerifiedAt || now - mfaVerifiedAt > maxAge) {
        return true;
      }
    }
    return false;
  }
  async grantPrivilegedAccess(sessionId, ipAddress) {
    const now = Math.floor(Date.now() / 1e3);
    const privilegedExpiresAt = now + this.config.privilegedTimeoutSeconds;
    await this.db.prepare(
      `UPDATE sessions
         SET privileged = 1, privileged_expires_at = ?
         WHERE id = ?`
    ).bind(privilegedExpiresAt, sessionId).run();
    await this.logActivity(sessionId, "privilege_grant", ipAddress, {
      expires_at: privilegedExpiresAt
    });
  }
  async revokePrivilegedAccess(sessionId) {
    await this.db.prepare(
      `UPDATE sessions
         SET privileged = 0, privileged_expires_at = NULL
         WHERE id = ?`
    ).bind(sessionId).run();
  }
  async verifyMFA(sessionId, ipAddress) {
    const now = Math.floor(Date.now() / 1e3);
    await this.db.prepare(
      `UPDATE sessions
         SET mfa_verified_at = ?
         WHERE id = ?`
    ).bind(now, sessionId).run();
    await this.logActivity(sessionId, "mfa_verify", ipAddress);
  }
  async deleteSession(sessionId) {
    await this.db.prepare("DELETE FROM sessions WHERE id = ?").bind(sessionId).run();
  }
  async terminateAllUserSessions(userId, exceptSessionId) {
    if (exceptSessionId) {
      await this.db.prepare("DELETE FROM sessions WHERE user_id = ? AND id != ?").bind(userId, exceptSessionId).run();
    } else {
      await this.db.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run();
    }
  }
  async cleanupExpiredSessions() {
    const now = Math.floor(Date.now() / 1e3);
    const idleThreshold = now - this.config.idleTimeoutSeconds;
    const result = await this.db.prepare(
      `DELETE FROM sessions
         WHERE expires_at < ? OR last_activity < ?`
    ).bind(now, idleThreshold).run();
    return result.meta?.changes || 0;
  }
  async getSession(sessionId) {
    const result = await this.db.prepare(
      `SELECT
          id, user_id, refresh_token, expires_at, last_activity,
          ip_address, user_agent, requires_mfa, mfa_verified_at,
          privileged, privileged_expires_at, created_at
        FROM sessions
        WHERE id = ?`
    ).bind(sessionId).first();
    if (!result) {
      return null;
    }
    return {
      id: result.id,
      userId: result.user_id,
      refreshToken: result.refresh_token,
      expiresAt: result.expires_at,
      lastActivity: result.last_activity,
      ipAddress: result.ip_address,
      userAgent: result.user_agent,
      requiresMfa: Boolean(result.requires_mfa),
      mfaVerifiedAt: result.mfa_verified_at,
      privileged: Boolean(result.privileged),
      privilegedExpiresAt: result.privileged_expires_at,
      createdAt: result.created_at
    };
  }
  async updateLastActivity(sessionId) {
    const now = Math.floor(Date.now() / 1e3);
    await this.db.prepare("UPDATE sessions SET last_activity = ? WHERE id = ?").bind(now, sessionId).run();
  }
  async logActivity(sessionId, activityType, ipAddress, metadata) {
    const id = crypto.randomUUID();
    const now = Math.floor(Date.now() / 1e3);
    const metadataJson = metadata ? JSON.stringify(metadata) : null;
    await this.db.prepare(
      `INSERT INTO session_activities (id, session_id, activity_type, ip_address, metadata, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(id, sessionId, activityType, ipAddress || null, metadataJson, now).run();
  }
  generateSecureToken() {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, (byte) => byte.toString(16).padStart(2, "0")).join("");
  }
};
function createSessionManager(db, config) {
  return new SessionManager(db, config);
}
__name(createSessionManager, "createSessionManager");

// src/utils/audit-logger.ts
init_checked_fetch();
init_modules_watch_stub();
var AuditLogger = class {
  constructor(db) {
    this.db = db;
  }
  static {
    __name(this, "AuditLogger");
  }
  async log(entry) {
    const id = crypto.randomUUID();
    const createdAt = Math.floor(Date.now() / 1e3);
    const checksum = await this.generateChecksum({
      ...entry,
      id,
      createdAt
    });
    const phiAccessedJson = entry.phiAccessed ? JSON.stringify(entry.phiAccessed) : null;
    const metadataJson = entry.metadata ? JSON.stringify(entry.metadata) : null;
    await this.db.prepare(
      `INSERT INTO audit_logs (
          id, tenant_id, user_id, action, resource_type, resource_id,
          phi_accessed, ip_address, user_agent, request_id, success,
          failure_reason, metadata, checksum, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id,
      entry.tenantId,
      entry.userId,
      entry.action,
      entry.resourceType,
      entry.resourceId || null,
      phiAccessedJson,
      entry.ipAddress || null,
      entry.userAgent || null,
      entry.requestId || null,
      entry.success !== false ? 1 : 0,
      entry.failureReason || null,
      metadataJson,
      checksum,
      createdAt
    ).run();
    await this.addToChain(id, entry.tenantId);
    return id;
  }
  async logPHIAccess(tenantId, userId, patientId, fieldsAccessed, justification, approvedBy, ipAddress) {
    const id = crypto.randomUUID();
    const createdAt = Math.floor(Date.now() / 1e3);
    await this.db.prepare(
      `INSERT INTO phi_access_log (
          id, tenant_id, user_id, patient_id, fields_accessed,
          justification, approved_by, ip_address, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      id,
      tenantId,
      userId,
      patientId,
      JSON.stringify(fieldsAccessed),
      justification || null,
      approvedBy || null,
      ipAddress || null,
      createdAt
    ).run();
    return id;
  }
  async query(query) {
    let sql = `
      SELECT
        id, tenant_id, user_id, action, resource_type, resource_id,
        phi_accessed, ip_address, user_agent, request_id, success,
        failure_reason, metadata, checksum, created_at
      FROM audit_logs
      WHERE tenant_id = ?
    `;
    const params = [query.tenantId];
    if (query.userId) {
      sql += " AND user_id = ?";
      params.push(query.userId);
    }
    if (query.action) {
      sql += " AND action = ?";
      params.push(query.action);
    }
    if (query.resourceType) {
      sql += " AND resource_type = ?";
      params.push(query.resourceType);
    }
    if (query.resourceId) {
      sql += " AND resource_id = ?";
      params.push(query.resourceId);
    }
    if (query.startDate) {
      sql += " AND created_at >= ?";
      params.push(query.startDate);
    }
    if (query.endDate) {
      sql += " AND created_at <= ?";
      params.push(query.endDate);
    }
    sql += " ORDER BY created_at DESC";
    if (query.limit) {
      sql += " LIMIT ?";
      params.push(query.limit);
    }
    if (query.offset) {
      sql += " OFFSET ?";
      params.push(query.offset);
    }
    const result = await this.db.prepare(sql).bind(...params).all();
    return result.results || [];
  }
  async verifyIntegrity(tenantId) {
    const errors = [];
    const chainResult = await this.db.prepare(
      `SELECT
          ac.id, ac.audit_log_id, ac.previous_hash, ac.current_hash,
          al.id as log_id, al.tenant_id, al.user_id, al.action,
          al.resource_type, al.resource_id, al.checksum, al.created_at
        FROM audit_chain ac
        JOIN audit_logs al ON ac.audit_log_id = al.id
        WHERE ac.tenant_id = ?
        ORDER BY ac.created_at ASC`
    ).bind(tenantId).all();
    const chain = chainResult.results || [];
    for (let i = 0; i < chain.length; i++) {
      const entry = chain[i];
      const calculatedChecksum = await this.generateChecksum({
        id: entry.log_id,
        tenantId: entry.tenant_id,
        userId: entry.user_id,
        action: entry.action,
        resourceType: entry.resource_type,
        resourceId: entry.resource_id,
        createdAt: entry.created_at
      });
      if (calculatedChecksum !== entry.checksum) {
        errors.push(
          `Checksum mismatch for audit log ${entry.log_id}: expected ${entry.checksum}, got ${calculatedChecksum}`
        );
      }
      const calculatedHash = await this.generateChainHash(
        entry.audit_log_id,
        entry.previous_hash || "",
        entry.checksum,
        entry.created_at,
        entry.tenant_id
      );
      if (calculatedHash !== entry.current_hash) {
        errors.push(
          `Chain hash mismatch for entry ${entry.id}: expected ${entry.current_hash}, got ${calculatedHash}`
        );
      }
      if (i > 0) {
        const prevEntry = chain[i - 1];
        if (entry.previous_hash !== prevEntry.current_hash) {
          errors.push(
            `Chain break between ${prevEntry.id} and ${entry.id}: previous_hash ${entry.previous_hash} != ${prevEntry.current_hash}`
          );
        }
      }
    }
    return {
      valid: errors.length === 0,
      errors
    };
  }
  async addToChain(auditLogId, tenantId) {
    const lastChainResult = await this.db.prepare(
      `SELECT current_hash
         FROM audit_chain
         WHERE tenant_id = ?
         ORDER BY created_at DESC
         LIMIT 1`
    ).bind(tenantId).first();
    const auditLogResult = await this.db.prepare(
      `SELECT checksum, created_at FROM audit_logs WHERE id = ?`
    ).bind(auditLogId).first();
    if (!auditLogResult) {
      throw new Error(`Audit log ${auditLogId} not found for chain entry`);
    }
    const previousHash = lastChainResult?.current_hash || null;
    const currentHash = await this.generateChainHash(
      auditLogId,
      previousHash || "",
      auditLogResult.checksum,
      auditLogResult.created_at,
      tenantId
    );
    const createdAt = Math.floor(Date.now() / 1e3);
    await this.db.prepare(
      `INSERT INTO audit_chain (id, tenant_id, audit_log_id, previous_hash, current_hash, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      crypto.randomUUID(),
      tenantId,
      auditLogId,
      previousHash,
      currentHash,
      createdAt
    ).run();
  }
  async generateChecksum(data) {
    const sortedData = JSON.stringify(data, Object.keys(data).sort());
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(sortedData);
    const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  async generateChainHash(auditLogId, previousHash, checksum, createdAt, tenantId) {
    const data = `${previousHash}|${auditLogId}|${checksum}|${createdAt}|${tenantId}`;
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
  }
};
function createAuditLogger(db) {
  return new AuditLogger(db);
}
__name(createAuditLogger, "createAuditLogger");

// src/utils/rbac.ts
init_checked_fetch();
init_modules_watch_stub();

// src/utils/phi-encryption.ts
init_checked_fetch();
init_modules_watch_stub();

// src/types/phi-registry.ts
init_checked_fetch();
init_modules_watch_stub();
var PHI_FIELDS = [
  "ssn",
  "date_of_birth",
  "medical_record_number",
  "insurance_id",
  "diagnosis_codes",
  "treatment_notes",
  "prescription_info",
  "lab_results",
  "phone_number",
  "email",
  "address",
  "emergency_contact",
  "client_name",
  "full_name",
  "first_name",
  "last_name",
  "results",
  "responses",
  "qualified_expenses",
  "notes",
  "description",
  "client",
  "project",
  "filename",
  "file_name",
  "file_content",
  "category"
];
var isPHIField = /* @__PURE__ */ __name((field) => {
  return PHI_FIELDS.includes(field);
}, "isPHIField");
var PHI_BEARING_TABLES = [
  "assessments",
  "documents",
  "time_entries",
  "users",
  "clients",
  "sessions",
  "audit_logs",
  "phi_access_log"
];
var isPHITable = /* @__PURE__ */ __name((table) => {
  return PHI_BEARING_TABLES.includes(table);
}, "isPHITable");
var TABLE_PHI_FIELDS = {
  assessments: ["client_name", "results", "responses", "qualified_expenses", "description"],
  time_entries: ["notes", "description", "client", "project"],
  documents: ["filename", "file_name", "file_content", "category", "description"],
  users: ["email", "phone_number", "full_name", "first_name", "last_name", "address"],
  clients: ["full_name", "first_name", "last_name", "email", "phone_number", "address", "ssn", "date_of_birth"],
  sessions: ["ssn", "medical_record_number", "insurance_id", "diagnosis_codes", "treatment_notes", "prescription_info", "lab_results"]
};
var getTablePHIFields = /* @__PURE__ */ __name((table) => {
  return TABLE_PHI_FIELDS[table] || [];
}, "getTablePHIFields");

// src/utils/phi-encryption.ts
var PHIEncryption = class {
  static {
    __name(this, "PHIEncryption");
  }
  static encoder = new TextEncoder();
  static decoder = new TextDecoder();
  static async deriveKey(masterKey, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      this.encoder.encode(masterKey),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 1e5,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  static async encrypt(plaintext, masterKey, keyId = "default") {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await this.deriveKey(masterKey, salt);
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      key,
      this.encoder.encode(plaintext)
    );
    const encrypted = new Uint8Array(encryptedBuffer);
    const ciphertext = encrypted.slice(0, -16);
    const tag = encrypted.slice(-16);
    return {
      encrypted: this.bufferToBase64(ciphertext),
      iv: this.bufferToBase64(iv),
      tag: this.bufferToBase64(tag),
      algorithm: "AES-GCM-256",
      keyId
    };
  }
  static async decrypt(encryptedData, masterKey) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await this.deriveKey(masterKey, salt);
    const iv = this.base64ToBuffer(encryptedData.iv);
    const ciphertext = this.base64ToBuffer(encryptedData.encrypted);
    const tag = this.base64ToBuffer(encryptedData.tag);
    const encryptedBuffer = new Uint8Array([...ciphertext, ...tag]);
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      key,
      encryptedBuffer
    );
    return this.decoder.decode(decryptedBuffer);
  }
  static async encryptObject(obj, masterKey, keyId = "default") {
    const result = { ...obj };
    const encryptionPromises = [];
    for (const [key, value] of Object.entries(obj)) {
      if (isPHIField(key) && value != null) {
        const stringValue = typeof value === "string" ? value : JSON.stringify(value);
        encryptionPromises.push({
          key,
          promise: this.encrypt(stringValue, masterKey, keyId)
        });
      }
    }
    const encryptedValues = await Promise.all(
      encryptionPromises.map(({ promise }) => promise)
    );
    encryptionPromises.forEach(({ key }, index) => {
      result[key] = encryptedValues[index];
    });
    return result;
  }
  static async decryptObject(obj, masterKey, options) {
    const result = { ...obj };
    const decryptionPromises = [];
    for (const [key, value] of Object.entries(obj)) {
      if (options?.fields && !options.fields.includes(key)) {
        continue;
      }
      if (isPHIField(key) && value != null && typeof value === "object") {
        const encryptedData = value;
        if (encryptedData.encrypted && encryptedData.iv && encryptedData.tag) {
          decryptionPromises.push({
            key,
            promise: this.decrypt(encryptedData, masterKey)
          });
        }
      }
    }
    const decryptedValues = await Promise.all(
      decryptionPromises.map(({ promise }) => promise)
    );
    decryptionPromises.forEach(({ key }, index) => {
      result[key] = decryptedValues[index];
    });
    return result;
  }
  static bufferToBase64(buffer) {
    const bytes = Array.from(buffer);
    const binary = bytes.map((b) => String.fromCharCode(b)).join("");
    return btoa(binary);
  }
  static base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
  static async rotateKey(encryptedData, oldKey, newKey, newKeyId) {
    const plaintext = await this.decrypt(encryptedData, oldKey);
    return this.encrypt(plaintext, newKey, newKeyId);
  }
};
var EncryptedPHISchema = external_exports.object({
  encrypted: external_exports.string(),
  iv: external_exports.string(),
  tag: external_exports.string(),
  algorithm: external_exports.string(),
  keyId: external_exports.string()
});

// src/utils/rbac.ts
var RBACManager = class {
  constructor(db) {
    this.db = db;
  }
  static {
    __name(this, "RBACManager");
  }
  async getUserRoles(userId, tenantId) {
    const now = Math.floor(Date.now() / 1e3);
    const result = await this.db.prepare(
      `SELECT
          r.id, r.tenant_id, r.name, r.description, r.is_system_role
        FROM roles r
        JOIN user_roles ur ON r.id = ur.role_id
        WHERE ur.user_id = ?
          AND ur.tenant_id = ?
          AND (ur.expires_at IS NULL OR ur.expires_at > ?)
        ORDER BY r.name`
    ).bind(userId, tenantId, now).all();
    const roles = [];
    for (const row of result.results || []) {
      const permissions = await this.getRolePermissions(row.id);
      roles.push({
        id: row.id,
        tenantId: row.tenant_id,
        name: row.name,
        description: row.description,
        isSystemRole: Boolean(row.is_system_role),
        permissions
      });
    }
    return roles;
  }
  async getRolePermissions(roleId) {
    const result = await this.db.prepare(
      `SELECT
          p.id, p.resource_type, p.action, p.field_level,
          p.allowed_fields, p.description,
          rp.constraints
        FROM permissions p
        JOIN role_permissions rp ON p.id = rp.permission_id
        WHERE rp.role_id = ?`
    ).bind(roleId).all();
    return (result.results || []).map((row) => ({
      id: row.id,
      resourceType: row.resource_type,
      action: row.action,
      fieldLevel: Boolean(row.field_level),
      allowedFields: row.allowed_fields ? JSON.parse(row.allowed_fields) : void 0,
      description: row.description
    }));
  }
  async checkAccess(context) {
    const roles = await this.getUserRoles(context.userId, context.tenantId);
    if (roles.length === 0) {
      return {
        allowed: false,
        reason: "User has no roles assigned"
      };
    }
    let hasPermission = false;
    let allowedFields = /* @__PURE__ */ new Set();
    let constraints = {};
    for (const role of roles) {
      for (const permission of role.permissions) {
        if (permission.resourceType === context.resourceType && permission.action === context.action) {
          hasPermission = true;
          if (permission.fieldLevel && permission.allowedFields) {
            permission.allowedFields.forEach((field) => allowedFields.add(field));
          }
          const permConstraints = await this.getPermissionConstraints(
            role.id,
            permission.id
          );
          constraints = { ...constraints, ...permConstraints };
        }
      }
    }
    if (!hasPermission) {
      return {
        allowed: false,
        reason: `No permission for ${context.action} on ${context.resourceType}`
      };
    }
    if (constraints.own_records_only && context.resourceOwnerId) {
      if (context.userId !== context.resourceOwnerId) {
        return {
          allowed: false,
          reason: "Access restricted to own records only"
        };
      }
    }
    if (context.requestedFields && context.requestedFields.length > 0) {
      const filteredFields = context.requestedFields.filter((field) => {
        if (!isPHIField(field)) return true;
        return allowedFields.has(field);
      });
      if (filteredFields.length < context.requestedFields.length) {
        const deniedFields = context.requestedFields.filter(
          (f) => !filteredFields.includes(f)
        );
        return {
          allowed: false,
          reason: `Access denied to PHI fields: ${deniedFields.join(", ")}`
        };
      }
      return {
        allowed: true,
        allowedFields: filteredFields,
        constraints
      };
    }
    return {
      allowed: true,
      allowedFields: Array.from(allowedFields),
      constraints
    };
  }
  async filterPHIFields(data, userId, tenantId, resourceType) {
    const decision = await this.checkAccess({
      userId,
      tenantId,
      resourceType,
      action: "read",
      requestedFields: Object.keys(data)
    });
    if (!decision.allowed) {
      const filtered = { ...data };
      for (const key of Object.keys(filtered)) {
        if (isPHIField(key)) {
          delete filtered[key];
        }
      }
      return filtered;
    }
    if (decision.allowedFields && decision.allowedFields.length > 0) {
      const filtered = { ...data };
      for (const key of Object.keys(filtered)) {
        if (isPHIField(key) && !decision.allowedFields.includes(key)) {
          delete filtered[key];
        }
      }
      return filtered;
    }
    return data;
  }
  async assignRole(userId, roleId, tenantId, grantedBy, expiresAt) {
    const id = crypto.randomUUID();
    const grantedAt = Math.floor(Date.now() / 1e3);
    await this.db.prepare(
      `INSERT INTO user_roles (id, user_id, role_id, tenant_id, granted_by, granted_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, userId, roleId, tenantId, grantedBy, grantedAt, expiresAt || null).run();
  }
  async revokeRole(userId, roleId, tenantId) {
    await this.db.prepare(
      `DELETE FROM user_roles
         WHERE user_id = ? AND role_id = ? AND tenant_id = ?`
    ).bind(userId, roleId, tenantId).run();
  }
  async getPermissionConstraints(roleId, permissionId) {
    const result = await this.db.prepare(
      `SELECT constraints
         FROM role_permissions
         WHERE role_id = ? AND permission_id = ?`
    ).bind(roleId, permissionId).first();
    if (result?.constraints) {
      return JSON.parse(result.constraints);
    }
    return {};
  }
};
function createRBACManager(db) {
  return new RBACManager(db);
}
__name(createRBACManager, "createRBACManager");

// src/utils/phi-boundary.ts
init_checked_fetch();
init_modules_watch_stub();
var PHIBoundary = class {
  constructor(db, encryptionKey) {
    this.db = db;
    this.rbac = new RBACManager(db);
    this.audit = new AuditLogger(db);
    this.encryptionKey = encryptionKey;
  }
  static {
    __name(this, "PHIBoundary");
  }
  rbac;
  audit;
  encryptionKey;
  async read(request) {
    const phiFields = request.requestedFields.filter(isPHIField);
    const nonPhiFields = request.requestedFields.filter((f) => !isPHIField(f));
    if (phiFields.length > 0) {
      const accessDecision = await this.rbac.checkAccess({
        userId: request.userId,
        tenantId: request.tenantId,
        resourceType: request.resourceType,
        action: "read",
        resourceId: request.resourceId,
        requestedFields: phiFields
      });
      if (!accessDecision.allowed) {
        const auditLogId2 = await this.audit.log({
          tenantId: request.tenantId,
          userId: request.userId,
          action: "READ",
          resourceType: request.resourceType,
          resourceId: request.resourceId,
          phiAccessed: phiFields,
          ipAddress: request.ipAddress,
          userAgent: request.userAgent,
          success: false,
          failureReason: accessDecision.reason
        });
        return {
          success: false,
          deniedFields: phiFields,
          error: accessDecision.reason,
          auditLogId: auditLogId2
        };
      }
      const allowedPhiFields = phiFields.filter(
        (field) => !accessDecision.allowedFields || accessDecision.allowedFields.includes(field)
      );
      const deniedPhiFields = phiFields.filter(
        (field) => accessDecision.allowedFields && !accessDecision.allowedFields.includes(field)
      );
      await this.audit.logPHIAccess(
        request.tenantId,
        request.userId,
        request.resourceId,
        allowedPhiFields,
        request.justification,
        void 0,
        request.ipAddress
      );
      const data2 = await this.fetchData(
        request.resourceType,
        request.resourceId,
        [...nonPhiFields, ...allowedPhiFields]
      );
      if (!data2) {
        return {
          success: false,
          error: "Resource not found"
        };
      }
      const decryptedData = await this.decryptPHIFields(data2, allowedPhiFields);
      const auditLogId = await this.audit.log({
        tenantId: request.tenantId,
        userId: request.userId,
        action: "READ",
        resourceType: request.resourceType,
        resourceId: request.resourceId,
        phiAccessed: allowedPhiFields,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        success: true
      });
      return {
        success: true,
        data: decryptedData,
        deniedFields: deniedPhiFields.length > 0 ? deniedPhiFields : void 0,
        auditLogId
      };
    }
    const data = await this.fetchData(
      request.resourceType,
      request.resourceId,
      nonPhiFields
    );
    if (!data) {
      return {
        success: false,
        error: "Resource not found"
      };
    }
    return {
      success: true,
      data
    };
  }
  async write(request) {
    const fields = Object.keys(request.data);
    const phiFields = fields.filter(isPHIField);
    if (phiFields.length > 0) {
      const accessDecision = await this.rbac.checkAccess({
        userId: request.userId,
        tenantId: request.tenantId,
        resourceType: request.resourceType,
        action: "update",
        resourceId: request.resourceId,
        requestedFields: phiFields
      });
      if (!accessDecision.allowed) {
        const auditLogId2 = await this.audit.log({
          tenantId: request.tenantId,
          userId: request.userId,
          action: "UPDATE",
          resourceType: request.resourceType,
          resourceId: request.resourceId,
          phiAccessed: phiFields,
          ipAddress: request.ipAddress,
          userAgent: request.userAgent,
          success: false,
          failureReason: accessDecision.reason
        });
        return {
          success: false,
          error: accessDecision.reason,
          auditLogId: auditLogId2
        };
      }
      const encryptedData = await this.encryptPHIFields(request.data);
      await this.updateData(
        request.resourceType,
        request.resourceId,
        encryptedData
      );
      const auditLogId = await this.audit.log({
        tenantId: request.tenantId,
        userId: request.userId,
        action: "UPDATE",
        resourceType: request.resourceType,
        resourceId: request.resourceId,
        phiAccessed: phiFields,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        success: true
      });
      await this.audit.logPHIAccess(
        request.tenantId,
        request.userId,
        request.resourceId,
        phiFields,
        request.justification,
        void 0,
        request.ipAddress
      );
      return {
        success: true,
        auditLogId
      };
    }
    await this.updateData(
      request.resourceType,
      request.resourceId,
      request.data
    );
    return {
      success: true
    };
  }
  async bulkRead(request) {
    const phiFields = request.requestedFields.filter(isPHIField);
    const nonPhiFields = request.requestedFields.filter((f) => !isPHIField(f));
    if (phiFields.length > 0) {
      const accessDecision = await this.rbac.checkAccess({
        userId: request.userId,
        tenantId: request.tenantId,
        resourceType: request.resourceType,
        action: "read",
        resourceId: "*",
        requestedFields: phiFields
      });
      if (!accessDecision.allowed) {
        const auditLogId = await this.audit.log({
          tenantId: request.tenantId,
          userId: request.userId,
          action: "BULK_READ",
          resourceType: request.resourceType,
          resourceId: "*",
          phiAccessed: phiFields,
          ipAddress: request.ipAddress,
          userAgent: request.userAgent,
          success: false,
          failureReason: accessDecision.reason
        });
        return {
          success: false,
          deniedFields: phiFields,
          error: accessDecision.reason,
          auditLogId
        };
      }
      const allowedPhiFields = phiFields.filter(
        (field) => !accessDecision.allowedFields || accessDecision.allowedFields.includes(field)
      );
      const records2 = await this.fetchBulkData(
        request.resourceType,
        [...nonPhiFields, ...allowedPhiFields],
        request.query,
        request.limit,
        request.offset
      );
      const decryptedRecords = await Promise.all(
        records2.map((record) => this.decryptPHIFields(record, allowedPhiFields))
      );
      await this.audit.log({
        tenantId: request.tenantId,
        userId: request.userId,
        action: "BULK_READ",
        resourceType: request.resourceType,
        resourceId: `bulk:${decryptedRecords.length}`,
        phiAccessed: allowedPhiFields,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        success: true,
        metadata: {
          recordCount: decryptedRecords.length
        }
      });
      return {
        success: true,
        data: decryptedRecords
      };
    }
    const records = await this.fetchBulkData(
      request.resourceType,
      nonPhiFields,
      request.query,
      request.limit,
      request.offset
    );
    return {
      success: true,
      data: records
    };
  }
  async export(request) {
    const accessDecision = await this.rbac.checkAccess({
      userId: request.userId,
      tenantId: request.tenantId,
      resourceType: request.resourceType,
      action: "export",
      resourceId: request.resourceId
    });
    if (!accessDecision.allowed) {
      const auditLogId2 = await this.audit.log({
        tenantId: request.tenantId,
        userId: request.userId,
        action: "EXPORT",
        resourceType: request.resourceType,
        resourceId: request.resourceId,
        ipAddress: request.ipAddress,
        userAgent: request.userAgent,
        success: false,
        failureReason: accessDecision.reason
      });
      return {
        success: false,
        error: accessDecision.reason,
        auditLogId: auditLogId2
      };
    }
    const auditLogId = await this.audit.log({
      tenantId: request.tenantId,
      userId: request.userId,
      action: "EXPORT",
      resourceType: request.resourceType,
      resourceId: request.resourceId,
      phiAccessed: request.requestedFields.filter(isPHIField),
      ipAddress: request.ipAddress,
      userAgent: request.userAgent,
      success: true,
      metadata: {
        justification: request.justification
      }
    });
    return {
      success: true,
      auditLogId
    };
  }
  async filterResponse(data, userId, tenantId, resourceType) {
    return this.rbac.filterPHIFields(data, userId, tenantId, resourceType);
  }
  async encryptPHIFields(data) {
    return PHIEncryption.encryptObject(data, this.encryptionKey);
  }
  async decryptPHIFields(data, selectiveFields) {
    if (selectiveFields) {
      return PHIEncryption.decryptObject(data, this.encryptionKey, {
        fields: selectiveFields
      });
    }
    return PHIEncryption.decryptObject(data, this.encryptionKey);
  }
  async fetchData(resourceType, resourceId, fields) {
    const tableName = this.getTableName(resourceType);
    const fieldsList = fields.join(", ");
    const result = await this.db.prepare(`SELECT ${fieldsList} FROM ${tableName} WHERE id = ?`).bind(resourceId).first();
    return result;
  }
  async updateData(resourceType, resourceId, data) {
    const tableName = this.getTableName(resourceType);
    const fields = Object.keys(data);
    const setClause = fields.map((f) => `${f} = ?`).join(", ");
    const values = fields.map((f) => {
      const value = data[f];
      return typeof value === "object" ? JSON.stringify(value) : value;
    });
    await this.db.prepare(`UPDATE ${tableName} SET ${setClause} WHERE id = ?`).bind(...values, resourceId).run();
  }
  async fetchBulkData(resourceType, fields, query, limit = 100, offset = 0) {
    const tableName = this.getTableName(resourceType);
    const fieldsList = fields.join(", ");
    let sql = `SELECT ${fieldsList} FROM ${tableName}`;
    const bindings = [];
    if (query && Object.keys(query).length > 0) {
      const whereClause = Object.keys(query).map((key) => `${key} = ?`).join(" AND ");
      sql += ` WHERE ${whereClause}`;
      bindings.push(...Object.values(query));
    }
    sql += ` LIMIT ? OFFSET ?`;
    bindings.push(limit, offset);
    const result = await this.db.prepare(sql).bind(...bindings).all();
    return result.results || [];
  }
  getTableName(resourceType) {
    const tableMap = {
      patient: "patients",
      document: "documents",
      assessment: "assessments",
      time_entry: "time_entries",
      user: "users"
    };
    return tableMap[resourceType] || resourceType;
  }
};
function createPHIBoundary(db, encryptionKey) {
  return new PHIBoundary(db, encryptionKey);
}
__name(createPHIBoundary, "createPHIBoundary");

// src/middleware/hipaa-security.ts
function initializeHIPAASecurity(encryptionKey) {
  return async (c, next) => {
    const db = c.env.DB;
    if (!db) {
      return c.json({ error: "Database not configured" }, 500);
    }
    const sessionManager = createSessionManager(db);
    const auditLogger2 = createAuditLogger(db);
    const rbacManager = createRBACManager(db);
    const phiBoundary = createPHIBoundary(db, encryptionKey);
    const ipAddress = c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || c.req.header("X-Real-IP");
    const userAgent = c.req.header("User-Agent");
    c.set("sessionManager", sessionManager);
    c.set("auditLogger", auditLogger2);
    c.set("rbacManager", rbacManager);
    c.set("phiBoundary", phiBoundary);
    c.set("ipAddress", ipAddress);
    c.set("userAgent", userAgent);
    await next();
  };
}
__name(initializeHIPAASecurity, "initializeHIPAASecurity");

// src/middleware/phi-route-guard.ts
init_checked_fetch();
init_modules_watch_stub();
var PHI_BEARING_ROUTES = {
  assessments: {
    basePath: "/api/assessments",
    operations: ["read", "create", "update", "delete", "export"],
    phiFields: getTablePHIFields("assessments"),
    requiresAuth: true,
    requiresAudit: true
  },
  documents: {
    basePath: "/api/documents",
    operations: ["read", "create", "update", "delete", "share"],
    phiFields: getTablePHIFields("documents"),
    requiresAuth: true,
    requiresAudit: true
  },
  timeEntries: {
    basePath: "/api/time-entries",
    operations: ["read", "create", "update", "delete"],
    phiFields: getTablePHIFields("time_entries"),
    requiresAuth: true,
    requiresAudit: true
  },
  users: {
    basePath: "/api/users",
    operations: ["read", "update", "delete"],
    phiFields: getTablePHIFields("users"),
    requiresAuth: true,
    requiresAudit: true
  },
  clients: {
    basePath: "/api/clients",
    operations: ["read", "create", "update", "delete"],
    phiFields: getTablePHIFields("clients"),
    requiresAuth: true,
    requiresAudit: true
  }
};
var SUSPICIOUS_PHI_PATTERNS = [
  /\/api\/patient/i,
  /\/api\/health/i,
  /\/api\/medical/i,
  /\/api\/diagnosis/i,
  /\/api\/treatment/i,
  /\/api\/prescription/i,
  /\/api\/insurance/i,
  /\/api\/billing/i,
  /\/api\/claim/i,
  /\/api\/encounter/i,
  /\/api\/vital/i,
  /\/api\/lab/i,
  /\/api\/record/i,
  /\/api\/chart/i
];
var NON_PHI_ROUTES = /* @__PURE__ */ new Set([
  "/api/health",
  "/api/healthcheck",
  "/api/status",
  "/api/ping",
  "/api/auth/login",
  "/api/auth/logout",
  "/api/auth/register",
  "/api/auth/refresh",
  "/api/session/ping"
]);
var registeredRoutes = /* @__PURE__ */ new Map();
function isPHIBearingRoute(path) {
  for (const [route, config] of Object.entries(PHI_BEARING_ROUTES)) {
    if (path.startsWith(config.basePath)) {
      return route;
    }
  }
  return null;
}
__name(isPHIBearingRoute, "isPHIBearingRoute");
function isSuspiciousPHIRoute(path) {
  if (NON_PHI_ROUTES.has(path)) {
    return false;
  }
  for (const pattern of SUSPICIOUS_PHI_PATTERNS) {
    if (pattern.test(path)) {
      return true;
    }
  }
  return false;
}
__name(isSuspiciousPHIRoute, "isSuspiciousPHIRoute");
function enforceHIPAAMiddleware() {
  return async (c, next) => {
    const path = c.req.path;
    const method = c.req.method;
    const phiRoute = isPHIBearingRoute(path);
    const suspicious = isSuspiciousPHIRoute(path);
    const metadata = registeredRoutes.get(`${method}:${path}`);
    if (suspicious && !phiRoute && !metadata) {
      console.error(`CRITICAL SECURITY VIOLATION: Suspicious PHI route ${method} ${path} not explicitly registered!`);
      return c.json(
        {
          error: "Security configuration error",
          message: "This route matches PHI patterns but is not registered. If this route does not contain PHI, use declareNonPHIRoute(). Otherwise, register it in PHI_BEARING_ROUTES.",
          route: path,
          patterns: SUSPICIOUS_PHI_PATTERNS.filter((p) => p.test(path)).map((p) => p.toString()),
          action: "Contact security team to register this route properly"
        },
        500
      );
    }
    if (phiRoute || metadata?.requiresHIPAAMiddleware) {
      const hasSessionManager = c.get("sessionManager");
      const hasAuditLogger = c.get("auditLogger");
      const hasRBACManager = c.get("rbacManager");
      const hasPHIBoundary = c.get("phiBoundary");
      if (!hasSessionManager || !hasAuditLogger || !hasRBACManager || !hasPHIBoundary) {
        console.error(`CRITICAL SECURITY VIOLATION: PHI route ${method} ${path} accessed without HIPAA security middleware!`);
        return c.json(
          {
            error: "Security configuration error",
            message: "This route requires HIPAA security middleware but it was not initialized",
            route: path,
            phiRoute
          },
          500
        );
      }
      const sessionId = c.req.header("X-Session-ID");
      const userId = c.get("userId");
      const tenantId = c.get("tenantId");
      if (!sessionId) {
        console.error(`CRITICAL SECURITY VIOLATION: PHI route ${method} ${path} accessed without session!`);
        return c.json(
          {
            error: "Session required",
            message: "PHI routes require active session with X-Session-ID header",
            route: path,
            phiRoute
          },
          401
        );
      }
      const sessionValid = await hasSessionManager.validateSession(
        sessionId,
        c.get("ipAddress"),
        c.get("userAgent"),
        userId
      );
      if (!sessionValid.valid) {
        console.error(`PHI route ${method} ${path} accessed with invalid session: ${sessionValid.reason}`);
        return c.json(
          {
            error: "Session invalid",
            message: sessionValid.reason || "Your session is invalid or expired",
            code: sessionValid.reason === "Session expired due to idle timeout" ? "SESSION_IDLE_TIMEOUT" : sessionValid.reason === "Session expired (absolute timeout)" ? "SESSION_ABSOLUTE_TIMEOUT" : "SESSION_INVALID",
            route: path
          },
          401
        );
      }
      if (metadata && !metadata.requiresHIPAAMiddleware) {
        console.error(`CRITICAL SECURITY VIOLATION: PHI route ${method} ${path} is not registered with HIPAA middleware requirement!`);
        return c.json(
          {
            error: "Security configuration error",
            message: "This PHI-bearing route must be registered with requiresHIPAAMiddleware: true",
            route: path,
            phiRoute
          },
          500
        );
      }
    }
    await next();
  };
}
__name(enforceHIPAAMiddleware, "enforceHIPAAMiddleware");
function auditRouteAccess() {
  return async (c, next) => {
    const path = c.req.path;
    const phiRoute = isPHIBearingRoute(path);
    if (phiRoute) {
      const startTime = Date.now();
      let error = null;
      let statusCode = 200;
      try {
        await next();
        statusCode = c.res.status;
      } catch (e) {
        error = e;
        statusCode = 500;
        throw e;
      } finally {
        const duration = Date.now() - startTime;
        const auditLogger2 = c.get("auditLogger");
        const userId = c.get("userId");
        const tenantId = c.get("tenantId");
        if (!auditLogger2) {
          console.error("CRITICAL: Audit logger not available for PHI route access");
        }
        if (!userId || !tenantId) {
          console.error("CRITICAL: User/tenant context missing for PHI route access");
        }
        if (auditLogger2 && userId && tenantId) {
          const config = PHI_BEARING_ROUTES[phiRoute];
          try {
            await auditLogger2.log({
              tenantId,
              userId,
              action: "PHI_ACCESS",
              resourceType: phiRoute,
              resourceId: c.req.param("id") || "list",
              ipAddress: c.get("ipAddress") || "unknown",
              userAgent: c.get("userAgent") || "unknown",
              requestId: c.get("requestId"),
              success: !error && statusCode < 400,
              failureReason: error?.message || (statusCode >= 400 ? `HTTP ${statusCode}` : void 0),
              metadata: {
                method: c.req.method,
                path: c.req.path,
                duration,
                statusCode,
                phiFields: config.phiFields,
                sessionId: c.req.header("X-Session-ID")
              }
            });
          } catch (auditError) {
            console.error("CRITICAL: Failed to write audit log for PHI access:", auditError);
          }
        }
      }
    } else {
      await next();
    }
  };
}
__name(auditRouteAccess, "auditRouteAccess");

// src/lib/secure-database.ts
init_checked_fetch();
init_modules_watch_stub();
function detectPHIFieldsInQuery(sql, table) {
  if (!table) return [];
  const phiFields = [];
  const sqlLower = sql.toLowerCase();
  const tablePHIFields = getTablePHIFields(table);
  for (const field of tablePHIFields) {
    if (sqlLower.includes(field)) {
      phiFields.push(field);
    }
  }
  return phiFields;
}
__name(detectPHIFieldsInQuery, "detectPHIFieldsInQuery");
function detectTableInQuery(sql) {
  const sqlLower = sql.toLowerCase();
  const fromMatch = sqlLower.match(/from\s+(\w+)/);
  if (fromMatch) {
    return fromMatch[1];
  }
  const intoMatch = sqlLower.match(/into\s+(\w+)/);
  if (intoMatch) {
    return intoMatch[1];
  }
  const updateMatch = sqlLower.match(/update\s+(\w+)/);
  if (updateMatch) {
    return updateMatch[1];
  }
  const deleteMatch = sqlLower.match(/delete\s+from\s+(\w+)/);
  if (deleteMatch) {
    return deleteMatch[1];
  }
  return null;
}
__name(detectTableInQuery, "detectTableInQuery");
function isAllowedBypassQuery(sql) {
  const sqlLower = sql.toLowerCase();
  const allowedPatterns = [
    /^select.*from\s+audit_logs/,
    /^insert\s+into\s+audit_logs/,
    /^select.*from\s+audit_chain/,
    /^insert\s+into\s+audit_chain/,
    /^select.*from\s+phi_access_log/,
    /^insert\s+into\s+phi_access_log/,
    /^select.*from\s+session_activities/,
    /^insert\s+into\s+session_activities/,
    /^select.*from\s+roles/,
    /^select.*from\s+permissions/,
    /^select.*from\s+role_permissions/,
    /^select.*from\s+user_roles/,
    /^select.*from\s+sessions\s+where/,
    /^update\s+sessions\s+set\s+last_activity/,
    /^update\s+sessions\s+set\s+privileged/,
    /^update\s+sessions\s+set\s+mfa_verified_at/,
    /^delete\s+from\s+sessions\s+where/
  ];
  return allowedPatterns.some((pattern) => pattern.test(sqlLower));
}
__name(isAllowedBypassQuery, "isAllowedBypassQuery");
var SecureD1Database = class _SecureD1Database {
  static {
    __name(this, "SecureD1Database");
  }
  db;
  phiBoundaryRequired;
  auditLogger;
  context;
  constructor(db, options = {}) {
    this.db = db;
    this.phiBoundaryRequired = options.phiBoundaryRequired ?? true;
    this.auditLogger = options.auditLogger;
    this.context = options.context;
  }
  prepare(sql) {
    if (this.phiBoundaryRequired) {
      const table = detectTableInQuery(sql);
      const phiFields = detectPHIFieldsInQuery(sql, table);
      if (table && isPHITable(table) && phiFields.length > 0) {
        const isAllowed = isAllowedBypassQuery(sql);
        if (!isAllowed) {
          const error = new Error(
            `CRITICAL SECURITY VIOLATION: Direct database query with PHI fields detected!
Table: ${table}
PHI Fields: ${phiFields.join(", ")}
Request ID: ${this.context?.requestId || "N/A"}

All PHI operations must go through the PHIBoundary layer.
Use: phiBoundary.read() or phiBoundary.write() instead of direct DB queries.

If you need to bypass this check for system operations, use:
  new SecureD1Database(db, { phiBoundaryRequired: false })`
          );
          console.error(`[SECURITY] PHI access violation - Table: ${table}, Fields: ${phiFields.join(", ")}, Request: ${this.context?.requestId || "N/A"}`);
          if (this.auditLogger && this.context?.userId && this.context?.tenantId) {
            this.auditLogger.log({
              tenantId: this.context.tenantId,
              userId: this.context.userId,
              action: "ACCESS",
              resourceType: table,
              phiAccessed: phiFields,
              requestId: this.context.requestId,
              success: false,
              failureReason: "Direct PHI database access attempted",
              metadata: {
                table,
                phiFields: phiFields.join(", "),
                queryLength: sql.length
              }
            }).catch(console.error);
          }
          throw error;
        }
      }
    }
    return this.db.prepare(sql);
  }
  batch(statements) {
    return this.db.batch(statements);
  }
  dump() {
    return this.db.dump();
  }
  exec(query) {
    return this.db.exec(query);
  }
  setAuditContext(context) {
    this.context = context;
  }
  static createSystemDB(db, auditLogger2) {
    return new _SecureD1Database(db, {
      phiBoundaryRequired: false,
      auditLogger: auditLogger2
    });
  }
};
function wrapD1Database(db, options) {
  return new SecureD1Database(db, options);
}
__name(wrapD1Database, "wrapD1Database");

// src/utils/envelope-encryption.ts
init_checked_fetch();
init_modules_watch_stub();
var EnvelopeEncryption = class {
  static {
    __name(this, "EnvelopeEncryption");
  }
  masterKey;
  db;
  activeDEKCache = /* @__PURE__ */ new Map();
  constructor(masterKey, db) {
    this.masterKey = masterKey;
    this.db = db;
  }
  async initialize() {
    await this.createKeyManagementTables();
    await this.ensureActiveDEK();
  }
  async encrypt(plaintext, tenantId) {
    const dek = await this.getOrCreateActiveDEK(tenantId);
    const dekKey = await this.decryptDEK(dek.encryptedKey);
    const encoder = new TextEncoder();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      dekKey,
      encoder.encode(plaintext)
    );
    const encrypted = new Uint8Array(encryptedBuffer);
    const ciphertext = encrypted.slice(0, -16);
    const tag = encrypted.slice(-16);
    return {
      ciphertext: this.bufferToBase64(ciphertext),
      iv: this.bufferToBase64(iv),
      tag: this.bufferToBase64(tag),
      dekId: dek.id,
      algorithm: "AES-GCM-256"
    };
  }
  async decrypt(encryptedData) {
    const dek = await this.getDEK(encryptedData.dekId);
    if (!dek) {
      throw new Error(`DEK not found: ${encryptedData.dekId}`);
    }
    if (dek.status === "compromised") {
      throw new Error(`Cannot decrypt with compromised DEK: ${encryptedData.dekId}`);
    }
    const dekKey = await this.decryptDEK(dek.encryptedKey);
    const iv = this.base64ToBuffer(encryptedData.iv);
    const ciphertext = this.base64ToBuffer(encryptedData.ciphertext);
    const tag = this.base64ToBuffer(encryptedData.tag);
    const encryptedBuffer = new Uint8Array([...ciphertext, ...tag]);
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
        tagLength: 128
      },
      dekKey,
      encryptedBuffer
    );
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  }
  async rotateDEK(tenantId, rotatedBy, reason) {
    const oldDEK = await this.getActiveDEK(tenantId);
    if (!oldDEK) {
      throw new Error(`No active DEK found for tenant: ${tenantId}`);
    }
    const newDEK = await this.createDEK(tenantId);
    await this.db.prepare(
      `UPDATE data_encryption_keys
         SET status = 'rotated', rotated_at = ?
         WHERE id = ?`
    ).bind(Math.floor(Date.now() / 1e3), oldDEK.id).run();
    const logId = crypto.randomUUID();
    await this.db.prepare(
      `INSERT INTO key_rotation_logs (id, old_dek_id, new_dek_id, rotated_by, reason, records_reencrypted, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      logId,
      oldDEK.id,
      newDEK.id,
      rotatedBy,
      reason,
      0,
      Math.floor(Date.now() / 1e3)
    ).run();
    this.activeDEKCache.delete(tenantId);
    return {
      newDekId: newDEK.id,
      recordsReencrypted: 0
    };
  }
  async reencryptWithNewDEK(oldEncrypted) {
    const plaintext = await this.decrypt(oldEncrypted);
    const oldDEK = await this.getDEK(oldEncrypted.dekId);
    if (!oldDEK) {
      throw new Error(`Old DEK not found: ${oldEncrypted.dekId}`);
    }
    const tenantIdResult = await this.db.prepare("SELECT tenant_id FROM data_encryption_keys WHERE id = ?").bind(oldEncrypted.dekId).first();
    const tenantId = tenantIdResult?.tenant_id;
    return this.encrypt(plaintext, tenantId);
  }
  async markDEKCompromised(dekId, reason) {
    await this.db.prepare(
      `UPDATE data_encryption_keys
         SET status = 'compromised'
         WHERE id = ?`
    ).bind(dekId).run();
    await this.db.prepare(
      `INSERT INTO key_compromise_logs (id, dek_id, reason, created_at)
         VALUES (?, ?, ?, ?)`
    ).bind(
      crypto.randomUUID(),
      dekId,
      reason,
      Math.floor(Date.now() / 1e3)
    ).run();
  }
  async getKeyRotationHistory(tenantId, limit = 10) {
    const result = await this.db.prepare(
      `SELECT krl.*
         FROM key_rotation_logs krl
         JOIN data_encryption_keys dek ON krl.new_dek_id = dek.id
         WHERE dek.tenant_id = ?
         ORDER BY krl.created_at DESC
         LIMIT ?`
    ).bind(tenantId, limit).all();
    return (result.results || []).map((row) => ({
      id: row.id,
      oldDekId: row.old_dek_id,
      newDekId: row.new_dek_id,
      rotatedBy: row.rotated_by,
      reason: row.reason,
      recordsReencrypted: row.records_reencrypted,
      createdAt: row.created_at
    }));
  }
  async validateMasterKey() {
    try {
      const testDEK = await this.getActiveDEK("test-validation");
      if (testDEK) {
        await this.decryptDEK(testDEK.encryptedKey);
      }
      return true;
    } catch (error) {
      console.error("Master key validation failed:", error);
      return false;
    }
  }
  async createKeyManagementTables() {
    await this.db.exec(
      `
        CREATE TABLE IF NOT EXISTS data_encryption_keys (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          tenant_id TEXT NOT NULL,
          version INTEGER NOT NULL DEFAULT 1,
          encrypted_key TEXT NOT NULL,
          key_hash TEXT NOT NULL,
          algorithm TEXT NOT NULL DEFAULT 'AES-GCM-256',
          status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotated', 'compromised')),
          created_at INTEGER NOT NULL DEFAULT (unixepoch()),
          rotated_at INTEGER,
          FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE RESTRICT
        );

        CREATE INDEX IF NOT EXISTS idx_dek_tenant_id ON data_encryption_keys(tenant_id);
        CREATE INDEX IF NOT EXISTS idx_dek_status ON data_encryption_keys(status);

        CREATE TABLE IF NOT EXISTS key_rotation_logs (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          old_dek_id TEXT NOT NULL,
          new_dek_id TEXT NOT NULL,
          rotated_by TEXT NOT NULL,
          reason TEXT NOT NULL,
          records_reencrypted INTEGER DEFAULT 0,
          created_at INTEGER NOT NULL DEFAULT (unixepoch()),
          FOREIGN KEY (old_dek_id) REFERENCES data_encryption_keys(id),
          FOREIGN KEY (new_dek_id) REFERENCES data_encryption_keys(id)
        );

        CREATE INDEX IF NOT EXISTS idx_krl_old_dek ON key_rotation_logs(old_dek_id);
        CREATE INDEX IF NOT EXISTS idx_krl_new_dek ON key_rotation_logs(new_dek_id);
        CREATE INDEX IF NOT EXISTS idx_krl_created_at ON key_rotation_logs(created_at);

        CREATE TABLE IF NOT EXISTS key_compromise_logs (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          dek_id TEXT NOT NULL,
          reason TEXT NOT NULL,
          created_at INTEGER NOT NULL DEFAULT (unixepoch()),
          FOREIGN KEY (dek_id) REFERENCES data_encryption_keys(id)
        );

        CREATE INDEX IF NOT EXISTS idx_kcl_dek ON key_compromise_logs(dek_id);
        CREATE INDEX IF NOT EXISTS idx_kcl_created_at ON key_compromise_logs(created_at);

        CREATE TABLE IF NOT EXISTS master_key_access_log (
          id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
          accessed_by TEXT NOT NULL,
          operation TEXT NOT NULL CHECK (operation IN ('encrypt', 'decrypt', 'rotate', 'validate')),
          ip_address TEXT,
          success INTEGER NOT NULL DEFAULT 1 CHECK (success IN (0, 1)),
          failure_reason TEXT,
          created_at INTEGER NOT NULL DEFAULT (unixepoch())
        );

        CREATE INDEX IF NOT EXISTS idx_mkal_accessed_by ON master_key_access_log(accessed_by);
        CREATE INDEX IF NOT EXISTS idx_mkal_operation ON master_key_access_log(operation);
        CREATE INDEX IF NOT EXISTS idx_mkal_created_at ON master_key_access_log(created_at);
      `
    ).catch((err) => {
      console.error("Failed to create key management tables:", err);
    });
  }
  async ensureActiveDEK() {
    const result = await this.db.prepare(
      `SELECT COUNT(*) as count
         FROM data_encryption_keys
         WHERE status = 'active'`
    ).first();
    if (result && result.count === 0) {
      await this.createDEK("default");
    }
  }
  async createDEK(tenantId) {
    const rawDEK = crypto.getRandomValues(new Uint8Array(32));
    const dekKey = await crypto.subtle.importKey(
      "raw",
      rawDEK,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
    const encryptedKey = await this.encryptWithMasterKey(rawDEK);
    const keyHashBuffer = await crypto.subtle.digest("SHA-256", rawDEK);
    const keyHash = this.bufferToBase64(new Uint8Array(keyHashBuffer));
    const id = crypto.randomUUID();
    const createdAt = Math.floor(Date.now() / 1e3);
    const maxVersionResult = await this.db.prepare(
      `SELECT COALESCE(MAX(version), 0) as max_version
         FROM data_encryption_keys
         WHERE tenant_id = ?`
    ).bind(tenantId).first();
    const version = (maxVersionResult?.max_version || 0) + 1;
    await this.db.prepare(
      `INSERT INTO data_encryption_keys (id, tenant_id, version, encrypted_key, key_hash, algorithm, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(id, tenantId, version, encryptedKey, keyHash, "AES-GCM-256", "active", createdAt).run();
    return {
      id,
      version,
      encryptedKey,
      keyHash,
      algorithm: "AES-GCM-256",
      createdAt,
      status: "active"
    };
  }
  async encryptWithMasterKey(data) {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(this.masterKey),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"]
    );
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 1e5,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt"]
    );
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      data
    );
    const combined = new Uint8Array(salt.length + iv.length + encrypted.byteLength);
    combined.set(salt, 0);
    combined.set(iv, salt.length);
    combined.set(new Uint8Array(encrypted), salt.length + iv.length);
    return this.bufferToBase64(combined);
  }
  async decryptDEK(encryptedKey) {
    const combined = this.base64ToBuffer(encryptedKey);
    const salt = combined.slice(0, 16);
    const iv = combined.slice(16, 28);
    const ciphertext = combined.slice(28);
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      encoder.encode(this.masterKey),
      "PBKDF2",
      false,
      ["deriveBits", "deriveKey"]
    );
    const key = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations: 1e5,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"]
    );
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      ciphertext
    );
    return crypto.subtle.importKey(
      "raw",
      decrypted,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }
  async getOrCreateActiveDEK(tenantId) {
    let dek = await this.getActiveDEK(tenantId);
    if (!dek) {
      dek = await this.createDEK(tenantId);
    }
    return dek;
  }
  async getActiveDEK(tenantId) {
    const result = await this.db.prepare(
      `SELECT id, tenant_id, version, encrypted_key, key_hash, algorithm, status, created_at, rotated_at
         FROM data_encryption_keys
         WHERE tenant_id = ? AND status = 'active'
         ORDER BY version DESC
         LIMIT 1`
    ).bind(tenantId).first();
    if (!result) {
      return null;
    }
    return {
      id: result.id,
      version: result.version,
      encryptedKey: result.encrypted_key,
      keyHash: result.key_hash,
      algorithm: result.algorithm,
      createdAt: result.created_at,
      rotatedAt: result.rotated_at,
      status: result.status
    };
  }
  async getDEK(dekId) {
    const result = await this.db.prepare(
      `SELECT id, tenant_id, version, encrypted_key, key_hash, algorithm, status, created_at, rotated_at
         FROM data_encryption_keys
         WHERE id = ?`
    ).bind(dekId).first();
    if (!result) {
      return null;
    }
    return {
      id: result.id,
      version: result.version,
      encryptedKey: result.encrypted_key,
      keyHash: result.key_hash,
      algorithm: result.algorithm,
      createdAt: result.created_at,
      rotatedAt: result.rotated_at,
      status: result.status
    };
  }
  bufferToBase64(buffer) {
    const bytes = Array.from(buffer);
    const binary = bytes.map((b) => String.fromCharCode(b)).join("");
    return btoa(binary);
  }
  base64ToBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
};
function createEnvelopeEncryption(masterKey, db) {
  return new EnvelopeEncryption(masterKey, db);
}
__name(createEnvelopeEncryption, "createEnvelopeEncryption");

// src/utils/schema-validator.ts
init_checked_fetch();
init_modules_watch_stub();
var KNOWN_PHI_COLUMN_PATTERNS = [
  /ssn/i,
  /social_security/i,
  /date_of_birth/i,
  /dob/i,
  /phone/i,
  /email/i,
  /address/i,
  /medical_record/i,
  /diagnosis/i,
  /treatment/i,
  /prescription/i,
  /insurance/i,
  /client_name/i,
  /patient/i,
  /health/i,
  /^notes$/i,
  /^description$/i,
  /^results$/i,
  /^responses$/i
];
function isPotentialPHIField(columnName) {
  return KNOWN_PHI_COLUMN_PATTERNS.some((pattern) => pattern.test(columnName));
}
__name(isPotentialPHIField, "isPotentialPHIField");
async function validateTablePHIFieldMapping(db) {
  const result = {
    valid: true,
    warnings: [],
    errors: [],
    missingTables: [],
    missingFields: [],
    unmappedPHIFields: []
  };
  for (const tableName of PHI_BEARING_TABLES) {
    try {
      const tableInfo = await db.prepare(
        `PRAGMA table_info(${tableName})`
      ).all();
      if (!tableInfo.results || tableInfo.results.length === 0) {
        result.missingTables.push(tableName);
        result.errors.push(
          `Table '${tableName}' is declared as PHI-bearing but does not exist in schema`
        );
        result.valid = false;
        continue;
      }
      const actualColumns = tableInfo.results.map((col) => col.name.toLowerCase());
      const declaredPHIFields = getTablePHIFields(tableName).map((f) => f.toLowerCase());
      for (const phiField of declaredPHIFields) {
        if (!actualColumns.includes(phiField)) {
          result.missingFields.push({ table: tableName, field: phiField });
          result.warnings.push(
            `PHI field '${phiField}' declared for table '${tableName}' but column does not exist in schema`
          );
        }
      }
      for (const columnName of actualColumns) {
        if (isPotentialPHIField(columnName) && !declaredPHIFields.includes(columnName)) {
          result.unmappedPHIFields.push({ table: tableName, field: columnName });
          result.warnings.push(
            `Column '${columnName}' in table '${tableName}' looks like PHI but is not declared in TABLE_PHI_FIELDS`
          );
        }
      }
    } catch (error) {
      result.errors.push(
        `Failed to validate table '${tableName}': ${error instanceof Error ? error.message : String(error)}`
      );
      result.valid = false;
    }
  }
  if (result.errors.length > 0) {
    result.valid = false;
  }
  return result;
}
__name(validateTablePHIFieldMapping, "validateTablePHIFieldMapping");
async function logSchemaValidation(db, logger = console) {
  logger.log("[HIPAA] Validating TABLE_PHI_FIELDS against database schema...");
  const validation = await validateTablePHIFieldMapping(db);
  if (validation.valid && validation.warnings.length === 0) {
    logger.log("[HIPAA] \u2705 Schema validation passed - all PHI fields properly mapped");
    return;
  }
  if (validation.errors.length > 0) {
    logger.error("[HIPAA] \u274C CRITICAL: Schema validation failed!");
    for (const error of validation.errors) {
      logger.error(`  - ${error}`);
    }
  }
  if (validation.warnings.length > 0) {
    logger.warn("[HIPAA] \u26A0\uFE0F  Schema validation warnings:");
    for (const warning of validation.warnings) {
      logger.warn(`  - ${warning}`);
    }
  }
  if (validation.missingTables.length > 0) {
    logger.error("[HIPAA] Missing tables:", validation.missingTables);
  }
  if (validation.unmappedPHIFields.length > 0) {
    logger.warn(
      "[HIPAA] \u26A0\uFE0F  Found potential PHI fields not declared in TABLE_PHI_FIELDS:",
      validation.unmappedPHIFields
    );
    logger.warn("[HIPAA] Please review and add these to src/types/phi-registry.ts if they contain PHI");
  }
  if (!validation.valid) {
    throw new Error(
      "HIPAA schema validation failed! TABLE_PHI_FIELDS does not match database schema. This creates a security risk where PHI fields may be unprotected. See logs above for details."
    );
  }
}
__name(logSchemaValidation, "logSchemaValidation");

// src/worker.ts
var app = new Hono2();
var schemaValidationRun = false;
app.use("*", async (c, next) => {
  if (!c.env.MASTER_ENCRYPTION_KEY) {
    console.error("CRITICAL: MASTER_ENCRYPTION_KEY not configured");
    return c.json({
      error: "Server configuration error",
      code: "ENCRYPTION_NOT_CONFIGURED"
    }, 500);
  }
  const envelopeEncryption = createEnvelopeEncryption(
    c.env.MASTER_ENCRYPTION_KEY,
    c.env.DB
  );
  try {
    await envelopeEncryption.initialize();
  } catch (error) {
    console.error("Failed to initialize envelope encryption:", error);
  }
  c.set("envelopeEncryption", envelopeEncryption);
  if (!schemaValidationRun && c.env.ENVIRONMENT !== "production") {
    try {
      await logSchemaValidation(c.env.DB);
      schemaValidationRun = true;
    } catch (error) {
      console.error("[HIPAA] Schema validation failed:", error);
    }
  }
  await next();
});
app.use("*", async (c, next) => {
  const encryptionKey = c.env.MASTER_ENCRYPTION_KEY;
  await initializeHIPAASecurity(encryptionKey)(c, next);
});
app.use("*", async (c, next) => {
  const auditLogger2 = c.get("auditLogger");
  const userId = c.get("userId");
  const tenantId = c.get("tenantId");
  if (auditLogger2 && userId && tenantId) {
    const secureDb = wrapD1Database(c.env.DB, {
      auditLogger: auditLogger2,
      context: {
        userId,
        tenantId,
        requestId: c.get("requestId"),
        ipAddress: c.get("ipAddress")
      }
    });
    c.set("db", secureDb);
  }
  await next();
});
app.use("*", enforceHIPAAMiddleware());
app.use("/api/*", auditRouteAccess());
app.use("*", async (c, next) => {
  const origin = c.req.header("Origin") || "";
  const allowedOrigins = [
    "http://localhost:5173",
    "https://localhost:5173",
    "https://meek-cheesecake-1382d7.netlify.app",
    c.env.APP_ORIGIN
  ].filter(Boolean);
  if (c.req.method === "OPTIONS") {
    return handlePreflight(origin, allowedOrigins);
  }
  await next();
  const corsHeaders = createCorsHeaders(origin, allowedOrigins);
  Object.entries(corsHeaders).forEach(([key, value]) => {
    c.res.headers.set(key, value);
  });
});
app.use("/api/*", async (c, next) => {
  const ip = c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown";
  const rateLimitKey = `api:${ip}`;
  const allowed = await rateLimitCheck(c.env, rateLimitKey, 1e3, 6e4);
  if (!allowed) {
    return c.json({
      error: "Rate limit exceeded",
      code: "RATE_LIMIT_EXCEEDED"
    }, 429);
  }
  await next();
});
app.use("/api/*", async (c, next) => {
  if (c.req.path.startsWith("/api/auth/") || c.req.path === "/health") {
    return next();
  }
  const authHeader = c.req.header("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return c.json({
      error: "Missing or invalid authorization header",
      code: "UNAUTHORIZED"
    }, 401);
  }
  const token = authHeader.substring(7);
  try {
    const payload = await verifyJWT(token, c.env.JWT_SECRET);
    const userId = payload.user_id;
    const userRole = payload.role;
    const userEmail = payload.email;
    const userType = payload.user_type;
    const tenantId = payload.tenant_id;
    const readOnly = payload.read_only || false;
    if (!validateUserId(userId)) {
      return c.json({
        error: "Invalid user ID format",
        code: "INVALID_USER"
      }, 400);
    }
    if (userType === "platform" && !tenantId) {
      return c.json({
        error: "Tenant context required for platform admin",
        code: "TENANT_CONTEXT_REQUIRED"
      }, 400);
    }
    if (readOnly && !["GET", "HEAD", "OPTIONS"].includes(c.req.method)) {
      return c.json({
        error: "Read-only mode active. Write operations are not permitted.",
        code: "READ_ONLY_MODE"
      }, 403);
    }
    c.set("user_id", userId);
    c.set("user_role", userRole);
    c.set("user_email", userEmail);
    c.set("user_type", userType);
    c.set("tenant_id", tenantId || "default");
    c.set("read_only", readOnly);
    c.set("user_ip", c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown");
    c.set("userId", userId);
    c.set("userRole", userRole);
    c.set("userEmail", userEmail);
    c.set("userType", userType);
    c.set("tenantId", tenantId || "default");
    c.set("readOnly", readOnly);
    c.set("ipAddress", c.req.header("CF-Connecting-IP") || c.req.header("X-Forwarded-For") || "unknown");
    c.set("userAgent", c.req.header("User-Agent") || "unknown");
    c.set("requestId", crypto.randomUUID());
    await auditLogger(c.env, {
      tenant_id: tenantId || "default",
      user_id: userId,
      action: "api_access",
      resource_type: "api",
      resource_id: c.req.path,
      ip_address: c.get("user_ip"),
      user_agent: c.req.header("User-Agent"),
      details: userType === "platform" ? JSON.stringify({ acting_as_tenant: tenantId, read_only: readOnly }) : void 0
    }).catch((error) => {
      console.error("Audit logging failed:", error);
    });
  } catch (error) {
    return c.json({
      error: "Invalid or expired token",
      code: "TOKEN_INVALID"
    }, 401);
  }
  await next();
});
app.route("/api/auth", authRouter);
app.route("/api/time-entries", timeEntriesRouter);
app.route("/api/analytics", analyticsRouter);
app.route("/api/documents", documentsRouter);
app.route("/api/assessments", assessmentsRouter);
app.route("/api/centralreach", centralReachRouter);
app.route("/api/quickbooks", quickBooksRouter);
app.get("/health", (c) => {
  return c.json({
    status: "ok",
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    environment: c.env.ENVIRONMENT || "unknown"
  });
});
app.onError((err, c) => {
  console.error("Unhandled error:", err);
  return c.json({
    error: "Internal server error",
    code: "INTERNAL_ERROR",
    timestamp: (/* @__PURE__ */ new Date()).toISOString()
  }, 500);
});
app.notFound((c) => {
  return c.json({
    error: "Not found",
    code: "NOT_FOUND",
    path: c.req.path
  }, 404);
});
var worker_default = app;

// node_modules/wrangler/templates/middleware/middleware-ensure-req-body-drained.ts
init_checked_fetch();
init_modules_watch_stub();
var drainBody = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } finally {
    try {
      if (request.body !== null && !request.bodyUsed) {
        const reader = request.body.getReader();
        while (!(await reader.read()).done) {
        }
      }
    } catch (e) {
      console.error("Failed to drain the unused request body.", e);
    }
  }
}, "drainBody");
var middleware_ensure_req_body_drained_default = drainBody;

// node_modules/wrangler/templates/middleware/middleware-miniflare3-json-error.ts
init_checked_fetch();
init_modules_watch_stub();
function reduceError(e) {
  return {
    name: e?.name,
    message: e?.message ?? String(e),
    stack: e?.stack,
    cause: e?.cause === void 0 ? void 0 : reduceError(e.cause)
  };
}
__name(reduceError, "reduceError");
var jsonError = /* @__PURE__ */ __name(async (request, env, _ctx, middlewareCtx) => {
  try {
    return await middlewareCtx.next(request, env);
  } catch (e) {
    const error = reduceError(e);
    return Response.json(error, {
      status: 500,
      headers: { "MF-Experimental-Error-Stack": "true" }
    });
  }
}, "jsonError");
var middleware_miniflare3_json_error_default = jsonError;

// .wrangler/tmp/bundle-fkHa3b/middleware-insertion-facade.js
var __INTERNAL_WRANGLER_MIDDLEWARE__ = [
  middleware_ensure_req_body_drained_default,
  middleware_miniflare3_json_error_default
];
var middleware_insertion_facade_default = worker_default;

// node_modules/wrangler/templates/middleware/common.ts
init_checked_fetch();
init_modules_watch_stub();
var __facade_middleware__ = [];
function __facade_register__(...args) {
  __facade_middleware__.push(...args.flat());
}
__name(__facade_register__, "__facade_register__");
function __facade_invokeChain__(request, env, ctx, dispatch, middlewareChain) {
  const [head, ...tail] = middlewareChain;
  const middlewareCtx = {
    dispatch,
    next(newRequest, newEnv) {
      return __facade_invokeChain__(newRequest, newEnv, ctx, dispatch, tail);
    }
  };
  return head(request, env, ctx, middlewareCtx);
}
__name(__facade_invokeChain__, "__facade_invokeChain__");
function __facade_invoke__(request, env, ctx, dispatch, finalMiddleware) {
  return __facade_invokeChain__(request, env, ctx, dispatch, [
    ...__facade_middleware__,
    finalMiddleware
  ]);
}
__name(__facade_invoke__, "__facade_invoke__");

// .wrangler/tmp/bundle-fkHa3b/middleware-loader.entry.ts
var __Facade_ScheduledController__ = class ___Facade_ScheduledController__ {
  constructor(scheduledTime, cron, noRetry) {
    this.scheduledTime = scheduledTime;
    this.cron = cron;
    this.#noRetry = noRetry;
  }
  static {
    __name(this, "__Facade_ScheduledController__");
  }
  #noRetry;
  noRetry() {
    if (!(this instanceof ___Facade_ScheduledController__)) {
      throw new TypeError("Illegal invocation");
    }
    this.#noRetry();
  }
};
function wrapExportedHandler(worker) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return worker;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  const fetchDispatcher = /* @__PURE__ */ __name(function(request, env, ctx) {
    if (worker.fetch === void 0) {
      throw new Error("Handler does not export a fetch() function.");
    }
    return worker.fetch(request, env, ctx);
  }, "fetchDispatcher");
  return {
    ...worker,
    fetch(request, env, ctx) {
      const dispatcher = /* @__PURE__ */ __name(function(type, init) {
        if (type === "scheduled" && worker.scheduled !== void 0) {
          const controller = new __Facade_ScheduledController__(
            Date.now(),
            init.cron ?? "",
            () => {
            }
          );
          return worker.scheduled(controller, env, ctx);
        }
      }, "dispatcher");
      return __facade_invoke__(request, env, ctx, dispatcher, fetchDispatcher);
    }
  };
}
__name(wrapExportedHandler, "wrapExportedHandler");
function wrapWorkerEntrypoint(klass) {
  if (__INTERNAL_WRANGLER_MIDDLEWARE__ === void 0 || __INTERNAL_WRANGLER_MIDDLEWARE__.length === 0) {
    return klass;
  }
  for (const middleware of __INTERNAL_WRANGLER_MIDDLEWARE__) {
    __facade_register__(middleware);
  }
  return class extends klass {
    #fetchDispatcher = /* @__PURE__ */ __name((request, env, ctx) => {
      this.env = env;
      this.ctx = ctx;
      if (super.fetch === void 0) {
        throw new Error("Entrypoint class does not define a fetch() function.");
      }
      return super.fetch(request);
    }, "#fetchDispatcher");
    #dispatcher = /* @__PURE__ */ __name((type, init) => {
      if (type === "scheduled" && super.scheduled !== void 0) {
        const controller = new __Facade_ScheduledController__(
          Date.now(),
          init.cron ?? "",
          () => {
          }
        );
        return super.scheduled(controller);
      }
    }, "#dispatcher");
    fetch(request) {
      return __facade_invoke__(
        request,
        this.env,
        this.ctx,
        this.#dispatcher,
        this.#fetchDispatcher
      );
    }
  };
}
__name(wrapWorkerEntrypoint, "wrapWorkerEntrypoint");
var WRAPPED_ENTRY;
if (typeof middleware_insertion_facade_default === "object") {
  WRAPPED_ENTRY = wrapExportedHandler(middleware_insertion_facade_default);
} else if (typeof middleware_insertion_facade_default === "function") {
  WRAPPED_ENTRY = wrapWorkerEntrypoint(middleware_insertion_facade_default);
}
var middleware_loader_entry_default = WRAPPED_ENTRY;
export {
  __INTERNAL_WRANGLER_MIDDLEWARE__,
  middleware_loader_entry_default as default
};
//# sourceMappingURL=worker.js.map
