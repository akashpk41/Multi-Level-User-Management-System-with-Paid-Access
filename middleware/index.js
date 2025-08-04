// Middleware Index - Export all middleware
const auth = require("./auth");
const role = require("./role");
const rateLimiter = require("./rateLimiter");
const deviceLock = require("./deviceLock");

// Combine auth and device lock for common authentication flow
const authenticateAndVerifyDevice = [
  deviceLock.extractDeviceId,
  auth.verifyToken,
  deviceLock.checkSingleDeviceLock,
  deviceLock.checkMultiDeviceLock,
  auth.verifyDevice,
];

// Full authentication with role checking
const authenticateWithRole = (roles) => [
  ...authenticateAndVerifyDevice,
  role.authorize(roles),
];

// Authentication with subscription/package checking
const authenticateWithChecks = [
  ...authenticateAndVerifyDevice,
  role.checkSubAdminSubscription,
  role.checkUserPackage,
];

// Authentication with all checks and role
const fullAuthentication = (roles) => [
  ...authenticateWithChecks,
  role.authorize(roles),
];

module.exports = {
  // Individual middleware modules
  auth,
  role,
  rateLimiter,
  deviceLock,

  // Combined middleware chains
  authenticateAndVerifyDevice,
  authenticateWithRole,
  authenticateWithChecks,
  fullAuthentication,

  // Common middleware combinations
  userAuth: fullAuthentication(["user"]),
  subAdminAuth: fullAuthentication(["subadmin"]),
  mainAdminAuth: fullAuthentication(["mainadmin"]),
  adminAuth: fullAuthentication(["subadmin", "mainadmin"]),
  allRolesAuth: fullAuthentication(["user", "subadmin", "mainadmin"]),

  // Rate limiters
  limiters: rateLimiter,
};
