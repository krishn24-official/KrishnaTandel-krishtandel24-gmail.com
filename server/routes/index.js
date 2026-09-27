// Route registration. First match wins — register specific paths before parameterised ones.
// '/members/me' before '/members/:userId' etc.

import { registerAuthRoutes } from './auth.js';
import { registerOrgRoutes } from './orgs.js';
import { registerInviteRoutes } from './invites.js';
import { registerDeviceRoutes } from './devices.js';
import { registerSessionRoutes } from './sessions.js';

export function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
  registerOrgRoutes(router, deps);
  registerInviteRoutes(router, deps);
  registerDeviceRoutes(router, deps);
  registerSessionRoutes(router, deps);
}
