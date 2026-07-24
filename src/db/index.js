// Single import surface for the data layer:
//   import { db } from './db/index.js';
//   await db.checks.saveCheck(result, { userId });
export { getPool, dbEnabled, query, withTransaction, closePool } from './pool.js';
export { migrate } from './migrate.js';

import * as users from './repositories/users.js';
import * as domains from './repositories/domains.js';
import * as checks from './repositories/checks.js';
import * as monitors from './repositories/monitors.js';
import * as alerts from './repositories/alerts.js';

export const db = { users, domains, checks, monitors, alerts };
