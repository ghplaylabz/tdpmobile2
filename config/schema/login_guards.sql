-- Agent sign-in guards (App\Model\Table\LoginsTable): `logins.loc` values for wrong sign-in codes
-- (agent_code) and sign-in code emails (agent_otp_mail).
--
-- The `logins` table is shared with tdpadmin, which owns its migrations: prefer running tdpadmin's
-- `bin/cake migrations migrate` (migration AddAgentLoginGuards). This file is the same change for a DB
-- without tdpadmin. Run it BEFORE deploying the tdpmobile2 code that writes these values.
-- It assumes tdpadmin's AddLoginGuards (admin_code, admin_otp_mail, email_loc_created_idx) already ran.
-- After running: bin/cake schema_cache clear

ALTER TABLE `logins`
  MODIFY `loc` ENUM('agent', 'admin', 'merchant', 'redeem', 'admin_code', 'admin_otp_mail', 'agent_code', 'agent_otp_mail') NULL DEFAULT 'agent';

-- Only if tdpadmin's AddLoginGuards has not run (index for the per-account counts):
-- ALTER TABLE `logins` ADD INDEX `email_loc_created_idx` (`email`, `loc`, `created`);
