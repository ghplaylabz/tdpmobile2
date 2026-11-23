<?php
/**
 * Sent to the TDP admins (Default.admin_email, Login.deactivation_notify_emails) and the agent's master accounts.
 *
 * @var array $data name, email, company, failures, minutes (null: no window), ip, time
 */
?>
<p>Hello,</p>
<p>The agent user <b><?= h($data['name']) ?></b> (<?= h($data['email']) ?>)<?= $data['company'] !== '' ? ' of <b>' . h($data['company']) . '</b>' : '' ?>
has been <b>disabled</b>. Someone entered this user's password correctly but then entered a wrong sign-in code
<?= h($data['failures']) ?> times<?= !empty($data['minutes']) ? ' within ' . h($data['minutes']) . ' minutes' : ' without signing in successfully' ?>.
The last attempt came from the IP address <?= h($data['ip']) ?> on <?= h($data['time']) ?>.</p>
<p>The user cannot log in or reset their password until they are enabled again. Before enabling the user, check
with them whether these attempts were theirs. If they weren't, their password is probably known to someone else:
reset it.</p>
<p>A master account can enable the user again from <b>Agent Users</b>; TDP staff can do it from the back office.</p>
<p>This is an auto generated email. Do not reply.</p>
