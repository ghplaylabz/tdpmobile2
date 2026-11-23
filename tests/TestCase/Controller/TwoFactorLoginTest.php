<?php
declare(strict_types=1);

namespace App\Test\TestCase\Controller;

use App\Lib\Turnstile;
use App\Lib\TwoFactor;
use Authentication\PasswordHasher\DefaultPasswordHasher;
use Cake\Core\Configure;
use Cake\Database\Connection;
use Cake\Http\Client;
use Cake\Http\Client\Response;
use Cake\I18n\DateTime;
use Cake\TestSuite\EmailTrait;
use Cake\TestSuite\IntegrationTestTrait;
use Cake\TestSuite\TestCase;
use Cake\Utility\Hash;
use RobThree\Auth\Providers\Qr\BaconQrCodeProvider;
use RobThree\Auth\TwoFactorAuth;
use RuntimeException;
use Throwable;

/**
 * Login with the second factor: authenticator app, emailed OTP,
 * first-time set-up, and the master's reset.
 */
class TwoFactorLoginTest extends TestCase
{
    use EmailTrait;
    use IntegrationTestTrait;

    protected array $fixtures = [
        'app.Agents',
        'app.AgentUsers',
        'app.AgentSessions',
        'app.Logins',
        'app.Logs',
        'app.UsersIpaddress',
        'app.LastOtpIps',
        'app.PasswordResets',
    ];

    private const AGENT_A = '00000000-0000-4000-8000-00000000000a';
    private const AGENT_B = '00000000-0000-4000-8000-00000000000b';
    private const MASTER_A = '00000000-0000-4000-8000-0000000000a1';
    private const NORMAL_A = '00000000-0000-4000-8000-0000000000a2';
    private const NORMAL_B = '00000000-0000-4000-8000-0000000000b2';
    private const PASSWORD = 'Secret#12345';
    private const IP = '10.1.2.3';

    private Connection $db;

    protected function setUp(): void
    {
        parent::setUp();
        $this->db = $this->getTableLocator()->get('Agents')->getConnection();
        // Raw inserts: the ORM would run LoggableBehavior, which isn't the subject here.
        foreach ([self::AGENT_A => 'Agent A', self::AGENT_B => 'Agent B'] as $id => $name) {
            $this->db->insert('agents', [
                'id' => $id, 'first_name' => 'Test', 'last_name' => $name, 'email' => strtolower(str_replace(' ', '', $name)) . '@example.com',
                'company_name' => $name, 'image' => '', 'country' => 'Singapore', 'gender' => 'male', 'enable_api' => 0,
                'status' => 'active', 'enable_agent_login' => 1, 'mobile_otp' => 1, 'credits' => '100.00',
            ], ['id' => 'binaryuuid']);
        }
        $hash = (new DefaultPasswordHasher())->hash(self::PASSWORD);
        $users = [
            [self::MASTER_A, self::AGENT_A, 'master', 'master.a@example.com'],
            [self::NORMAL_A, self::AGENT_A, 'normal', 'normal.a@example.com'],
            [self::NORMAL_B, self::AGENT_B, 'normal', 'normal.b@example.com'],
        ];
        foreach ($users as [$id, $agentId, $role, $email]) {
            $this->db->insert('agent_users', [
                'id' => $id, 'agent_id' => $agentId, 'name' => $role . ' user', 'email' => $email,
                'password' => $hash, 'role' => $role, 'status' => 'active',
            ], ['id' => 'binaryuuid', 'agent_id' => 'binaryuuid']);
        }
        $this->configRequest(['environment' => ['REMOTE_ADDR' => self::IP]]);
    }

    private function setUser(string $id, array $values): void
    {
        $this->db->update('agent_users', $values, ['id' => $id], ['id' => 'binaryuuid']);
    }

    private function trustCurrentIp(string $id): void
    {
        $this->db->insert('last_otp_ips', [
            'agent_user_id' => $id, 'ip' => self::IP, 'created' => new DateTime(), 'modified' => new DateTime(),
        ], ['agent_user_id' => 'binaryuuid', 'created' => 'datetime', 'modified' => 'datetime']);
    }

    private function loginPost(string $email = 'master.a@example.com'): void
    {
        $this->enableCsrfToken();
        $this->post('/agent-users/login', ['email' => $email, 'password' => self::PASSWORD]);
    }

    private function row(string $id): array
    {
        return $this->db->execute(
            'SELECT otp, totp_secret, totp_enabled, totp_last_step, backup_codes FROM agent_users WHERE id = UNHEX(REPLACE(?, \'-\', \'\'))',
            [$id]
        )->fetch('assoc');
    }

    private function user(string $id)
    {
        return $this->getTableLocator()->get('AgentUsers')->get($id, contain: ['Agents']);
    }

    /**
     * Links an authenticator for the user; returns [secret].
     */
    private function linkAuthenticator(string $id): array
    {
        $secret = TwoFactor::newSecret();
        TwoFactor::enable($this->user($id), $secret, 1);

        return [$secret];
    }

    private function appCode(string $secret): string
    {
        return (new TwoFactorAuth(new BaconQrCodeProvider()))->getCode($secret);
    }

    private function postCode(string $code, array $session = ['agent_id' => self::MASTER_A]): void
    {
        $this->session($session);
        $this->enableCsrfToken();
        $this->post('/agent-users/otp', ['otp' => $code]);
    }

    public function testNoCodeWhenAgentOtpIsOff(): void
    {
        $this->db->update('agents', ['mobile_otp' => 0], ['id' => self::AGENT_A], ['id' => 'binaryuuid']);
        $this->loginPost();

        $this->assertRedirectContains('city_id');
        $this->assertSession(self::MASTER_A, 'Auth.User.id');
        $this->assertNoMailSent();
    }

    public function testNoCodeWhenUserSwitchIsOff(): void
    {
        $this->setUser(self::MASTER_A, ['two_factor_enabled' => 0]);
        $this->loginPost();

        $this->assertSession(self::MASTER_A, 'Auth.User.id');
        $this->assertNoMailSent();
    }

    public function testEmailMethodKeepsTrustedIpSkip(): void
    {
        $this->setUser(self::MASTER_A, ['two_factor_method' => 'email_otp']);
        $this->trustCurrentIp(self::MASTER_A);
        $this->loginPost();

        $this->assertSession(self::MASTER_A, 'Auth.User.id');
        $this->assertNoMailSent();
    }

    public function testEmailMethodOnNewIpSendsCode(): void
    {
        $this->setUser(self::MASTER_A, ['two_factor_method' => 'email_otp']);
        $this->loginPost();

        $this->assertRedirectContains('/agent-users/otp');
        $this->assertSession(null, 'Auth.User');
        $this->assertMailSentTo('master.a@example.com');
    }

    public function testAuthenticatorAsksAppCodeEvenOnTrustedIp(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $this->trustCurrentIp(self::MASTER_A);
        $this->loginPost();

        $this->assertRedirectContains('/agent-users/otp');
        $this->assertSession(null, 'Auth.User');
        $this->assertNoMailSent();
    }

    public function testAppCodeLogsInOnce(): void
    {
        [$secret] = $this->linkAuthenticator(self::MASTER_A);
        $code = $this->appCode($secret);

        $this->postCode($code);
        $this->assertRedirectContains('city_id');
        $this->assertSession(self::MASTER_A, 'Auth.User.id');
        $this->assertSession(null, 'Auth.User.totp_secret');

        $this->postCode($code);
        $this->assertSession(null, 'Auth.User');
        $this->assertFlashMessage('Incorrect code. Please try again.');
    }

    public function testWrongAppCodeCountsAttempt(): void
    {
        $this->linkAuthenticator(self::MASTER_A);

        $this->postCode('000000');
        $this->assertSession(null, 'Auth.User');
        $this->assertSession(1, 'otp_attempts');
    }

    // ---- account-wide limits (survive new logins, sessions and IPs) ----

    private function countLogins(string $loc, string $email = 'master.a@example.com'): int
    {
        return (int)$this->db->execute('SELECT COUNT(*) AS n FROM logins WHERE loc = ? AND email = ?', [$loc, $email])->fetch('assoc')['n'];
    }

    private const DISABLED_MESSAGE = 'Too many incorrect codes. Your account has been disabled for security. Please contact your master account or administrator.';

    private function userStatus(string $id): string
    {
        return $this->db->execute('SELECT status FROM agent_users WHERE id = UNHEX(REPLACE(?, \'-\', \'\'))', [$id])->fetch('assoc')['status'];
    }

    public function testWrongCodesAcrossLoginsDeactivateTheUser(): void
    {
        Configure::write('Login.code_max_failures', 4);
        Configure::write('Login.deactivation_notify_emails', ['ops@example.com']);
        $this->linkAuthenticator(self::NORMAL_A);
        $this->db->insert('agent_sessions', ['id' => 'sess-normal-a', 'data' => '', 'expires' => time() + 3600, 'agent_user_id' => self::NORMAL_A]);
        $pending = ['agent_id' => self::NORMAL_A];

        // Each postCode() starts from a fresh session, like logging in again with the password:
        // the per-login counter resets, the account-wide one doesn't.
        for ($i = 1; $i <= 2; $i++) {
            $this->postCode('000000', $pending);
            $this->assertFlashMessage('Incorrect code. Please try again.');
        }
        // From the 3rd wrong code the message warns before the account is disabled.
        $this->postCode('000000', $pending);
        $this->assertFlashMessage('Incorrect code. Please try again. Warning: your account will be deactivated after 1 more incorrect code.');
        $this->assertSame('active', $this->userStatus(self::NORMAL_A));
        $this->assertNoMailSent();

        $this->postCode('000000', $pending);
        $this->assertRedirectContains('/agent-users/login');
        $this->assertFlashMessage(self::DISABLED_MESSAGE);
        $this->assertSame('inactive', $this->userStatus(self::NORMAL_A));
        $this->assertSame(0, (int)$this->db->execute("SELECT COUNT(*) AS n FROM agent_sessions WHERE agent_user_id = ?", [self::NORMAL_A])->fetch('assoc')['n'], 'logged out everywhere');
        // The admins and the agent's master, not the user.
        $this->assertMailSentTo('admin@example.com');
        $this->assertMailSentTo('ops@example.com');
        $this->assertMailSentTo('master.a@example.com');
        $this->assertMailSubjectContains('Agent user disabled after too many incorrect sign-in codes');
        $this->assertMailContains('normal.a@example.com');

        // A pending login of the disabled user can't continue...
        $this->postCode('123456', $pending);
        $this->assertRedirectContains('/agent-users/login');
        $this->assertSession(null, 'Auth.User');

        // ...and a correct password is refused like any inactive account.
        $this->loginPost('normal.a@example.com');
        $this->assertFlashMessage('Wrong login information.');
        $this->assertSession(null, 'Auth.User');
    }

    public function testDeactivatedMasterNotifiesOnlyTheList(): void
    {
        Configure::write('Login.code_max_failures', 1);
        Configure::write('Login.deactivation_notify_emails', ['ops@example.com']);
        $this->linkAuthenticator(self::MASTER_A);

        $this->postCode('000000');

        $this->assertSame('inactive', $this->userStatus(self::MASTER_A));
        $this->assertMailCount(1);
        $this->assertMailSentTo('admin@example.com');
        $this->assertMailSentTo('ops@example.com');
        $this->assertFlashMessage(self::DISABLED_MESSAGE);
    }

    public function testFiveWrongCodesInOneLoginDeactivateTheUser(): void
    {
        $this->linkAuthenticator(self::NORMAL_A);
        $this->session(['agent_id' => self::NORMAL_A]);

        $messages = [
            1 => 'Incorrect code. Please try again.',
            2 => 'Incorrect code. Please try again.',
            3 => 'Incorrect code. Please try again. Warning: your account will be deactivated after 2 more incorrect codes.',
            4 => 'Incorrect code. Please try again. Warning: your account will be deactivated after 1 more incorrect code.',
        ];
        foreach ($messages as $i => $message) {
            $this->enableCsrfToken();
            $this->post('/agent-users/otp', ['otp' => '000000']);
            $this->assertFlashMessage($message, 'flash', "wrong code $i");
            $this->assertSame('active', $this->userStatus(self::NORMAL_A));
            // Carry the pending login (and its per-login count) to the next request.
            $this->session(['agent_id' => self::NORMAL_A, 'otp_attempts' => $i]);
        }

        $this->enableCsrfToken();
        $this->post('/agent-users/otp', ['otp' => '000000']);
        $this->assertFlashMessage(self::DISABLED_MESSAGE);
        $this->assertSame('inactive', $this->userStatus(self::NORMAL_A));
        // Admins always get the email (Login.deactivation_notify_emails is empty here), plus the master.
        $this->assertMailSentTo('admin@example.com');
        $this->assertMailSentTo('master.a@example.com');
        // Cleared on disable: status inactive is the lock, and an enable from the back office starts afresh.
        $this->assertSame(0, $this->countLogins('agent_code', 'normal.a@example.com'));
    }

    public function testBackOfficeEnableGivesAFreshCount(): void
    {
        Configure::write('Login.code_max_failures', 2);
        [$secret] = $this->linkAuthenticator(self::NORMAL_A);
        $this->postCode('000000', ['agent_id' => self::NORMAL_A]);
        $this->postCode('000000', ['agent_id' => self::NORMAL_A]);
        $this->assertSame('inactive', $this->userStatus(self::NORMAL_A));

        // tdpadmin only flips the status.
        $this->setUser(self::NORMAL_A, ['status' => 'active']);

        $this->loginPost('normal.a@example.com');
        $this->assertRedirectContains('/agent-users/otp');
        $this->postCode('000000', ['agent_id' => self::NORMAL_A]);
        $this->assertFlashMessage('Incorrect code. Please try again.');
        $this->postCode($this->appCode($secret), ['agent_id' => self::NORMAL_A]);
        $this->assertSession(self::NORMAL_A, 'Auth.User.id');
    }

    public function testDisabledUserCannotRequestAPasswordReset(): void
    {
        $this->setUser(self::NORMAL_A, ['status' => 'inactive']);
        $this->enableCsrfToken();
        $this->post('/agent-users/forgot-password', ['email' => 'normal.a@example.com']);

        // Same message as for any address, but nothing is sent or stored.
        $this->assertFlashMessage('You should receive an email to reset your password. Please check your email and click the link provided within 24 hours.');
        $this->assertNoMailSent();
        $this->assertSame(0, (int)$this->db->execute("SELECT COUNT(*) AS n FROM password_resets WHERE email = 'normal.a@example.com'")->fetch('assoc')['n']);
    }

    public function testDisabledUserCannotUseAnEarlierResetLink(): void
    {
        $this->db->insert('password_resets', [
            'email' => 'normal.a@example.com', 'reset_code' => 'abc123', 'type' => 'agent', 'created' => new DateTime(),
        ], ['created' => 'datetime']);
        $this->setUser(self::NORMAL_A, ['status' => 'inactive']);

        $this->enableCsrfToken();
        $this->post('/agent-users/reset-password/normal.a@example.com/abc123', ['password' => 'New#Pass12345', 'confirm_password' => 'New#Pass12345']);

        $this->assertRedirectContains('/agent-users/login');
        $this->assertFlashMessage('Password reset link not found or expired.');
        $this->assertSame(0, (int)$this->db->execute("SELECT COUNT(*) AS n FROM password_resets WHERE email = 'normal.a@example.com'")->fetch('assoc')['n']);
        $hash = $this->db->execute('SELECT password FROM agent_users WHERE id = UNHEX(REPLACE(?, \'-\', \'\'))', [self::NORMAL_A])->fetch('assoc')['password'];
        $this->assertTrue((new DefaultPasswordHasher())->check(self::PASSWORD, $hash), 'password unchanged');
    }

    public function testFailuresOlderThanTheWindowDontCount(): void
    {
        Configure::write('Login.code_max_failures', 3);
        Configure::write('Login.code_failure_minutes', 60);
        $this->linkAuthenticator(self::NORMAL_A);
        $old = new DateTime('-61 minutes');
        foreach ([1, 2] as $n) {
            $this->db->insert('logins', ['ip' => self::IP, 'email' => 'normal.a@example.com', 'loc' => 'agent_code', 'created' => $old], ['created' => 'datetime']);
        }

        $this->postCode('000000', ['agent_id' => self::NORMAL_A]);

        $this->assertFlashMessage('Incorrect code. Please try again.');
        $this->assertSame('active', $this->userStatus(self::NORMAL_A));
    }

    public function testMasterEnableClearsTheWrongCodeCount(): void
    {
        Configure::write('Login.code_max_failures', 2);
        $this->linkAuthenticator(self::NORMAL_A);
        $this->postCode('000000', ['agent_id' => self::NORMAL_A]);
        $this->postCode('000000', ['agent_id' => self::NORMAL_A]);
        $this->assertSame('inactive', $this->userStatus(self::NORMAL_A));

        $this->session(['Auth' => ['User' => [
            'id' => self::MASTER_A, 'agent_id' => self::AGENT_A, 'role' => 'master', 'email' => 'master.a@example.com', 'name' => 'Test',
            'credits' => '0.00',
            'agent' => ['mobile_otp' => true, 'low_credit_limit' => '0.00', 'first_name' => 'T', 'last_name' => 'A'],
        ]]]);
        $this->enableCsrfToken();
        $this->post('/agent-users/activate/' . self::NORMAL_A);

        $this->assertSame('active', $this->userStatus(self::NORMAL_A));
        $this->assertSame(0, $this->countLogins('agent_code', 'normal.a@example.com'));
    }

    public function testCorrectPasswordDoesNotResetTheCounters(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $this->db->insert('logins', ['ip' => self::IP, 'email' => 'master.a@example.com', 'loc' => 'agent', 'created' => new DateTime()], ['created' => 'datetime']);
        $this->db->insert('logins', ['ip' => self::IP, 'email' => 'master.a@example.com', 'loc' => 'agent_code', 'created' => new DateTime()], ['created' => 'datetime']);

        $this->loginPost();

        $this->assertRedirectContains('/agent-users/otp');
        $this->assertSame(2, $this->countLogins('agent'), 'earlier attempt + this one');
        $this->assertSame(1, $this->countLogins('agent_code'));
    }

    public function testCompleteLoginClearsTheCounters(): void
    {
        [$secret] = $this->linkAuthenticator(self::MASTER_A);
        $this->db->insert('logins', ['ip' => self::IP, 'email' => 'master.a@example.com', 'loc' => 'agent', 'created' => new DateTime()], ['created' => 'datetime']);
        $this->db->insert('logins', ['ip' => '10.9.9.9', 'email' => 'master.a@example.com', 'loc' => 'agent_code', 'created' => new DateTime()], ['created' => 'datetime']);
        $this->db->insert('logins', ['ip' => self::IP, 'email' => 'normal.a@example.com', 'loc' => 'agent', 'created' => new DateTime()], ['created' => 'datetime']);

        $this->postCode($this->appCode($secret));

        $this->assertSession(self::MASTER_A, 'Auth.User.id');
        $this->assertSame(0, $this->countLogins('agent'));
        $this->assertSame(0, $this->countLogins('agent_code'));
        $this->assertSame(1, $this->countLogins('agent', 'normal.a@example.com'), 'other users from the same IP still count');
    }

    public function testRightCodeIsNotCountedAsFailure(): void
    {
        [$secret] = $this->linkAuthenticator(self::MASTER_A);
        $this->postCode('000000');
        $this->assertSame(1, $this->countLogins('agent_code'));

        $this->postCode($this->appCode($secret));
        $this->assertSession(self::MASTER_A, 'Auth.User.id');
        // Cleared by the complete login; the right code itself never left a row.
        $this->assertSame(0, $this->countLogins('agent_code'));
    }

    public function testCodeEmailsAreCappedPerAccount(): void
    {
        Configure::write('Login.otp_mail_max', 1);
        $this->setUser(self::MASTER_A, ['two_factor_method' => 'email_otp']);

        $this->loginPost();
        $this->assertRedirectContains('/agent-users/otp');
        $this->assertMailSentTo('master.a@example.com');

        $this->cleanupEmailTrait();
        $this->loginPost();
        $this->assertRedirectContains('/agent-users/login');
        $this->assertFlashMessage('Too many codes have been sent to your email. Please try again in 15 minutes.');
        $this->assertNoMailSent();
    }

    public function testBackupCodesAreNotAccepted(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        // A user who still has backup codes from before they were removed can't use them.
        $this->db->update('agent_users', ['backup_codes' => json_encode([password_hash('ABCD2345', PASSWORD_DEFAULT)])], ['id' => self::MASTER_A], ['id' => 'binaryuuid']);

        $this->postCode('ABCD-2345');
        $this->assertSession(null, 'Auth.User');
        $this->assertSession(1, 'otp_attempts');

        $this->session(['agent_id' => self::MASTER_A]);
        $this->get('/agent-users/otp');
        $this->assertResponseNotContains('backup code');
    }

    public function testOtpPageWithoutPendingLoginGoesToLogin(): void
    {
        $this->get('/agent-users/otp');
        $this->assertRedirectContains('/agent-users/login');

        $this->session(['agent_id' => '00000000-0000-4000-8000-00000000dead']);
        $this->get('/agent-users/otp');
        $this->assertRedirectContains('/agent-users/login');
    }

    public function testOtpPageShowsForPendingLogin(): void
    {
        $this->session(['agent_id' => self::MASTER_A]);
        $this->get('/agent-users/otp');

        $this->assertResponseOk();
    }

    public function testResendOtpRefusedForAuthenticatorUsers(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $this->session(['agent_id' => self::MASTER_A]);
        $this->enableCsrfToken();
        $this->post('/agent-users/resend-otp');

        $this->assertNoMailSent();
        $this->assertNull($this->row(self::MASTER_A)['otp']);
    }

    public function testFirstLoginEmailCodeThenSetupLogsIn(): void
    {
        $this->loginPost();
        $this->assertRedirectContains('/agent-users/otp');
        $this->assertMailSentTo('master.a@example.com');
        $otp = (string)$this->row(self::MASTER_A)['otp'];

        $this->postCode($otp);
        $this->assertRedirectContains('/agent-users/two-factor/setup');
        $this->assertSession(null, 'Auth.User');

        $pending = ['agent_id' => self::MASTER_A, 'TwoFactor' => ['setup_pending' => time()]];
        $this->session($pending);
        $this->get('/agent-users/two-factor/setup');
        $this->assertResponseOk();
        $this->assertResponseContains('<svg');
        // Server::run() closes the session; reading it through the Session object would restart (and wipe) it in CLI.
        $secret = Hash::get($_SESSION, 'TwoFactor.setup_secret');
        $this->assertNotEmpty($secret);

        $this->session(['agent_id' => self::MASTER_A, 'TwoFactor' => ['setup_pending' => time(), 'setup_secret' => $secret]]);
        $this->enableCsrfToken();
        $this->post('/agent-users/two-factor/setup', ['code' => $this->appCode($secret)]);
        $row = $this->row(self::MASTER_A);
        $this->assertNotNull($row['totp_enabled']);
        $this->assertNull($row['backup_codes']);
        $this->assertSession(self::MASTER_A, 'Auth.User.id');
        $this->assertSession(null, 'TwoFactor');
    }

    public function testSetupNeedsTheEmailCodeFirst(): void
    {
        $this->session(['agent_id' => self::MASTER_A]);
        $this->get('/agent-users/two-factor/setup');
        $this->assertRedirectContains('/agent-users/login');

        $this->session(['agent_id' => self::MASTER_A, 'TwoFactor' => ['setup_pending' => time() - 3600]]);
        $this->get('/agent-users/two-factor/setup');
        $this->assertRedirectContains('/agent-users/login');
    }

    public function testSetupCannotReplaceALinkedAuthenticatorBeforeLogin(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $before = $this->row(self::MASTER_A)['totp_secret'];

        $this->session(['agent_id' => self::MASTER_A, 'TwoFactor' => ['setup_pending' => time()]]);
        $this->get('/agent-users/two-factor/setup');
        $this->assertRedirectContains('/agent-users/login');
        $this->assertSame($before, $this->row(self::MASTER_A)['totp_secret']);
    }

    private function loginAs(string $userId, string $agentId, string $role): void
    {
        $this->session(['Auth' => ['User' => [
            'id' => $userId, 'agent_id' => $agentId, 'role' => $role, 'email' => 'x@example.com', 'name' => 'Test',
            'credits' => '0.00',
            'agent' => ['mobile_otp' => true, 'low_credit_limit' => '0.00', 'first_name' => 'T', 'last_name' => 'A'],
        ]]]);
    }

    public function testSelfServicePageShowsStatus(): void
    {
        $this->linkAuthenticator(self::NORMAL_A);
        $this->loginAs(self::NORMAL_A, self::AGENT_A, 'normal');
        $this->get('/agent-users/two-factor');

        $this->assertResponseOk();
        $this->assertResponseContains('Authenticator app is set up');
    }

    public function testMasterResetsOwnSubUserOnly(): void
    {
        $this->linkAuthenticator(self::NORMAL_A);
        $this->linkAuthenticator(self::NORMAL_B);
        $this->linkAuthenticator(self::MASTER_A);

        $this->loginAs(self::MASTER_A, self::AGENT_A, 'master');
        $this->enableCsrfToken();
        $this->post('/agent-users/reset-two-factor/' . self::NORMAL_B);
        $this->assertNotNull($this->row(self::NORMAL_B)['totp_secret'], 'another agent\'s user is untouched');

        $this->loginAs(self::NORMAL_A, self::AGENT_A, 'normal');
        $this->enableCsrfToken();
        $this->post('/agent-users/reset-two-factor/' . self::MASTER_A);
        $this->assertNotNull($this->row(self::MASTER_A)['totp_secret'], 'a normal user cannot reset anyone');

        $this->loginAs(self::MASTER_A, self::AGENT_A, 'master');
        $this->enableCsrfToken();
        $this->post('/agent-users/reset-two-factor/' . self::NORMAL_A);
        $row = $this->row(self::NORMAL_A);
        $this->assertNull($row['totp_secret']);
        $this->assertNull($row['backup_codes']);
    }

    /**
     * Turnstile configured with Cloudflare's test keys; siteverify answers $json.
     */
    private function turnstile(array|Throwable $json = ['success' => true, 'action' => 'email-otp']): void
    {
        Configure::write('Turnstile', ['siteKey' => '1x00000000000000000000AA', 'secretKey' => '1x0000000000000000000000000000000AA']);
        $client = $this->createStub(Client::class);
        if ($json instanceof Throwable) {
            $client->method('post')->willThrowException($json);
        } else {
            $client->method('post')->willReturn(new Response(['Content-Type: application/json'], (string)json_encode($json)));
        }
        Turnstile::setClient($client);
    }

    private function postAnotherWay(array $data = ['cf-turnstile-response' => 'token'], array $session = ['agent_id' => self::MASTER_A]): void
    {
        $this->session($session);
        $this->enableCsrfToken();
        $this->post('/agent-users/otp/another-way', $data);
    }

    protected function tearDown(): void
    {
        Turnstile::setClient(null);
        Configure::delete('Turnstile');
        parent::tearDown();
    }

    public function testTryAnotherWayLinkOnlyWithTurnstileKeys(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $this->session(['agent_id' => self::MASTER_A]);
        $this->get('/agent-users/otp');
        $this->assertResponseNotContains('Try another way');

        $this->turnstile();
        $this->session(['agent_id' => self::MASTER_A]);
        $this->get('/agent-users/otp');
        $this->assertResponseContains('href="/agent-users/otp/another-way"');
    }

    public function testAnotherWayPageNeedsPendingAuthenticatorLogin(): void
    {
        $this->turnstile();
        $this->get('/agent-users/otp/another-way');
        $this->assertRedirectContains('/agent-users/login');

        // Email-method user: nothing to fall back from.
        $this->setUser(self::MASTER_A, ['two_factor_method' => 'email_otp']);
        $this->session(['agent_id' => self::MASTER_A]);
        $this->get('/agent-users/otp/another-way');
        $this->assertRedirectContains('/agent-users/otp');
    }

    public function testAnotherWayPageShowsWidget(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $this->turnstile();
        $this->session(['agent_id' => self::MASTER_A]);
        $this->get('/agent-users/otp/another-way');

        $this->assertResponseOk();
        $this->assertResponseContains('class="cf-turnstile');
        $this->assertResponseContains('data-sitekey="1x00000000000000000000AA"');
        $this->assertResponseContains('ma•••@example.com');
        $this->assertResponseContains('challenges.cloudflare.com/turnstile/v0/api.js');
    }

    public function testFailedTurnstileSendsNoCode(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $this->turnstile(['success' => false, 'error-codes' => ['invalid-input-response']]);
        $this->postAnotherWay();

        $this->assertRedirectContains('/agent-users/otp/another-way');
        $this->assertNoMailSent();
        $this->assertNull($this->row(self::MASTER_A)['otp']);
        $this->assertSession(null, 'TwoFactor.email_fallback');
        $this->assertSession(1, 'otp_attempts');
    }

    public function testMissingTokenOrNetworkErrorFailsClosed(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $this->turnstile();
        $this->postAnotherWay([]);
        $this->assertNoMailSent();

        $this->turnstile(new RuntimeException('timeout'));
        $this->postAnotherWay();
        $this->assertNoMailSent();
        $this->assertNull($this->row(self::MASTER_A)['otp']);
    }

    public function testEmailedCodeAfterTurnstileLogsInOnce(): void
    {
        [$secret] = $this->linkAuthenticator(self::MASTER_A);
        $this->turnstile();
        $this->postAnotherWay();

        $this->assertRedirectContains('/agent-users/otp');
        $this->assertMailSentTo('master.a@example.com');
        $this->assertMailContains('without the authenticator app');
        $otp = (string)$this->row(self::MASTER_A)['otp'];
        $this->assertNotSame('', $otp);
        $fallback = ['agent_id' => self::MASTER_A, 'TwoFactor' => ['email_fallback' => time()]];

        // The OTP page now asks for the emailed code, and an app code is not accepted.
        $this->session($fallback);
        $this->get('/agent-users/otp');
        $this->assertResponseContains('sent to your email');
        $this->assertResponseContains('Use my authenticator app instead');
        $this->postCode($this->appCode($secret), $fallback);
        $this->assertSession(null, 'Auth.User');

        $this->postCode($otp, $fallback);
        $this->assertRedirectContains('city_id');
        $this->assertSession(self::MASTER_A, 'Auth.User.id');
        $this->assertNull($this->row(self::MASTER_A)['otp']);

        $this->postCode($otp, $fallback);
        $this->assertSession(null, 'Auth.User');
    }

    public function testFallbackModeNeedsAnEmailedCode(): void
    {
        // Only otpAnotherWay() sets the flag; without a sent code nothing is accepted.
        $this->linkAuthenticator(self::MASTER_A);
        $this->postCode('123456', ['agent_id' => self::MASTER_A, 'TwoFactor' => ['email_fallback' => time()]]);

        $this->assertSession(null, 'Auth.User');
    }

    public function testCancelReturnsToAppCode(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $this->turnstile();
        $this->postAnotherWay(['do' => 'cancel'], ['agent_id' => self::MASTER_A, 'TwoFactor' => ['email_fallback' => time()]]);

        $this->assertRedirectContains('/agent-users/otp');
        $this->assertSession(null, 'TwoFactor.email_fallback');
    }

    public function testOneSendPerLoginThenResendIsLimited(): void
    {
        $this->linkAuthenticator(self::MASTER_A);
        $this->turnstile();
        $fallback = ['agent_id' => self::MASTER_A, 'TwoFactor' => ['email_fallback' => time()]];

        $this->postAnotherWay(['cf-turnstile-response' => 'token'], $fallback);
        $this->assertNoMailSent();

        $this->session($fallback);
        $this->enableCsrfToken();
        $this->post('/agent-users/resend-otp');
        $this->assertMailSentTo('master.a@example.com');
        $this->assertNotNull($this->row(self::MASTER_A)['otp']);

        $this->cleanupEmailTrait();
        $this->session($fallback + ['otp_resends' => 3]);
        $this->enableCsrfToken();
        $this->post('/agent-users/resend-otp');
        $this->assertNoMailSent();
    }
}
