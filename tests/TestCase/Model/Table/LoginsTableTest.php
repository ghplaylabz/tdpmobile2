<?php
declare(strict_types=1);

namespace App\Test\TestCase\Model\Table;

use App\Model\Table\LoginsTable;
use App\Test\TestCase\Support\AppDataTrait;
use Cake\Core\Configure;
use Cake\Http\ServerRequest;
use Cake\I18n\DateTime;
use Cake\TestSuite\TestCase;
use PHPUnit\Framework\Attributes\DataProvider;

/**
 * Login rate limiting: at most Login.max_count_per_max_minutes (5) attempts per IP + email
 * within Login.max_minutes (3). Chronos test-now is fixed in tests/bootstrap.php.
 */
class LoginsTableTest extends TestCase
{
    use AppDataTrait;
    use ValidationTestTrait;

    protected array $fixtures = ['app.Logins', 'app.Agents'];

    private LoginsTable $Logins;

    protected function setUp(): void
    {
        parent::setUp();
        $this->Logins = $this->getTableLocator()->get('Logins');
    }

    protected function validData(): array
    {
        return ['ip' => '10.0.0.1', 'email' => 'jane@example.com'];
    }

    public static function validationProvider(): array
    {
        return [
            'valid' => [[], []],
            'missing ip' => [['ip' => self::UNSET], ['ip' => ['_required']]],
            'long ip' => [['ip' => str_repeat('1', 65)], ['ip' => ['maxLength']]],
            'missing email' => [['email' => self::UNSET], ['email' => ['_required']]],
            'invalid email' => [['email' => 'nope'], ['email' => ['email']]],
        ];
    }

    #[DataProvider('validationProvider')]
    public function testValidation(array $changes, array $expected): void
    {
        $this->assertValidation($this->Logins, $changes, $expected);
    }

    private function request(string $email, string $remoteAddr = '10.0.0.1', ?string $cfIp = null): ServerRequest
    {
        $env = ['REQUEST_METHOD' => 'POST', 'REMOTE_ADDR' => $remoteAddr];
        if ($cfIp !== null) {
            $env['HTTP_CF_CONNECTING_IP'] = $cfIp;
        }

        return new ServerRequest(['environment' => $env, 'post' => ['email' => $email]]);
    }

    public function testAllowsUpToTheLimitThenBlocks(): void
    {
        $request = $this->request('jane@example.com');
        for ($i = 1; $i <= 5; $i++) {
            $this->assertTrue($this->Logins->isAllowed($request), "attempt $i");
        }
        $this->assertFalse($this->Logins->isAllowed($request));
        // A blocked attempt isn't recorded.
        $this->assertSame(5, $this->countRows('logins', "ip = '10.0.0.1' AND email = 'jane@example.com' AND loc = 'agent'"));
    }

    public function testCountsPerIpAndEmail(): void
    {
        for ($i = 1; $i <= 5; $i++) {
            $this->Logins->isAllowed($this->request('jane@example.com'));
        }

        $this->assertFalse($this->Logins->isAllowed($this->request('jane@example.com')));
        $this->assertTrue($this->Logins->isAllowed($this->request('john@example.com')));
        $this->assertTrue($this->Logins->isAllowed($this->request('jane@example.com', '10.0.0.2')));
    }

    public function testAttemptsOutsideTheIpWindowDontCountForTheIpLimit(): void
    {
        $old = DateTime::now()->subMinutes(Configure::read('Login.max_minutes') + 1);
        for ($i = 0; $i < 5; $i++) {
            $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'jane@example.com', 'loc' => 'agent', 'created' => $old]);
        }

        $this->assertTrue($this->Logins->isAllowed($this->request('jane@example.com')));
        // Still kept: they count for the account limit (Login.account_max_minutes).
        $this->assertSame(6, $this->countRows('logins'));
    }

    public function testOldAttemptsArePurged(): void
    {
        $old = DateTime::now()->subMinutes(Configure::read('Login.account_max_minutes') + 1);
        foreach (['agent', 'agent_code', 'agent_otp_mail'] as $loc) {
            $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'jane@example.com', 'loc' => $loc, 'created' => $old]);
        }

        $this->assertTrue($this->Logins->isAllowed($this->request('jane@example.com')));
        // Wrong codes have no window by default: kept until a complete sign-in.
        $this->assertSame(2, $this->countRows('logins'));
        $this->assertSame(1, $this->countRows('logins', "loc = 'agent_code'"));
    }

    public function testOldCodeFailuresArePurgedWhenAWindowIsSet(): void
    {
        Configure::write('Login.code_failure_minutes', 60);
        $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'jane@example.com', 'loc' => 'agent_code', 'created' => DateTime::now()->subMinutes(61)]);

        $this->Logins->isAllowed($this->request('jane@example.com'));

        $this->assertSame(0, $this->countRows('logins', "loc = 'agent_code'"));
    }

    public function testPurgeLeavesOtherSystemsRowsAlone(): void
    {
        // e.g. tdpadmin's sign-in lock rows, which have their own windows.
        $old = DateTime::now()->subMinutes(Configure::read('Login.account_max_minutes') + 1);
        $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'boss@example.com', 'loc' => 'admin_code', 'created' => $old]);
        $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'boss@example.com', 'loc' => 'admin', 'created' => $old]);

        $this->Logins->isAllowed($this->request('jane@example.com'));

        $this->assertSame(1, $this->countRows('logins', "loc = 'admin_code'"));
        $this->assertSame(1, $this->countRows('logins', "loc = 'admin'"));
    }

    public function testOtherSystemsAttemptsDontCount(): void
    {
        for ($i = 0; $i < 5; $i++) {
            $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'jane@example.com', 'loc' => 'admin', 'created' => DateTime::now()]);
        }

        $this->assertTrue($this->Logins->isAllowed($this->request('jane@example.com')));
    }

    public function testAccountLimitCountsAttemptsFromAnyIp(): void
    {
        Configure::write('Login.account_max_count', 6);
        // 3 IPs x 2 attempts: each IP is under its own limit (5).
        foreach (['10.0.0.1', '10.0.0.2', '10.0.0.3'] as $ip) {
            $this->assertTrue($this->Logins->isAllowed($this->request('jane@example.com', $ip)));
            $this->assertTrue($this->Logins->isAllowed($this->request('jane@example.com', $ip)));
        }

        $this->assertFalse($this->Logins->isAllowed($this->request('jane@example.com', '10.0.0.4')), 'account limit');
        $this->assertTrue($this->Logins->isAllowed($this->request('john@example.com', '10.0.0.4')), 'other accounts unaffected');
    }

    public function testMalformedEmailIsStillCounted(): void
    {
        $request = $this->request('not an email');
        for ($i = 1; $i <= 5; $i++) {
            $this->assertTrue($this->Logins->isAllowed($request), "attempt $i");
        }
        $this->assertFalse($this->Logins->isAllowed($request));
    }

    // ---- wrong sign-in codes (account-wide) ----

    public function testCodeAttemptsLockTheAccountAcrossIps(): void
    {
        Configure::write('Login.code_max_failures', 3);
        $ips = ['10.0.0.1', '10.0.0.2', '10.0.0.3'];
        foreach ($ips as $n => $ip) {
            $attempt = $this->Logins->reserveCodeAttempt('jane@example.com', $ip);
            $this->assertNotNull($attempt, "attempt from $ip");
            $this->assertSame($n + 1, $attempt['count']);
            $this->assertSame($n === 2, $this->Logins->isLockingAttempt($attempt), 'the 3rd wrong code locks');
        }

        $this->assertTrue($this->Logins->isCodeLocked('jane@example.com'));
        $this->assertNull($this->Logins->reserveCodeAttempt('jane@example.com', '10.0.0.9'));
        // A refused attempt isn't kept (doesn't extend the lock).
        $this->assertSame(3, $this->countRows('logins', "loc = 'agent_code'"));
        $this->assertFalse($this->Logins->isCodeLocked('john@example.com'));
    }

    public function testReleasedCodeAttemptDoesntCount(): void
    {
        $attempt = $this->Logins->reserveCodeAttempt('jane@example.com', '10.0.0.1');
        $this->Logins->releaseCodeAttempt($attempt);

        $this->assertSame(0, $this->countRows('logins', "loc = 'agent_code'"));
    }

    public function testDefaultLimitIsFiveWrongCodes(): void
    {
        Configure::delete('Login.code_max_failures');
        for ($i = 1; $i <= 5; $i++) {
            $attempt = $this->Logins->reserveCodeAttempt('jane@example.com', '10.0.0.1');
            $this->assertSame($i === 5, $this->Logins->isLockingAttempt($attempt), "attempt $i");
        }
        $this->assertTrue($this->Logins->isCodeLocked('jane@example.com'));
    }

    public function testCodeFailuresCountUntilClearedWithoutAWindow(): void
    {
        Configure::write('Login.code_max_failures', 3);
        $old = DateTime::now()->subDays(10);
        for ($i = 0; $i < 3; $i++) {
            $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'jane@example.com', 'loc' => 'agent_code', 'created' => $old]);
        }

        $this->assertTrue($this->Logins->isCodeLocked('jane@example.com'));
        $this->assertNull($this->Logins->reserveCodeAttempt('jane@example.com', '10.0.0.1'));
    }

    public function testCodeFailuresExpireAfterTheWindowWhenSet(): void
    {
        Configure::write('Login.code_max_failures', 3);
        Configure::write('Login.code_failure_minutes', 60);
        $old = DateTime::now()->subMinutes(61);
        for ($i = 0; $i < 3; $i++) {
            $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'jane@example.com', 'loc' => 'agent_code', 'created' => $old]);
        }

        $this->assertFalse($this->Logins->isCodeLocked('jane@example.com'));
        $this->assertNotNull($this->Logins->reserveCodeAttempt('jane@example.com', '10.0.0.1'));
    }

    public function testFailureWindowFallsBackToTheOldKey(): void
    {
        Configure::delete('Login.code_failure_minutes');
        Configure::write('Login.code_lock_minutes', 30);
        $this->assertSame(30, LoginsTable::codeFailureMinutes());

        Configure::delete('Login.code_lock_minutes');
        $this->assertNull(LoginsTable::codeFailureMinutes(), 'default: no window');
    }

    public function testClearCodeFailuresUnlocks(): void
    {
        Configure::write('Login.code_max_failures', 1);
        $this->Logins->reserveCodeAttempt('jane@example.com', '10.0.0.1');
        $this->Logins->reserveCodeAttempt('john@example.com', '10.0.0.1');
        $this->assertTrue($this->Logins->isCodeLocked('jane@example.com'));

        $this->Logins->clearCodeFailures('jane@example.com');

        $this->assertFalse($this->Logins->isCodeLocked('jane@example.com'));
        $this->assertTrue($this->Logins->isCodeLocked('john@example.com'));
    }

    public function testOtpMailsAreCappedPerAccount(): void
    {
        for ($i = 1; $i <= 5; $i++) {
            $this->assertTrue($this->Logins->claimOtpMail('jane@example.com', '10.0.0.' . $i), "email $i");
        }

        $this->assertFalse($this->Logins->claimOtpMail('jane@example.com', '10.0.0.9'));
        $this->assertSame(5, $this->countRows('logins', "loc = 'agent_otp_mail'"));
        $this->assertTrue($this->Logins->claimOtpMail('john@example.com', '10.0.0.9'));
    }

    public function testCloudflareHeaderOnlyTrustedFromCloudflare(): void
    {
        // Peer inside a Cloudflare range: the header is the client IP.
        $this->Logins->isAllowed($this->request('jane@example.com', '173.245.48.10', '203.0.113.7'));
        // Any other peer: the header is ignored.
        $this->Logins->isAllowed($this->request('john@example.com', '10.0.0.9', '203.0.113.8'));

        $this->assertSame(1, $this->countRows('logins', "ip = '203.0.113.7' AND email = 'jane@example.com'"));
        $this->assertSame(1, $this->countRows('logins', "ip = '10.0.0.9' AND email = 'john@example.com'"));
        $this->assertSame(0, $this->countRows('logins', "ip = '203.0.113.8'"));
    }

    public function testClearLoginRemovesOnlyThisUsersAttemptsFromTheIp(): void
    {
        $now = DateTime::now();
        $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'jane@example.com', 'loc' => 'agent', 'created' => $now]);
        $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'john@example.com', 'loc' => 'agent', 'created' => $now]);
        $this->insertRow('logins', ['ip' => '10.0.0.1', 'email' => 'jane@example.com', 'loc' => 'admin', 'created' => $now]);
        $this->insertRow('logins', ['ip' => '10.0.0.2', 'email' => 'jane@example.com', 'loc' => 'agent', 'created' => $now]);

        $this->Logins->clearLogin($this->request('jane@example.com'), 'jane@example.com');

        $this->assertSame(0, $this->countRows('logins', "ip = '10.0.0.1' AND email = 'jane@example.com' AND loc = 'agent'"));
        // Another user's attempts from the same IP still count (one success no longer resets the IP).
        $this->assertSame(1, $this->countRows('logins', "email = 'john@example.com'"));
        $this->assertSame(1, $this->countRows('logins', "ip = '10.0.0.1' AND loc = 'admin'"));
        $this->assertSame(1, $this->countRows('logins', "ip = '10.0.0.2'"));
    }
}
