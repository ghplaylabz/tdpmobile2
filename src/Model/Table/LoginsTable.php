<?php
namespace App\Model\Table;

use App\Util\ClientIp;
use Cake\ORM\Table;
use Cake\Core\Configure;
use Cake\I18n\DateTime;
use Cake\ORM\RulesChecker;
use Cake\Validation\Validator;

/**
 * Logins Model
 *
 * @method \App\Model\Entity\Login get($primaryKey, $options = [])
 * @method \App\Model\Entity\Login newEntity($data = null, array $options = [])
 * @method \App\Model\Entity\Login[] newEntities(array $data, array $options = [])
 * @method \App\Model\Entity\Login|false save(\Cake\Datasource\EntityInterface $entity, $options = [])
 * @method \App\Model\Entity\Login saveOrFail(\Cake\Datasource\EntityInterface $entity, $options = [])
 * @method \App\Model\Entity\Login patchEntity(\Cake\Datasource\EntityInterface $entity, array $data, array $options = [])
 * @method \App\Model\Entity\Login[] patchEntities($entities, array $data, array $options = [])
 * @method \App\Model\Entity\Login findOrCreate($search, callable $callback = null, $options = [])
 *
 * @mixin \Cake\ORM\Behavior\TimestampBehavior
 */
class LoginsTable extends Table
{
    /**
     * Initialize method
     *
     * @param array $config The configuration for the Table.
     * @return void
     */
    public function initialize(array $config): void
    {
        parent::initialize($config);

        $this->setTable('logins');
        $this->setDisplayField('id');
        $this->setPrimaryKey('id');

        $this->addBehavior('Timestamp');
    }

    /**
     * Default validation rules.
     *
     * @param \Cake\Validation\Validator $validator Validator instance.
     * @return \Cake\Validation\Validator
     */
    public function validationDefault(Validator $validator): \Cake\Validation\Validator
    {
        $validator
            ->integer('id')
            ->allowEmptyString('id', null, 'create');

        $validator
            ->scalar('ip')
            ->maxLength('ip', 64)
            ->requirePresence('ip', 'create')
            ->notEmptyString('ip');

        $validator
            ->email('email')
            ->requirePresence('email', 'create')
            ->notEmptyString('email');

        $validator
            ->scalar('system')
            ->allowEmptyString('system');

        return $validator;
    }

    /**
     * Returns a rules checker object that will be used for validating
     * application integrity.
     *
     * @param \Cake\ORM\RulesChecker $rules The rules object to be modified.
     * @return \Cake\ORM\RulesChecker
     */
    public function buildRules(RulesChecker $rules): \Cake\ORM\RulesChecker
    {
        // $rules->add($rules->isUnique(['email','ip', 'system']));

        return $rules;
    }

    /**
     * `loc` values of the agent portal. The table is shared with tdpadmin (admin, admin_code, ...),
     * so every query here is scoped by loc.
     */
    public const LOC_AGENT = 'agent';
    public const LOC_AGENT_CODE = 'agent_code';
    public const LOC_AGENT_OTP_MAIL = 'agent_otp_mail';

    /**
     * Whether a password attempt is allowed, and records it when it is. Refused when the IP + email reached
     * Login.max_count_per_max_minutes within Login.max_minutes, or the email (from any IP) reached
     * Login.account_max_count within Login.account_max_minutes.
     *
     * @param \Cake\Http\ServerRequest $request Request
     * @return bool
     */
    public function isAllowed($request): bool
    {
        $maxMinutes = (int)Configure::read('Login.max_minutes', 3);
        $accountMinutes = (int)Configure::read('Login.account_max_minutes', 30);

        // Prune only our own rows, each past its window (other locs belong to other systems).
        $now = DateTime::now();
        $this->deleteAll(['loc' => self::LOC_AGENT, 'created <' => $now->subMinutes(max($maxMinutes, $accountMinutes))]);
        // Wrong codes have no window by default: they count until a complete sign-in (or the disable).
        $codeMinutes = self::codeFailureMinutes();
        if ($codeMinutes !== null) {
            $this->deleteAll(['loc' => self::LOC_AGENT_CODE, 'created <' => $now->subMinutes($codeMinutes)]);
        }
        $this->deleteAll(['loc' => self::LOC_AGENT_OTP_MAIL, 'created <' => $now->subMinutes((int)Configure::read('Login.otp_mail_minutes', 15))]);

        $clientIp = ClientIp::fromRequest($request);
        // (string): logins.email is NOT NULL, and where(['col' => null]) throws.
        // Cut to the column length so counting matches what record() stores.
        $raw = $request->getData('email');
        $email = mb_substr(is_scalar($raw) ? (string)$raw : '', 0, 100);

        $ipCount = $this->countSince(['ip' => $clientIp, 'email' => $email, 'loc' => self::LOC_AGENT], $maxMinutes);
        $accountCount = $this->countSince(['email' => $email, 'loc' => self::LOC_AGENT], $accountMinutes);
        $allowed = $ipCount < (int)Configure::read('Login.max_count_per_max_minutes', 5)
            && $accountCount < (int)Configure::read('Login.account_max_count', 20);
        if ($allowed) {
            $this->record($email, $clientIp, self::LOC_AGENT);
        }

        return $allowed;
    }

    /**
     * Clears the user's password attempts from this IP. Only after a complete login (second factor
     * included): clearing on a correct password would reset the limits for whoever has the password.
     *
     * @param \Cake\Http\ServerRequest $request Request
     * @param string $email Agent user email
     * @return void
     */
    public function clearLogin($request, string $email): void
    {
        $this->deleteAll(['ip' => ClientIp::fromRequest($request), 'email' => $email, 'loc' => self::LOC_AGENT]);
    }

    /**
     * Reserves one sign-in code attempt (app code, emailed code, set-up code) before the code is checked.
     *
     * The row is written first and then counted, so parallel requests can't all pass a "count < limit"
     * check. Release it with releaseCodeAttempt() when the code was right; a wrong code keeps it.
     *
     * @param string $email Agent user email
     * @param string $ip Client IP
     * @return array{id: int, count: int}|null Null when the account is locked (nothing is kept)
     */
    public function reserveCodeAttempt(string $email, string $ip): ?array
    {
        $id = $this->record($email, $ip, self::LOC_AGENT_CODE);
        $count = $this->codeFailures($email);
        if ($count > self::codeMaxFailures()) {
            $this->deleteAll(['id' => $id]);

            return null;
        }

        return ['id' => $id, 'count' => $count];
    }

    /**
     * Whether a wrong code on this reserved attempt locks the account (it reached the limit).
     *
     * @param array{id: int, count: int} $attempt From reserveCodeAttempt()
     * @return bool
     */
    public function isLockingAttempt(array $attempt): bool
    {
        return $attempt['count'] === self::codeMaxFailures();
    }

    /**
     * Removes a reserved attempt whose code was right (only wrong codes count).
     *
     * @param array{id: int, count: int} $attempt From reserveCodeAttempt()
     * @return void
     */
    public function releaseCodeAttempt(array $attempt): void
    {
        $this->deleteAll(['id' => $attempt['id'], 'loc' => self::LOC_AGENT_CODE]);
    }

    /**
     * Whether the user's sign-in is locked: Login.code_max_failures wrong codes since the last complete
     * sign-in (or within Login.code_failure_minutes when set), counted from any IP and across logins.
     *
     * @param string $email Agent user email
     * @return bool
     */
    public function isCodeLocked(string $email): bool
    {
        return $this->codeFailures($email) >= self::codeMaxFailures();
    }

    /**
     * Wrong sign-in codes that disable the agent user (Login.code_max_failures, default 5).
     *
     * @return int
     */
    public static function codeMaxFailures(): int
    {
        return (int)Configure::read('Login.code_max_failures', 5);
    }

    /**
     * Clears the user's wrong-code count after a complete login.
     *
     * @param string $email Agent user email
     * @return void
     */
    public function clearCodeFailures(string $email): void
    {
        $this->deleteAll(['email' => $email, 'loc' => self::LOC_AGENT_CODE]);
    }

    /**
     * Claims one sign-in code email: at most Login.otp_mail_max within Login.otp_mail_minutes per user
     * (every password login sends one). Written first, then counted, like reserveCodeAttempt().
     *
     * @param string $email Agent user email
     * @param string $ip Client IP
     * @return bool False when the limit is reached (don't send)
     */
    public function claimOtpMail(string $email, string $ip): bool
    {
        $id = $this->record($email, $ip, self::LOC_AGENT_OTP_MAIL);
        $sent = $this->countSince(['email' => $email, 'loc' => self::LOC_AGENT_OTP_MAIL], (int)Configure::read('Login.otp_mail_minutes', 15));
        if ($sent > (int)Configure::read('Login.otp_mail_max', 5)) {
            $this->deleteAll(['id' => $id]);

            return false;
        }

        return true;
    }

    /**
     * @param string $email Agent user email
     * @return int
     */
    private function codeFailures(string $email): int
    {
        return $this->countSince(['email' => $email, 'loc' => self::LOC_AGENT_CODE], self::codeFailureMinutes());
    }

    /**
     * Optional window (minutes) in which Login.code_max_failures wrong codes deactivate the user:
     * Login.code_failure_minutes, or the older Login.code_lock_minutes. Null (the default): no window,
     * wrong codes count until a complete sign-in.
     *
     * @return int|null
     */
    public static function codeFailureMinutes(): ?int
    {
        $minutes = Configure::read('Login.code_failure_minutes') ?? Configure::read('Login.code_lock_minutes');

        return $minutes === null ? null : (int)$minutes;
    }

    /**
     * @param array<string, mixed> $conditions Conditions
     * @param int|null $minutes Window, null for all rows
     * @return int
     */
    private function countSince(array $conditions, ?int $minutes): int
    {
        if ($minutes !== null) {
            $conditions['created >='] = DateTime::now()->subMinutes($minutes);
        }

        return $this->find()->where($conditions)->count();
    }

    /**
     * @param string $email Email
     * @param string $ip Client IP
     * @param string $loc Row type
     * @return int New row id
     */
    private function record(string $email, string $ip, string $loc): int
    {
        // No validation: these are our own counters, and a malformed email typed at login must still be
        // counted (the validator would reject it and the attempt would go unlimited).
        $login = $this->newEntity(['ip' => mb_substr($ip, 0, 64), 'email' => mb_substr($email, 0, 100), 'loc' => $loc], ['validate' => false]);
        $this->saveOrFail($login);

        return (int)$login->id;
    }
}
