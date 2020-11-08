<?php
declare(strict_types=1);
namespace Oire\Osst;

use DateTimeImmutable;
use DateTimeZone;
use Oire\Base64\Base64;
use Oire\Base64\Exception\Base64Exception;
use Oire\Colloportus\Colloportus;
use Oire\Colloportus\Exception\ColloportusException;
use Oire\Osst\Exception\OsstException;
use Oire\Osst\Exception\OsstInvalidTokenException as TokenError;
use PDO;
use PDOException;
use Throwable;

/**
 * Oirë Simple Split Tokens (OSST)
 * Implements the split token authentication model proposed by Paragon Initiatives.
 * Copyright © 2020 Andre Polykanine also known as Menelion Elensúlë, The Magical Kingdom of Oirë, https://github.com/Oire
 * Idea Copyright © 2017, Paragon Initiatives, https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 */
final class Osst
{
    public const TOKEN_SIZE = 36;
    public const SELECTOR_SIZE = 16;
    public const VERIFIER_SIZE = 20;
    public const TABLE_NAME = 'osst_tokens';
    public const DEFAULT_EXPIRATION_DATE_FORMAT = 'Y-m-d H:i:s';
    public const DEFAULT_EXPIRATION_DATE_OFFSET = '+14 days';
    public const DEFAULT_EXPIRATION_TIME_OFFSET = 1209600;

    private $dbConnection;
    private $token;
    private $selector;
    private $hashedVerifier;
    private $userId;
    private $expirationTime;
    private $tokenType;
    private $additionalInfo;

    /**
     * Instantiate a new Osst object.
     * @param PDO $dbConnection Connection to your database
     */
    public function __construct(PDO $dbConnection)
    {
        $this->dbConnection = $dbConnection;

        try {
            $this->dbConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->dbConnection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            $this->dbConnection->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            $this->dbConnection->setAttribute(PDO::ATTR_STRINGIFY_FETCHES, false);
            $this->dbConnection->setAttribute(PDO::ATTR_CASE, PDO::CASE_NATURAL);
        } catch (PDOException $e) {
            throw TokenError::sqlError($e);
        }
    }

    /**
     * Create a new token.
     * @return $this
     */
    public function createToken(): self
    {
        $rawToken = random_bytes(self::TOKEN_SIZE);
        $this->token = Base64::encode($rawToken);
        $this->selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, '8bit'));
        $this->hashedVerifier = Base64::encode(hash(Colloportus::HASH_FUNCTION, mb_substr($rawToken, self::SELECTOR_SIZE, self::VERIFIER_SIZE, '8bit'), true));

        return $this;
    }

    /**
     * Get the connection to the database.
     * @return PDO Returns the connection to the database as a PDO object
     */
    public function getDbConnection(): PDO
    {
        return $this->dbConnection;
    }

    /**
     * Get the token.
     * @throws OsstException If the token was not set or created beforehand
     * @return string        Returns the token
     */
    public function getToken(): string
    {
        if (empty($this->token)) {
            throw OsstException::tokenNotSet();
        }

        return $this->token;
    }

    /**
     * Set and validate a user-provided token.
     * @param string  $token                       The token provided by the user
     * @param ?string $additionalInfoDecryptionKey If not empty, the previously additional info for the token will be decrypted using Oirë Colloportus
     * @see https://github.com/Oire/Colloportus
     * @throws TokenError
     * @return $this
     */
    public function setToken(string $token, ?string $additionalInfoDecryptionKey = null): self
    {
        try {
            $rawToken = Base64::decode($token);
        } catch (Base64Exception $e) {
            throw TokenError::invalidTokenFormat($e->getMessage(), $e);
        }

        if (mb_strlen($rawToken, '8bit') !== self::TOKEN_SIZE) {
            throw TokenError::invalidTokenLength();
        }

        $selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, '8bit'));

        $sql = sprintf('SELECT user_id, token_type, selector, verifier, additional_info, expiration_time FROM %s WHERE selector = :selector', self::TABLE_NAME);
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            throw TokenError::pdoStatementError($this->dbConnection->errorInfo()[2]);
        }

        try {
            $statement->execute([':selector' => $selector]);
        } catch (PDOException $e) {
            throw TokenError::sqlError($e);
        }

        $result = $statement->fetch();

        if (!$result || count($result) === 0) {
            throw TokenError::selectorError();
        }

        $verifier = Base64::encode(hash(Colloportus::HASH_FUNCTION, mb_substr($rawToken, self::SELECTOR_SIZE, self::VERIFIER_SIZE, '8bit'), true));

        if (!hash_equals($verifier, $result['verifier'])) {
            throw TokenError::verifierError();
        }

        $this->token = $token;
        $this->selector = $selector;
        $this->hashedVerifier = $verifier;
        $this->userId = (int) $result['user_id'];
        $this->expirationTime = (int) $result['expiration_time'];
        $this->tokenType = $result['token_type']? (int) $result['token_type']: null;

        if (!empty($additionalInfoDecryptionKey)) {
            try {
                $this->additionalInfo = Colloportus::decrypt($result['additional_info'], $additionalInfoDecryptionKey);
            } catch (ColloportusException $e) {
                throw OsstException::additionalInfoDecryptionError($e);
            }
        }

        $this->additionalInfo = $result['additional_info'];

        return $this;
    }

    /**
     * Get the ID of the user the token belongs to.
     */
    public function getUserId(): int
    {
        return $this->userId;
    }

    /**
     * Set the ID of the user the token belongs to.
     * @param  int           $userId The ID of the user the token belongs to. Must be a positive integer.
     * @throws OsstException
     * @return $this
     */
    public function setUserId(int $userId): self
    {
        if ($this->userId) {
            throw OsstException::propertyAlreadySet('User ID');
        }

        if ($userId <= 0) {
            throw OsstException::invalidUserId($userId);
        }

        $this->userId = $userId;

        return $this;
    }

    /**
     * Get the expiration time of the token as timestamp.
     */
    public function getExpirationTime(): int
    {
        return $this->expirationTime;
    }

    /**
     * Get the expiration time of the token as a DateTime immutable object.
     * @return DateTimeImmutable Returns the expiration time as a DateTimeImmutable in the default time zone set in PHP settings
     */
    public function getExpirationDate(): DateTimeImmutable
    {
        return         (new DateTimeImmutable(sprintf('@%s', $this->expirationTime)))->setTimezone(new DateTimeZone(date_default_timezone_get()));
    }

    /**
     * Get the expiration time of the token in a given format.
     * @param string $format A valid date format. Defaults to `'Y-m-d H:i:s'`
     * @see https://www.php.net/manual/en/function.date.php
     * @throws OsstException if the date formatting fails
     * @return string        Returns the expiration time as date string in given format
     */
    public function getExpirationDateFormatted(string $format = self::DEFAULT_EXPIRATION_DATE_FORMAT): string
    {
        try {
            return (new DateTimeImmutable(sprintf('@%s', $this->expirationTime)))->setTimezone(new DateTimeZone(date_default_timezone_get()))->format($format);
        } catch (Throwable $e) {
            throw new OsstException(sprintf('Unable to format expiration date: %s.', $e->getMessage()), $e);
        }
    }

    /**
     * Set the expiration time for the token using timestamp.
     * @param  int           $timestamp The timestamp when the token should expire
     * @throws OsstException
     * @return $this
     */
    public function setExpirationTime(int $timestamp): self
    {
        if ($this->expirationTime) {
            throw OsstException::propertyAlreadySet('Expiration time');
        }

        if ($timestamp <= time()) {
            throw OsstException::expirationTimeInPast($timestamp);
        }

        $this->expirationTime = $timestamp;

        return $this;
    }

    /**
     * Set the expiration time for the token using relative time.
     * @param string $offset The time interval the token expires in. The default value is `'+14 days'`. Must be a valid relative date format.
     * @see https://www.php.net/manual/en/datetime.formats.relative.php
     * @throws OsstException
     * @return $this
     */
    public function setExpirationOffset(string $offset = self::DEFAULT_EXPIRATION_DATE_OFFSET): self
    {
        if ($this->expirationTime) {
            throw OsstException::propertyAlreadySet('Expiration time');
        }

        if (empty($offset)) {
            throw OsstException::emptyExpirationOffset();
        }

        try {
            $this->expirationTime = (new DateTimeImmutable())->modify($offset)->getTimestamp();

            if ($this->expirationTime <= time()) {
                throw OsstException::expirationTimeInPast($this->expirationTime);
            }
        } catch (Throwable $e) {
            throw OsstException::invalidExpirationOffset($offset, $e->getMessage(), $e);
        }

        return $this;
    }

    /**
     * Set the expiration time for the token using DateTime immutable object.
     * @param  DateTimeImmutable $expirationDate The date the token should expire at
     * @throws OsstException
     * @return $this
     */
    public function setExpirationDate(DateTimeImmutable $expirationDate): self
    {
        $this->expirationTime = $expirationDate->getTimestamp();

        if ($this->expirationTime <= time()) {
            throw OsstException::expirationTimeInPast($this->expirationTime);
        }

        return $this;
    }

    /**
     * Check if the token is expired.
     * @throws OsstException if the expiration date is empty
     * @return bool          True if the token is expired, false otherwise
     */
    public function isExpired(): bool
    {
        if (empty($this->expirationTime)) {
            throw OsstException::emptyExpirationTime();
        }

        return $this->expirationTime <= time();
    }

    /**
     * Get the token type.
     * @return ?int
     */
    public function getTokenType(): ?int
    {
        return $this->tokenType;
    }

    /**
     * Set the token type.
     * @param  int   $tokenType Set this if you want to categorize your tokens by type. The default value is null
     * @return $this
     */
    public function setTokenType(?int $tokenType): self
    {
        $this->tokenType = $tokenType;

        return $this;
    }

    /**
     * Get the additional info for the token.
     * @return ?string
     */
    public function getAdditionalInfo(): ?string
    {
        return $this->additionalInfo;
    }

    /**
     * Set the additional info for the token.
     * @param ?string $additionalInfo Any additional info you want to convey along with the token, as string
     * @param ?string $encryptionKey  If not empty, the data will be encrypted using Oirë Colloportus
     * @see https://github.com/Oire/Colloportus
     * @return $this
     */
    public function setAdditionalInfo(?string $additionalInfo, ?string $encryptionKey = null): self
    {
        if (!empty($encryptionKey)) {
            try {
                $this->additionalInfo = Colloportus::encrypt($additionalInfo, $encryptionKey);
            } catch (ColloportusException $e) {
                throw OsstException::additionalInfoEncryptionError($e);
            }
        }

        $this->additionalInfo = $additionalInfo;

        return $this;
    }

    /**
     * Store the token in the database.
     * @throws TokenError    If SQL error occurs
     * @throws OsstException if not enough data are provided
     * @return $this
     */
    public function persist(): self
    {
        if (empty($this->token)) {
            throw OsstException::tokenNotSet();
        }

        if ($this->userId <= 0) {
            throw OsstException::invalidUserId($this->userId);
        }

        if (empty($this->expirationTime)) {
            throw OsstException::emptyExpirationTime();
        }

        $sql = sprintf('INSERT INTO %s (user_id, token_type, selector, verifier, additional_info, expiration_time) VALUES (:userid, :tokentype, :selector, :verifier, :additional, :expires)', self::TABLE_NAME);
        $statement = $this->dbConnection->prepare($sql);

        if (!$statement) {
            throw TokenError::pdoStatementError($this->dbConnection->errorInfo()[2]);
        }

        try {
            $statement->execute([
                ':userid' => $this->userId,
                ':tokentype' => $this->tokenType,
                ':selector' => $this->selector,
                ':verifier' => $this->hashedVerifier,
                ':additional' => $this->additionalInfo,
                ':expires' => $this->expirationTime
            ]);
        } catch (PDOException $e) {
            throw TokenError::sqlError($e);
        }

        return $this;
    }

    /**
     * Invalidate the token.
     * @param  bool          $deleteToken If true, the token will be deleted from the database. If false (default), it will be updated with the expiration time set in the past
     * @throws OsstException
     * @return $this
     */
    public function invalidateToken(bool $deleteToken = false): self
    {
        if (empty($this->token)) {
            throw OsstException::tokenNotSet();
        }

        $this->expirationTime = time() - self::DEFAULT_EXPIRATION_TIME_OFFSET;

        if ($deleteToken) {
            $statement = $this->dbConnection->prepare(sprintf('DELETE FROM %s WHERE selector = :selector', self::TABLE_NAME));

            if (!$statement) {
                throw TokenError::pdoStatementError($this->dbConnection->errorInfo()[2]);
            }

            try {
                $statement->execute([':selector' => $this->selector]);
            } catch (PdoException $e) {
                throw TokenError::sqlError($e);
            }

            $this->token = null;
            $this->selector = null;
            $this->hashedVerifier = null;
        } else {
            $statement = $this->dbConnection->prepare(sprintf('UPDATE %s SET expiration_time = :expires WHERE selector = :selector', self::TABLE_NAME));

            if (!$statement) {
                throw TokenError::pdoStatementError($this->dbConnection->errorInfo()[2]);
            }

            try {
                $statement->execute([
                    ':expires' => $this->expirationTime,
                    ':selector' => $this->selector
                ]);
            } catch (PdoException $e) {
                throw TokenError::sqlError($e);
            }
        }

        return $this;
    }

    /**
     * Delete all expired tokens from database.
     * @param  PDO $dbConnection Connection to the database
     * @return int Returns the number of deleted tokens
     */
    public static function clearExpiredTokens(PDO $dbConnection): int
    {
        $statement = $dbConnection->prepare(sprintf('DELETE FROM %s WHERE expiration_time <= :time', self::TABLE_NAME));

        if (!$statement) {
            throw TokenError::pdoStatementError($dbConnection->errorInfo()[2]);
        }

        try {
            $statement->execute([':time' => time()]);

            return $statement->rowCount();
        } catch (PdoException $e) {
            throw TokenError::sqlError($e);
        }
    }
}
