<?php
declare(strict_types=1);
namespace Oire\Osst;

use DateTimeImmutable;
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
    public const TOKEN_SIZE = 48;
    public const SELECTOR_SIZE = 16;
    public const VERIFIER_SIZE = 32;
    public const TABLE_NAME = 'osst_tokens';

    private $dbConnection;
    private $token;
    private $userId;
    private $expirationDate;
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
        $this->token = Base64::encode(random_bytes(self::TOKEN_SIZE));

        return $this;
    }

    /**
     * Get the connection to the database.
     * @return PDO
    */
    public function getDbConnection(): PDO
    {
        return $this->dbConnection;
    }

    /**
     * Get the token.
     * @throws OsstException If the token was not set or created beforehand
     * @return string
    */
    public function getToken(): string
    {
        return $this->token;
    }

    /**
     * Set and validate a user-provided token.
     * @param string $token The token provided by the user
     * @param ?string $additionalInfoDecryptionKey If not empty, the previously additional info for the token will be decrypted using Oirë Colloportus
     * @see https://github.com/Oire/Colloportus
     * @throws TokenError
     * @return $this
     */
    public function setToken(string $token, ?string $additionalInfoDecryptionKey): self
    {
        $this->token = $token;

        try {
            $rawToken = Base64::decode($this->token);
        } catch (Base64Exception $e) {
            throw TokenError::invalidTokenFormat($e->getMessage(), $e);
        }

        if (mb_strlen($rawToken, '8bit') !== self::TOKEN_SIZE) {
            throw TokenError::invalidTokenLength();
        }

        $selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, '8bit'));

        $sql = sprintf('SELECT user_id, token_type, selector, verifier, additional_info, expires_at FROM %s WHERE selector = :selector', self::TABLE_NAME);
        $statement = $this->dbConnection->prepare($sql);
        $statement->bindParam(':selector', $selector, PDO::PARAM_STR);

        try {
            $statement->execute();
        } catch (PDOException $e) {
            throw TokenError::sqlError($e);
        }

        $result = $statement->fetch();

        if (empty($result) || count($result) === 0) {
            throw TokenError::selectorError();
        }

        $verifier = Base64::encode(hash(Colloportus::HASH_FUNCTION, mb_substr($rawToken, self::SELECTOR_SIZE, self::VERIFIER_SIZE, '8bit'), true));
        $validVerifier = $result['verifier'];

        if (!hash_equals($verifier, $validVerifier)) {
            throw TokenError::verifierError();
        }

        $this->userId = $result['user_id'];
        $this->expirationDate = new DateTimeImmutable(sprintf('@%s', $result['expires_at']));
        $this->tokenType = $result['token_type'];

        if (!empty($additionalInfoDecryptionKey)) {
            try {
                $this->additionalInfo = Colloportus::decrypt($result['additional_info'], $additionalInfoDecryptionKey);
            } catch (ColloportusException $e) {
                throw OsstException::decryptionError($e);
            }
        }

        $this->additionalInfo = $result['additional_info'];

        return $this;
    }

    /**
     * Get the ID of the user the token belongs to.
     * @return int
    */
    public function getUserId(): int
    {
        return $this->userId;
    }

    /**
     * Set the ID of the user the token belongs to.
     * @param int $userId The ID of the user the token belongs to. Must be a positive integer.
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
     * Get the expiration date of the token.
     * @return DateTimeImmutable
    */
    public function getExpirationDate(): DateTimeImmutable
    {
        return $this->expirationDate;
    }

    /**
     * Get the expiration date of the token in a given format.
     * @param string $format A valid date format. Defaults to `'Y-m-d H:i:s'`
     샔* @see https://www.php.net/manual/en/function.date.php
     * @throws OsstException if the date formatting fails
     * @return string
    */
    public function getExpirationDateFormatted(string $format = 'Y-m-d H:i:s'): string
    {
        try {
            return $this->expirationDate->format($format);
        } catch (Throwable $e) {
            throw new OsstException(sprintf('Unable to format expiration date: %s.', $e->getMessage()), $e);
        }
    }

    /**
     * Set the expiration date for the token.
     * @param string $expires The time interval the token expires in. The default value is `'+14 days'`. Must be a valid relative date format.
     * @see https://www.php.net/manual/en/datetime.formats.relative.php
     * @throws OsstException
     * @return $this
     */
    public function setExpirationDate(string $expires = '+14 days'): self
    {
        if ($this->expirationDate) {
            throw OsstException::propertyAlreadySet('Expiration date');
        }

        if (empty($expires)) {
            throw OsstException::emptyExpirationInterval();
        }

        try {
            $this->expirationDate = (new DateTimeImmutable())->modify($expires);
        } catch (Throwable $e) {
            throw OsstException::invalidExpirationInterval($expires, $e->getMessage(), $e);
        }

        return $this;
    }

    /**
     * Check if the token is expired.
     * @throws OsstException if the expiration date is empty
     * @return bool True if the token is expired, false otherwise
    */
    public function isExpired(): bool
    {
        if (empty($this->expirationDate)) {
            throw OsstException::emptyExpirationDate();
        }

        $now = new DateTimeImmutable();

        return $this->expirationDate < $now;
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
     * @param int $tokenType Set this if you want to categorize your tokens by type. The default value is null
     * @return $this
     */
    public function setTokenType(?int $tokenType = null): self
    {
        $this->tokenType = $tokenType;

        return $this;
    }

    /**
     * Get the additional info for the token.
     * @return string
    */
    public function getAdditionalInfo(): string
    {
        return $this->additionalInfo;
    }

    /**
     * Set the additional info for the token.
     * @param ?string $additionalInfo Any additional info you want to convey along with the token, as string. Default value is null
     * @param ?string $encryptionKey If not empty, the data will be encrypted using Oirë Colloportus
     * @see https://github.com/Oire/Colloportus
     * @return $this
     */
    public function setAdditionalInfo(?string $additionalInfo = null, ?string $encryptionKey = null): self
    {
        if (!empty($encryptionKey)) {
            try {
                $this->additionalInfo = Colloportus::encrypt($additionalInfo, $encryptionKey);
            } catch (ColloportusException $e) {
                throw OsstException::encryptionError($e);
            }
        }

        $this->additionalInfo = $additionalInfo;

        return $this;
    }

    /**
     * Store the token in the database.
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

        if (empty($this->expirationDate)) {
            throw OsstException::emptyExpirationDate();
        }

        try {
            $rawToken = Base64::decode($this->token);
        } catch (Base64Exception $e) {
            throw TokenError::invalidTokenFormat($e->getMessage(), $e);
        }

        if (mb_strlen($rawToken, '8bit') !== self::TOKEN_SIZE) {
            throw TokenError::invalidTokenLength();
        }

        $selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, '8bit'));
        $verifier = Base64::encode(hash(Colloportus::HASH_FUNCTION, mb_substr($rawToken, self::SELECTOR_SIZE, self::VERIFIER_SIZE, '8bit'), true));

        $sql = sprintf('INSERT INTO %s (user_id, token_type, selector, verifier, additional_info, expires_at) VALUES (:userid, :tokentype, :selector, :verifier, :additional, :expires)', self::TABLE_NAME);
        $statement = $this->dbConnection->prepare($sql);

        $statement->bindParam(':userid', $this->userId, PDO::PARAM_INT);
        $statement->bindParam(':tokentype', $this->tokenType, PDO::PARAM_INT);
        $statement->bindParam(':selector', $selector, PDO::PARAM_STR);
        $statement->bindParam(':verifier', $verifier, PDO::PARAM_STR);
        $statement->bindParam(':additional', $this->additionalInfo, PDO::PARAM_STR);
        $statement->bindParam(':expires', sprintf('@%s', $this->expirationDate), PDO::PARAM_INT);

        try {
            $statement->execute();
        } catch (PDOException $e) {
            throw TokenError::sqlError($e);
        }

        return $this;
    }
}
