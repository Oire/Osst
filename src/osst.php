<?php
declare(strict_types=1);
namespace Oire;

use DateTimeImmutable;
use Oire\Base64;
use Oire\Exception\Base64Exception;
use Oire\Exception\OsstException;
use Oire\Exception\OsstInvalidTokenException as TokenError;
use PDO;
use PDOException;

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
    public const HASH_FUNCTION = 'sha384';

    private $dbConnection;
    private $tableName;
    private $camelCaseColumns;
    private $token;

    private $userId;
    private $expirationDate;
    private $tokenType;
    private $additionalInfo;

    /**
     * Instantiate a new Osst object.
     * @param PDO $dbConnection Connection to your database
     * @param ?string $token A user-provided token. If empty, a new token will be created
     * @param ?string $tableName The name of the table where tokens are stored. If empty, will be set to `osst_tokens`
     * @param bool $camelCaseColumns Whether the table and column names should be camelCase or snake_case. Preferably leave it at the default `false` value to comply with the SQL standard
    */
    public function __construct(PDO $dbConnection, ?string $token = null, ?string $tableName = null, bool $camelCaseColumns = false)
    {
        $this->dbConnection = $dbConnection;

        try {
            $this->dbConnection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            throw TokenError::sqlError($e);
        }

        $this->token = $token?: Base64::encode(random_bytes(self::TOKEN_SIZE));

        $this->camelCaseColumns = $camelCaseColumns;
        $this->tableName = $tableName?: ($this->camelCaseColumns? 'OsstTokens': 'osst_tokens');
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
     * Get the name of the table where the tokens are stored.
     * @return string
    */
    public function getTableName(): string
    {
        return $this->tableName;
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
     * Validate a user-provided token.
     * @throws TokenError
     * @return $this
    */
    public function validate(): self
    {
        try {
            $rawToken = Base64::decode($this->token);
        } catch (Base64Exception $e) {
            throw TokenError::invalidTokenFormat($e->getMessage(), $e);
        }

        if (mb_strlen($rawToken, '8bit') !== self::TOKEN_SIZE) {
            throw TokenError::invalidTokenLength();
        }

        $selector = Base64::encode(mb_substr($rawToken, 0, self::SELECTOR_SIZE, '8bit'));

        $sql = $this->camelCaseColumns
            ? sprintf('SELECT UserId, TokenType, Selector, Verifier, AdditionalInfo, ExpiresAt FROM %s WHERE Selector = ?', $this->tableName)
            : sprintf('SELECT user_id, token_type, selector, verifier, additional_info, expires_at FROM %s WHERE selector = ?', $this->tableName);
        $statement = $this->dbConnection->prepare($sql);

        try {
            $statement->execute($storableSelector);
        } catch (PDOException $e) {
            throw TokenError::sqlError($e);
        }

        $result = $statement->fetch();

        if (empty($result) || count($result) === 0) {
            throw TokenError::selectorError();
        }

        $verifier = Base64::encode(hash(self::HASH_FUNCTION, mb_substr($rawToken, self::SELECTOR_SIZE, self::VERIFIER_SIZE, '8bit'), true));
        $validVerifier = $this->camelCaseColumns? $result['Verifier']: $result['verifier'];

        if (!hash_equals($verifier, $validVerifier)) {
            throw TokenError::verifierError();
        }

        $this->userId = $this->camelCaseColumns? $result['UserId']: $result['user_id'];
        $this->expirationDate = new DateTimeImmutable(sprintf('@%s', $this->camelCaseColumns? $result['ExpiresAt']: $result['expires_at']));
        $this->tokenType = $this->camelCaseColumns? $result['tokenType']: $result['token_type'];
        $this->additionalInfo = $this->camelCaseColumns? $result['AdditionalInfo']: $result['additional_info'];

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
        } catch (\Exception $e) {
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
        } catch (\Exception $e) {
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
     * @return mixed
    */
    public function getAdditionalInfo()
    {
        return $this->additionalInfo;
    }

    /**
     * Process the additional info for the token.
     * @param callable $callback The function to apply to the additional info
     * @param ?mixed[] $arguments More arguments to the callback function
     * @return $this
    */
    public function processAdditionalInfo(callable $callback, ?array $arguments): self
    {
        $this->additionalInfo = ($arguments && count($arguments) > 0)? call_user_func($callback, $additionalInfo, ...$arguments): call_user_func($callback, $this->additionalInfo);

        return $this;
    }

    /**
     * Set the additional info for the token.
     * @param mixed $additionalInfo Any additional info you want to convey along with the token. Default value is null
     * @return $this
     */
    public function setAdditionalInfo($additionalInfo = null): self
    {
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

        if (!empty($this->additionalInfo) && !is_string($this->additionalInfo)) {
            throw new OsstException(sprintf('Additional info must be a string when storing to database, %s given.', gettype($this->additionalInfo)));
        }        



    }
}
