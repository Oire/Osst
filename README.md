# Osst, Simple Yet Secure Tokens Suitable for Authentication Cookies and Password Recovery

[![Latest Version on Packagist](https://img.shields.io/packagist/v/Oire/Osst.svg?style=flat-square)](https://packagist.org/packages/Oire/Osst)
[![GitHub Tests Action Status](https://img.shields.io/github/workflow/status/Oire/Osst/run-tests?label=tests)](https://github.com/Oire/Osst/actions?query=workflow%3Arun-tests+branch%3Amaster)
[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Oire/Osst/blob/master/LICENSE)

Welcome to Osst, Oirë Simple Split Tokens!  
This library can be used for generating and validating secure tokens suitable for authentication cookies, password recovery and various other tasks.  
Depends on [Oirë Base64](https://github.com/Oire/Base64) for encoding binary data and [Oirë Colloportus](https://github.com/Oire/Colloportus) for encrypting data that need to be decrypted in future.

## The Split Tokens Concept

You can read everything about the split tokens authentication in [this 2017 article](https://paragonie.com/blog/2017/02/split-tokens-token-based-authentication-protocols-without-side-channels) by [Paragon Initiatives](https://paragonie.com). This library implements the idea outlined in that article in PHP.

## Requirements

Requires PHP 7.3 or later with _MbString_ and _OpenSSL_ enabled.

## Installation

Install via [Composer](https://getcomposer.org/):

```shell
composer require oire/osst
```

## Running Tests

Run `./vendor/bin/phpunit` in the project directory.

## Usage Examples

Osst uses fluent interface, i.e., all necessary methods can be chained.  
Each time you instantiate a new Osst object, you need to provide a database connection as a PDO instance. If you don’t use PDO yet, consider using it, it’s convenient. If you use an ORM, you most likely have a `getPdo()` or a similar method.  
Support for popular ORMs is planned for a future version.

### Create a Table

Osst tries to be as database agnostic as possible (MySQL and SQLite were tested, the latter actually powers the unit tests).  
First you need to create the `osst_tokens` table. For mySQL the statement is as follows:

```sql
CREATE TABLE `osst_tokens` (
    `id` INT UNSIGNED NULL AUTO_INCREMENT PRIMARY KEY,
    `user_id` INT UNSIGNED NOT NULL,
    `token_type` INT NULL ,
    `selector` VARCHAR(25) NOT NULL,
    `verifier` VARCHAR(70) NOT NULL,
    `additional_info` TEXT(300) NULL,
    `expiration_time` BIGINT(20) UNSIGNED NOT NULL,
    UNIQUE `token` (`selector`, `verifier`),
    CONSTRAINT `fk_token_user`
        FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
        ON DELETE CASCADE
        ON UPDATE RESTRICT
) ENGINE = InnoDB;
```

You may need to adjust the syntax to suit your particular database driver (see for example the SQLite statement in the tests), as well as the name of your `users` table.  
The field lengths are optimal, the only one you may need to adjust is `additional_info`, if you are planning to use it for larger sets of data.

### Create a Token

first you need to create a token. There are some **required** properties (marked in bold) and some *optional* ones (marked in italic) you can set. If you don’t set any of the required properties, an `OsstException` will be thrown.

* `userId`, **required** — ID of the user the token belongs to, as an integer.
* `expirationTime`, **required** — Time when the token expires. Stored as timestamp (big integer), but can be set in various ways, see below.
* `tokenType`, *optional* — If you want to perform an additional check of the token (say, separate password recovery tokens from e-mail change tokens), you may set a token type as an integer.
* `additionalInfo`, *optional* — Any additional information you want to convey with the token, as string. For instance, you can pass some JSON data here. The information can be additionally encrypted, see below.

To create a token for user with ID of `123` and with token type of `3` expiring in an hour, and store it into the database, do the following:

```php
use Oire\Osst\Osst;

// You should have set your $dbConnection first as a PDO instance
$osst = (new Osst($dbConnection))
    ->createToken()
    ->setUserId(123)
    ->setExpirationTime(time() + 3600)
    ->setTokenType(3)
    ->setAdditionalInfo('{"some": "data"}')
    ->persist();
```

Use `$osst->getToken()` to actually get the newly created token as a string.

### Set and Validate a User-Provided Token

If you received an Osst token from the user, you also need to instantiate Osst and validate the token. You don't need to set all the properties as their values are taken from the database.

```php
use Oire\Osst\Exception\OsstInvalidTokenException as tokenError;
use Oire\Osst\Osst;

try {
    $osst = (new Osst($dbConnection))->setToken($token);
} catch (TokenError $e) {
    // Something went wrong with the token: either it is invalid, not found or has been tampered with
}

if ($osst->tokenIsExpired()) {
    // The token is correct but expired
}
```

**Note**! An expired token is considered settable, i.e., not valid per se but correct, so no exception is thrown in this case, you have to check it manually as shown above. If this behavior is non-intuitive or inconvenient, please create a Github issue.

### Invalidate a Token

After a token is used once (or compromised), you must invalidate it. There are two ways of invalidating a token:

* Setting the expiration time for the token in the past (default);
* Deleting the token from the database whatsoever. To do this, pass `true` as the parameter to the `invalidateToken()` method:

```php
// Given that $osst contains a valid token
$osst->invalidateToken(true);
```

### Clear Expired Tokens

From time to time you will need to delete all expired tokens from the database to reduce the table size and search times. There is a method to do this. It is static, so you have to provide your PDO instance as its parameter. It returns the number of tokens deleted from the database.

```php
$deletedTokens = Osst::clearExpiredTokens($dbConnection);
```

### Three Ways of Setting Expiration Time

You may set expiration time in three different ways, as you like:

* `setExpirationTime()` — Accepts a raw timestamp as integer. If null, defaults to current time plus 14 days.
* `setExpirationDate()` — Accepts a `DateTimeImmutable` object.
* `setExpirationOffset()` — Accepts a [relative datetime format](https://www.php.net/manual/en/datetime.formats.relative.php). Default is `+14 days`.

### Notes on Expiration Times

* All expiration times are internally stored as UTC timestamps.
* Expiration times are set, compared and formatted according to the time of the PHP server, so you won't be in trouble even if your PHP and database server times are different for some reason.
* Microseconds for expiration times are ignored for now, their support is planned for a future version.

### Encrypt Additional Information

You may store some sensitive data in the additional information for the token such as old and new e-mail address and similar things.  
**Note**! Do **not** store passwords in this property, it can be decrypted! Passwords must not be decryptable, they must be hashed instead. If you need to handle passwords, use [Oirë Colloportus](https://github.com/Oire/Colloportus), a library suitable for proper password hashing. You may store password hashes in this property, though.  
If your additional info contains sensitive data, you can encrypt it. To do this, you first need to have a key created by the [Colloportus](https://github.com/Oire/Colloportus) library.  
Colloportus gets installed with Osst, so you don't need to add anything to your composer.json file, just do the following:

```php
use Oire\Colloportus\Colloportus;
use Oire\Osst\Osst;

$key = Colloportus::createKey();
// Store the key somewhere safe, i.e., in an environment variable
$additionalInfo = '{"oldEmail": "john@example.com", "newEmail": "john.doe@example.com"}';
$osst = (new Osst($dbConnection))
    ->createToken()
    ->setUserId(123)
    ->setExpirationOffset('+30 minutes')
    ->setTokenType(3)
    ->setAdditionalInfo($additionalInfo, $key)
    ->persist();
```

That's it. I.e., if the second parameter of `setAdditionalInfo()` is not empty and is a valid Colloportus key, your additional information will be encrypted. If something is wrong, an `OsstException` will be thrown.  
If you received a user-provided token whose additional info is encrypted, pass the key as the second parameter to the `setToken()` method.

## Error Handling

Osst throws two types of exceptions:

* `OsstInvalidTokenException` is thrown when something really wrong happens to the token itself or to SQL queries related to the token (for example, a token is not found, its length is invalid or a PDO statement cannot be executed);
* `OsstException` is thrown in most cases when you do something erroneously (for example, try to store an empty token into the database, forget to set a required property or try to set such a property when validating a user-provided token, try to set expiration time which is in the past etc.).

## Methods

Below all of the Osst methods are outlined.

* `__construct(PDO $dbConnection)` — Instantiate a new Osst object. Provide a PDO instance as the parameter.
* `createToken()` — Create a new token. Returns `$this` for chainability.
* `getDbConnection()` — Get the database connection for the current Osst instance as a PDO object.
* `getToken()` — Get the token for the current Osst instance as a string. Throws `OsstException` if the token was not created or set before.
* `setToken(string $token, string|null $additionalInfoDecryptionKey = null)` — Set and validate a user-provided token. If the `$additionalInfoDecryptionKey` parameter is set and is not empty, tries to decrypt the additional information for the token with the key provided. Returns `$this` for chainability.
* `getUserId()` — Get the ID of the user the token belongs to, as an integer.
* `setUserId(int $userId)` — Set the user ID for the newly created token. Do not use this method and similar methods when validating a user-provided token, use them only when creating a new token. Returns `$this` for chainability.
* `getExpirationTime()` — Get expiration time for the token as raw timestamp. Returns integer.
* `getExpirationDate()` — Get expiration time for the token as a DateTimeImmutable object. Returns the date in the current time zone of your PHP server.
* `getExpirationDateFormatted(string $format = 'Y-m-d H:i:s')` — Get expiration time for the token as date string. The default format is `2020-11-15 12:34:56`. The `$format` parameter must be a valid [date format](https://www.php.net/manual/en/function.date.php).
* `setExpirationTime(int|null $timestamp = null)` — Set expiration time for the token as a raw timestamp. If the timestamp is null, defaults to the current time plus 14 days.
* `setExpirationOffset(string $offset = '+14 days')` — Set expiration time for the token as a relative time offset. The default value is `+14 days`. The `$offset` parameter must be a valid [relative time format](https://www.php.net/manual/en/datetime.formats.relative.php). Returns `$this` for chainability.
* `setExpirationDate(DateTimeImmutable $expirationDate)` — Set expiration time for the token as a [DateTimeImmutable](https://www.php.net/manual/en/class.datetimeimmutable.php) object. Returns `$this` for chainability.
* `tokenIsExpired()` — Check if the token is expired. Returns `true` if the token has already expired, `false` otherwise.
* `getTokenType()` — Get the type for the current token. Returns integer if the token type was set before, or null if the token has no type.
* `setTokenType(int|null $tokenType)` — Set the type for the current token, as integer or null. Returns `$this` for chainability.
* `getAdditionalInfo()` — Get additional info for the token. Returns string or null, if additional info was not set before.
* `setAdditionalInfo(string|null $additionalInfo, string|null $encryptionKey = null)` — Set additional info for the current token. If the `$encryptionKey` parameter is not empty, tries to encrypt the additional information using the [Colloportus](https://github.com/Oire/Colloportus) library. Returns `$this` for chainability.
* `persist()` — Store the token into the database. Returns `$this` for chainability.
* `invalidateToken(bool $deleteToken = false)` — Invalidate the current token after it is used. If the `$deleteToken` parameter is set to `true`, the token will be deleted from the database, and `getToken()` will return `null`. If it is set to `false` (default), the expiration time for the token will be updated and set to a value in the past. The method returns no value.
* `static clearExpiredTokens(PDO $dbConnection)` — Delete all expired tokens from the database. As it is a static method, it receives the database connection as a PDO object. Returns the number of deleted tokens, as integer.

## Contributing

All contributions are welcome. Please fork, make a feature branch, hack on the code, run tests, push your branch and send a pull request.

## License

Copyright © 2020, Andre Polykanine also known as Menelion Elensúlë, [The Magical Kingdom of Oirë](https://github.com/Oire/).  
This software is licensed under an MIT license.