<?php
declare(strict_types=1);

namespace Oire\Osst\Exception;

use Oire\Colloportus\Exception\ColloportusException;
use RuntimeException;
use Throwable;

/**
 * Oirë Simple Split Tokens (OSST)
 * Implements the split token authentication model proposed by Paragon Initiatives.
 * Copyright © 2020 Andre Polykanine also known as Menelion Elensúlë, The magical kingdom of Oirë, https://github.com/Oire
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
class OsstException extends RuntimeException
{
    public function __construct(string $message, ?Throwable $previous = null)
    {
        parent::__construct($message, 0, $previous);
    }

    public static function invalidUserId(?int $userId): self
    {
        return new static(sprintf('Invalid user ID. Should be a positive integer, %d given.', $userId));
    }

    public static function emptyExpirationOffset(): self
    {
        return new static('Expiration offset must not be empty.');
    }

    public static function invalidExpirationOffset(string $offset, string $message, Throwable $e): self
    {
        return new static(sprintf('%s is not a valid expiration offset: %s.', $offset, $message), $e);
    }

    public static function emptyExpirationTime(): self
    {
        return new static('Expiration time cannot be empty, set or create the token first.');
    }

    public static function expirationTimeInPast(int $expirationTime): self
    {
        return new static(sprintf('Expiration time cannot be in the past. The difference is -%d seconds.', time() - $expirationTime));
    }

    public static function tokenNotSet(): self
    {
        return new static('The token is not set, please retrieve or create it first.');
    }

    public static function propertyAlreadySet(string $property): self
    {
        return new static(sprintf('%s is already set in token validation.', $property));
    }

    public static function additionalInfoEncryptionError(ColloportusException $e): self
    {
        return new static(sprintf('Unable to encrypt additional info: %s.', $e->getMessage()), $e);
    }

    public static function additionalInfoDecryptionError(ColloportusException $e): self
    {
        return new static(sprintf('Unable to decrypt additional info: %s.', $e->getMessage()), $e);
    }
}
