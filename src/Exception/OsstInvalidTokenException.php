<?php
declare(strict_types=1);

namespace Oire\Osst\Exception;

use RuntimeException;
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
final class OsstInvalidTokenException extends RuntimeException
{
    public const SQL_ERROR = 1;
    public const TOKEN_FORMAT_INVALID = 2;
    public const TOKEN_LENGTH_INVALID = 3;
    public const TOKEN_SELECTOR_ERROR = 4;
    public const TOKEN_VERIFIER_ERROR = 5;

    public static function sqlError(Throwable $e): self
    {
        return new self(sprintf('SQL error: %s.', $e->getMessage()), self::SQL_ERROR, $e);
    }

    public static function pdoStatementError(string $message): self
    {
        return new self(sprintf('PDO statement failed: %s.', $message), self::SQL_ERROR);
    }
    public static function invalidTokenFormat(string $message, Throwable $e): self
    {
        return new self(sprintf('The token format is invalid: %s.', $message), self::TOKEN_FORMAT_INVALID, $e);
    }

    public static function invalidTokenLength(): self
    {
        return new self('Invalid token length.', self::TOKEN_LENGTH_INVALID);
    }

    public static function selectorError(): self
    {
        return new self('Selector does not match!', self::TOKEN_SELECTOR_ERROR);
    }

    public static function verifierError(): self
    {
        return new self('Verifier does not match!', self::TOKEN_VERIFIER_ERROR);
    }
}
