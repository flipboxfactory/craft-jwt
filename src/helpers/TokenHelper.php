<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\helpers;

use Craft;
use craft\elements\User;
use craft\errors\SiteNotFoundException;
use flipbox\craft\jwt\Jwt;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Lcobucci\JWT\Validation\Validator;
use yii\web\IdentityInterface;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 1.0.0
 */
class TokenHelper
{
    /**
     * The CSRF claim identifier
     */
    const CLAIM_CSRF = 'csrf';

    /**
     * The Audience claim identifier
     */
    const CLAIM_AUDIENCE = 'aud';

    /**
     * The Issuer claim identifier
     */
    const CLAIM_ISSUER = 'iss';

    /**
     * The Identity claim identifier
     */
    const CLAIM_IDENTITY = 'sub';

    /**
     * @param string $token
     * @return Token|null
     */
    public static function parse(string $token)
    {
        try {
            $token = Jwt::getInstance()->getParser()->parse($token);
        } catch (\RuntimeException|\InvalidArgumentException $e) {
            Jwt::warning("Invalid JWT provided: " . $e->getMessage());
            return null;
        }

        return $token;
    }

    /**
     * @param IdentityInterface|null $identity
     * @return Key
     */
    public static function getSignatureKey(IdentityInterface|null $identity = null): Key
    {
        $result = Jwt::getInstance()->getSettings()->getKey();

        if ($identity === null) {
            return InMemory::plainText($result);
        }

        return InMemory::plainText(
            $result . '.' . ($identity instanceof User ? $identity->uid : $identity->getId())
        );
    }

    /**
     * @param Token $token
     * @param Validator|null $validator
     * @return bool
     */
    public static function verifyTokenDates(Token $token, Validator $validator = null): bool
    {
        $validator = $validator ?: new Validator();

        if (false === $validator->validate(
                $token, new StrictValidAt(
                    new FrozenClock(new \DateTimeImmutable())
                )
            )
        ) {
            Jwt::error("Unable to verify token dates");

            return false;
        }
        return true;
    }

    /**
     * @param Token $token
     * @return bool
     */
    public static function verifyTokenCsrfClaim(Token $token): bool
    {
        $csrf = $token->claims()->get(self::CLAIM_CSRF);
        if (false === Craft::$app->getRequest()->validateCsrfToken($csrf)) {
            Jwt::error(sprintf(
                "Unable to verify CSRF Token: %s",
                $csrf
            ));

            return false;
        }
        return true;
    }

    /**
     * @param Token $token
     * @param IdentityInterface|null $identity
     * @param Validator|null $validator
     * @return bool
     */
    public static function verifyTokenSignature(Token $token, IdentityInterface|null $identity = null, Validator $validator = null): bool
    {
        $validator = $validator ?: new Validator();

        try {
            if (false === $validator->validate(
                    $token,
                    new SignedWith(
                        Jwt::getInstance()->getSettings()->resolveSigner($token->headers()->get('alg')),
                        TokenHelper::getSignatureKey($identity)
                    )
                )
            ) {
                Jwt::error("Unable to verify token signature");
                return false;
            }
            return true;
        } catch (\Exception $e) {
            Jwt::error(sprintf(
                "Exception caught while trying to verify token signature: %s",
                $e->getMessage()
            ));
        }
        return false;
    }

    /**
     * @param Token $token
     * @param Validator|null $validator
     * @return bool
     * @throws SiteNotFoundException
     */
    public static function verifyAudience(Token $token, Validator $validator = null): bool
    {
        $validator = $validator ?: new Validator();

        if (false === $validator->validate(
                $token,
                new PermittedFor(
                    Craft::$app->getSites()->getCurrentSite()->getBaseUrl()
                )
            )
        ) {
            Jwt::error(sprintf(
                "Unable to verify audience: %s",
                $token->claims()->get(TokenHelper::CLAIM_AUDIENCE)
            ));

            return false;
        }
        return true;
    }

    /**
     * Verify that the issuer is one we can accept from
     *
     * @param Token $token
     * @param array $issuers
     * @param Validator|null $validator
     * @return bool
     */
    public static function verifyIssuer(Token $token, array $issuers, Validator $validator = null): bool
    {
        $validator = $validator ?: new Validator();

        if (false === $validator->validate(
                $token,
                new IssuedBy(
                    ...$issuers
                )
            )
        ) {
            Jwt::error(sprintf(
                "Unable to verify issuer: %s",
                $token->claims()->get(TokenHelper::CLAIM_ISSUER)
            ));

            return false;
        }
        return true;
    }
}
