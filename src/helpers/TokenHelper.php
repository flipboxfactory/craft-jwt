<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\helpers;

use Craft;
use craft\helpers\User;
use flipbox\craft\jwt\Jwt;
use Lcobucci\JWT\Token;
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
    const CLAIM_IDENTITY = 'jti';

    /**
     * @param $token
     * @param bool $validate
     * @return Token|null
     * @throws \craft\errors\SiteNotFoundException
     */
    public static function parse(string $token, bool $validate = true)
    {
        try {
            $token = Jwt::getInstance()->getParser()->parse((string)$token);
        } catch (\RuntimeException $e) {
            Jwt::warning("Invalid JWT provided: " . $e->getMessage());
            return null;
        } catch (\InvalidArgumentException $e) {
            Jwt::warning("Invalid JWT provided: " . $e->getMessage());
            return null;
        }

        if ($validate && !Jwt::getInstance()->validateToken($token)) {
            return null;
        }

        return $token;
    }

    /**
     * @param IdentityInterface $identity
     * @return string
     */
    public static function getSignatureKey(IdentityInterface $identity = null)
    {
        $result = Jwt::getInstance()->getSettings()->getKey();

        if ($identity === null) {
            return $result;
        }

        return $result . '.' . $identity instanceof User ? $identity->uid : $identity->getId();
    }

    /**
     * @param Token $token
     * @return bool
     */
    public static function verifyTokenCsrfClaim(Token $token): bool
    {
        $csrf = $token->getClaim(self::CLAIM_CSRF);
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
     * @param IdentityInterface $identity
     * @return bool
     */
    public static function verifyTokenSignature(Token $token, IdentityInterface $identity = null): bool
    {
        try {
            if (false === $token->verify(
                    Jwt::getInstance()->getSettings()->resolveSigner($token->getHeader('alg')),
                    TokenHelper::getSignatureKey($identity)
                )) {
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
     * @return bool
     * @throws \craft\errors\SiteNotFoundException
     */
    public static function verifyAudience(Token $token): bool
    {
        $audience = $token->getClaim(TokenHelper::CLAIM_AUDIENCE);
        if (false === ($audience === Craft::$app->getSites()->getCurrentSite()->getBaseUrl())) {
            Jwt::error(sprintf(
                "Unable to verify audience: %s",
                $audience
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
     * @return bool
     * @throws \craft\errors\SiteNotFoundException
     */
    public static function verifyIssuer(Token $token, array $issuers): bool
    {
        $issuer = $token->getClaim(TokenHelper::CLAIM_ISSUER);
        if (false === in_array(
                $issuer,
                $issuers
            )) {
            Jwt::error(sprintf(
                "Unable to verify issuer: %s",
                $issuer
            ));

            return false;
        }
        return true;
    }
}