<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\services;

use Craft;
use craft\elements\User;
use flipbox\craft\jwt\Jwt;
use flipbox\craft\jwt\helpers\TokenHelper;
use flipbox\craft\jwt\helpers\UserHelper;
use Lcobucci\JWT\Token;
use yii\base\Component;
use yii\web\IdentityInterface;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 1.0.0
 */
class Identity extends Component
{
    /**
     * Issue an authorization JWT token on behalf of a user.
     *
     * @param string $user
     * @param string|null $audience
     * @param int|null $expiration
     * @return Token|null
     * @throws \craft\errors\SiteNotFoundException
     * @throws \yii\base\InvalidConfigException
     */
    public function issue(
        $user = 'CURRENT_USER',
        string $audience = null,
        int $expiration = null
    ) {
        if (null === ($identity = UserHelper::resolveUser($user))) {
            $identity = new User();
        }

        return Jwt::getInstance()->getBuilder()
            ->setIssuer(Jwt::getInstance()->getSettings()->getIssuer())
            ->setAudience($this->resolveAudience($audience))
            ->setId($identity->getId(), true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration($this->resolveTokenExpiration($expiration))
            ->set(TokenHelper::CLAIM_CSRF, Craft::$app->getRequest()->getCsrfToken())
            ->sign(Jwt::getInstance()->getSettings()->getSigner(), TokenHelper::getSignatureKey($identity))
            ->getToken();
    }

    /**
     * This
     * @param string $token
     * @return bool|null|IdentityInterface
     * @throws \craft\errors\SiteNotFoundException
     */
    public function claim(string $token)
    {
        if (null === ($token = $this->parse($token))) {
            return false;
        }

        return $this->tokenIdentity($token);
    }

    /**
     * @param $token
     * @param bool $validate
     * @param bool $verify
     * @return Token|null
     * @throws \craft\errors\SiteNotFoundException
     */
    public function parse(string $token, bool $validate = true, bool $verify = true)
    {
        if (null === ($token = TokenHelper::parse($token, $validate))) {
            return null;
        }

        if ($verify && !$this->verifyToken($token)) {
            return null;
        }

        return $token;
    }

    /**
     * @param Token $token
     * @return bool
     * @throws \craft\errors\SiteNotFoundException
     */
    public function verifyToken(Token $token): bool
    {
        if (null === ($identity = UserHelper::resolveUser($token->getClaim(TokenHelper::CLAIM_IDENTITY)))) {
            $identity = new User();
        }

        return TokenHelper::verifyTokenCsrfClaim($token) &&
            TokenHelper::verifyIssuer($token, Jwt::getInstance()->getSettings()->getIdentityIssuers()) &&
            TokenHelper::verifyAudience($token) &&
            TokenHelper::verifyTokenSignature($token, $identity);
    }

    /**
     * @param Token $token
     * @return null|IdentityInterface
     */
    private function tokenIdentity(Token $token)
    {
        return UserHelper::resolveUser($token->getClaim(TokenHelper::CLAIM_IDENTITY));
    }

    /**
     * @param string|null $audience
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    private function resolveAudience(string $audience = null): string
    {
        if ($audience === null) {
            $audience = Jwt::getInstance()->getSettings()->getIdentityAudience();
        }

        return (string)$audience;
    }

    /**
     * @param int|null $expiration
     * @return int
     * @throws \yii\base\InvalidConfigException
     */
    private function resolveTokenExpiration(int $expiration = null): int
    {
        if ($expiration === null) {
            $expiration = Jwt::getInstance()->getSettings()->getIdentityTokenDuration();
        }

        return time() + (int)$expiration;
    }
}
