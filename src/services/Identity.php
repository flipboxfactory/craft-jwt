<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\services;

use Craft;
use craft\elements\User;
use craft\errors\SiteNotFoundException;
use flipbox\craft\jwt\errors\IdentityNotFoundException;
use flipbox\craft\jwt\helpers\TokenHelper;
use flipbox\craft\jwt\helpers\UserHelper;
use flipbox\craft\jwt\Jwt;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Validator;
use yii\base\Component;
use yii\base\InvalidConfigException;
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
     * @throws \Throwable
     */
    public function issue(
        string $user = 'CURRENT_USER',
        string $audience = null,
        int    $expiration = null
    ): ?Token
    {
        if (null === ($identity = UserHelper::resolveUser($user))) {
            throw new IdentityNotFoundException('Failed to find identity');
        }

        $now = new \DateTimeImmutable();

        return Jwt::getInstance()->getBuilder()
            ->issuedBy(Jwt::getInstance()->getSettings()->getIssuer())
            ->permittedFor($this->resolveAudience($audience))
            ->relatedTo($identity->getId())
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->resolveTokenExpiration($now, $expiration))
            ->withClaim(TokenHelper::CLAIM_CSRF, Craft::$app->getRequest()->getCsrfToken())
            ->getToken(Jwt::getInstance()->getSettings()->getSigner(), TokenHelper::getSignatureKey($identity));
    }

    /**
     * This
     *
     * @param string $token
     * @return bool|null|IdentityInterface
     * @throws \craft\errors\SiteNotFoundException
     * @throws \Throwable
     */
    public function claim(string $token): bool|IdentityInterface|null
    {
        if (null === ($token = $this->parse($token))) {
            return false;
        }

        return $this->tokenIdentity($token);
    }

    /**
     * @param string $token
     * @param bool $validate
     * @return Token|null
     * @throws SiteNotFoundException
     * @throws \Throwable
     */
    public function parse(string $token, bool $validate = true): ?Token
    {
        if (null === ($token = TokenHelper::parse($token))) {
            return null;
        }

        if ($validate && !$this->validateToken($token)) {
            return null;
        }

        return $token;
    }

    /**
     * @param Token $token
     * @return bool
     * @throws \craft\errors\SiteNotFoundException
     * @throws \Throwable
     */
    public function validateToken(Token $token): bool
    {
        if (null === ($identity = $this.tokenIdentity($token))) {
            throw new IdentityNotFoundException('Failed to find identity');
        }

        $validator = new Validator();

        return TokenHelper::verifyTokenDates($token, $validator) &&
            TokenHelper::verifyTokenCsrfClaim($token) &&
            TokenHelper::verifyIssuer($token, Jwt::getInstance()->getSettings()->getIdentityIssuers(), $validator) &&
            TokenHelper::verifyAudience($token, $validator) &&
            TokenHelper::verifyTokenSignature($token, $identity, $validator);
    }

    /**
     * @param Token $token
     * @return null|IdentityInterface
     * @throws \Throwable
     */
    private function tokenIdentity(Token $token): ?IdentityInterface
    {
        return UserHelper::resolveUser(
            $token->claims()->get(TokenHelper::CLAIM_IDENTITY)
        );
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
     * @param \DateTimeImmutable $now
     * @param int|null $expiration
     * @return \DateTimeImmutable
     * @throws InvalidConfigException
     */
    private function resolveTokenExpiration(\DateTimeImmutable $now, int $expiration = null): \DateTimeImmutable
    {
        if ($expiration === null) {
            $expiration = Jwt::getInstance()->getSettings()->getIdentityTokenDuration();
        }

        return $now->modify((int)$expiration . ' seconds');
    }
}
