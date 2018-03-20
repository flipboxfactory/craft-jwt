<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\services;

use Craft;
use flipbox\craft\jwt\Jwt;
use Lcobucci\JWT\Token;
use yii\base\Component;
use yii\web\IdentityInterface;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 1.0.0
 */
class Authorization extends Component
{
    /**
     * The CSRF claim identifier
     */
    const CLAIM_CSRF = 'csrf';

    /**
     * The Identity claim identifier
     */
    const CLAIM_IDENTITY = 'jti';

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
        if (null === ($identity = $this->resolveUser($user))) {
            return null;
        }

        return Jwt::getInstance()->getBuilder()
            ->setIssuer(Jwt::getInstance()->getSettings()->getIssuer())
            ->setAudience($this->resolveAudience($audience))
            ->setId($identity->getId(), true)
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration($this->resolveTokenExpiration($expiration))
            ->set(self::CLAIM_CSRF, Craft::$app->getRequest()->getCsrfToken())
            ->sign(Jwt::getInstance()->getSettings()->getSigner(), $this->getSignatureKey($identity))
            ->getToken();
    }

    /**
     * This
     * @param string $token
     * @return null|IdentityInterface
     */
    public function claim(string $token)
    {
        if (null === ($token = $this->parse($token))) {
            return null;
        }

        return $this->tokenIdentity($token);
    }

    /**
     * @param $token
     * @param bool $validate
     * @param bool $verify
     * @return Token|null
     */
    public function parse(string $token, bool $validate = true, bool $verify = true)
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

        if (($validate && !$this->validateToken($token)) ||
            ($verify && !$this->verifyToken($token))) {
            return null;
        }

        return $token;
    }

    /**
     * @param Token $token
     * @param int|null $currentTime
     * @return bool
     */
    public function validateToken(Token $token, int $currentTime = null): bool
    {
        return $token->validate(
            Jwt::getInstance()->getValidationData($currentTime)
        );
    }

    /**
     * @param Token $token
     * @return bool
     */
    public function verifyToken(Token $token): bool
    {
        if (null === ($identity = $this->resolveUser($token->getClaim(self::CLAIM_IDENTITY)))) {
            return false;
        }

        return $this->verifyTokenCsrfClaim($token) &&
            $this->verifyTokenSignature($token, $identity);
    }

    /**
     * @param Token $token
     * @return null|IdentityInterface
     */
    private function tokenIdentity(Token $token)
    {
        return $this->resolveUser($token->getClaim(self::CLAIM_IDENTITY));
    }

    /**
     * @param Token $token
     * @return bool
     */
    private function verifyTokenCsrfClaim(Token $token): bool
    {
        return Craft::$app->getRequest()->validateCsrfToken(
            $token->getClaim(self::CLAIM_CSRF)
        );
    }

    /**
     * @param Token $token
     * @param IdentityInterface $identity
     * @return bool
     */
    private function verifyTokenSignature(Token $token, IdentityInterface $identity): bool
    {
        try {
            return $token->verify(
                Jwt::getInstance()->getSettings()->resolveSigner($token->getHeader('alg')),
                $this->getSignatureKey($identity)
            );
        } catch (\Exception $e) {
            Jwt::error(sprintf(
                "Exception caught while trying to verify token signature: %s",
                $e->getMessage()
            ));
        }
        return false;
    }

    /**
     * @param IdentityInterface $identity
     * @return string
     */
    private function getSignatureKey(IdentityInterface $identity)
    {
        return Jwt::getInstance()->getSettings()->getKey() . '.' . $identity->getId();
    }

    /**
     * @param string|null $audience
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    private function resolveAudience(string $audience = null): string
    {
        if ($audience === null) {
            $audience = Jwt::getInstance()->getSettings()->getAudience();
        }

        return (string)$audience;
    }

    /**
     * @param int|null $expiration
     * @return int
     */
    private function resolveTokenExpiration(int $expiration = null): int
    {
        if ($expiration === null) {
            $expiration = Jwt::getInstance()->getSettings()->tokenExpiration;
        }

        return time() + (int)$expiration;
    }

    /**
     * @param $user
     * @return IdentityInterface|null
     */
    private function resolveUser($user)
    {
        if ($user instanceof IdentityInterface) {
            return $user;
        }

        if ($user === 'CURRENT_USER') {
            return Craft::$app->getUser()->getIdentity();
        }

        if (is_numeric($user)) {
            return Craft::$app->getUsers()->getUserById($user);
        }

        if (is_string($user)) {
            return Craft::$app->getUsers()->getUserByUsernameOrEmail($user);
        }

        return null;
    }
}
