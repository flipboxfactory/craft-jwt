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
class Route extends Component
{
    /**
     * The CSRF claim identifier
     */
    const CLAIM_ROUTE = 'route';

    /**
     * Issue an authorization JWT token on behalf of a user.
     *
     * An $action may come in the form of:
     *
     * STRING - Route to a controller action
     * 'action/path'
     *
     * ARRAY - Route to a template
     * ['templates/render', ['template' => 'template/path']]
     *
     * ARRAY w/ PARAMS - Route to a controller action with params
     * ['action/path', [
     *     'foo' => 'bar'
     * ]]
     *
     * @param string|array $action
     * @param string|int|IdentityInterface $user
     * @param string|null $audience
     * @param int|null $expiration
     * @return Token|null
     * @throws \craft\errors\SiteNotFoundException
     * @throws \yii\base\InvalidConfigException
     */
    public function issue(
        $action,
        $user = null,
        int $expiration = null,
        string $audience = null
    ) {
        $identity = UserHelper::resolveUser($user);

        $builder = Jwt::getInstance()->getBuilder()
            ->setIssuer(Jwt::getInstance()->getSettings()->getIssuer())
            ->setAudience($this->resolveAudience($audience))
            ->setIssuedAt(time())
            ->setNotBefore(time())
            ->setExpiration($this->resolveTokenExpiration($expiration))
            ->set(TokenHelper::CLAIM_CSRF, Craft::$app->getRequest()->getCsrfToken())
            ->set(self::CLAIM_ROUTE, serialize($action))
            ->sign(Jwt::getInstance()->getSettings()->getSigner(), TokenHelper::getSignatureKey($identity));

        if ($identity) {
            $builder->setId($identity->getId(), true);
        }

        return $builder->getToken();
    }

    /**
     * @param string $token
     * @param bool $assumeIdentity
     * @return string|array
     * @throws \craft\errors\SiteNotFoundException
     */
    public function claim(string $token, bool $assumeIdentity = true)
    {
        if (null === ($token = $this->parse($token))) {
            return false;
        }

        // Assume the identity token
        if ($assumeIdentity && null !== ($identity = $this->tokenIdentity($token))) {
            Craft::$app->getUser()->setIdentity($identity);
        }

        return unserialize($token->getClaim(static::CLAIM_ROUTE));
    }

    /**
     * @param Token $token
     * @return null|IdentityInterface
     */
    private function tokenIdentity(Token $token)
    {
        if (!$token->hasClaim(TokenHelper::CLAIM_IDENTITY)) {
            return null;
        }

        return UserHelper::resolveUser($token->getClaim(TokenHelper::CLAIM_IDENTITY));
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
        $identity = null;
        if ($token->hasClaim(TokenHelper::CLAIM_IDENTITY)) {
            $identity = UserHelper::resolveUser($token->getClaim(TokenHelper::CLAIM_IDENTITY));
        }

        return TokenHelper::verifyTokenCsrfClaim($token) &&
            TokenHelper::verifyIssuer($token, Jwt::getInstance()->getSettings()->getRouteIssuers()) &&
            TokenHelper::verifyAudience($token) &&
            TokenHelper::verifyTokenSignature($token, $identity);
    }

    /**
     * @param string|null $audience
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    private function resolveAudience(string $audience = null): string
    {
        if ($audience === null) {
            $audience = Jwt::getInstance()->getSettings()->getRouteAudience();
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
            $expiration = Jwt::getInstance()->getSettings()->getRouteTokenDuration();
        }

        return time() + (int)$expiration;
    }
}
