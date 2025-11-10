<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\services;

use Craft;
use craft\errors\SiteNotFoundException;
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
     * @param array|string $action
     * @param int|string|IdentityInterface|null $user
     * @param string|null $audience
     * @param int|null $expiration
     * @return Token|null
     * @throws \craft\errors\SiteNotFoundException
     * @throws \yii\base\InvalidConfigException
     * @throws \Throwable
     */
    public function issue(
        array|string                 $action,
        int|string|IdentityInterface $user = null,
        int                          $expiration = null,
        string                       $audience = null
    )
    {
        $identity = UserHelper::resolveUser($user);

        $now = new \DateTimeImmutable();

        $builder = Jwt::getInstance()->getBuilder()
            ->issuedBy(Jwt::getInstance()->getSettings()->getIssuer())
            ->permittedFor($this->resolveAudience($audience))
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->resolveTokenExpiration($now, $expiration))
            ->withClaim(TokenHelper::CLAIM_CSRF, Craft::$app->getRequest()->getCsrfToken())
            ->withClaim(self::CLAIM_ROUTE, serialize($action));

        if ($identity && $identity->getId()) {
            $builder->relatedTo($identity->getId());
        }

        return $builder->getToken(Jwt::getInstance()->getSettings()->getSigner(), TokenHelper::getSignatureKey($identity));
    }

    /**
     * @param string $token
     * @param bool $assumeIdentity
     * @return string|array
     * @throws \craft\errors\SiteNotFoundException
     * @throws \Throwable
     */
    public function claim(string $token, bool $assumeIdentity = true): false|array|string
    {
        if (null === ($token = $this->parse($token))) {
            return false;
        }

        // Assume the identity token
        if ($assumeIdentity && null !== ($identity = $this->tokenIdentity($token))) {
            Craft::$app->getUser()->setIdentity($identity);
        }

        return unserialize($token->claims()->get(static::CLAIM_ROUTE));
    }

    /**
     * @param Token $token
     * @return null|IdentityInterface
     * @throws \Throwable
     */
    private function tokenIdentity(Token $token)
    {
        if (!$token->claims()->has(TokenHelper::CLAIM_IDENTITY)) {
            return null;
        }

        return UserHelper::resolveUser($token->claims()->get(TokenHelper::CLAIM_IDENTITY));
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
        $identity = null;
        if ($token->claims()->has(TokenHelper::CLAIM_IDENTITY)) {
            $identity = UserHelper::resolveUser($token->claims()->get(TokenHelper::CLAIM_IDENTITY));
        }

        $validator = new Validator();

        return TokenHelper::verifyTokenDates($token, $validator) &&
            TokenHelper::verifyTokenCsrfClaim($token) &&
            TokenHelper::verifyIssuer($token, Jwt::getInstance()->getSettings()->getRouteIssuers(), $validator) &&
            TokenHelper::verifyAudience($token, $validator) &&
            TokenHelper::verifyTokenSignature($token, $identity, $validator);
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
     * @param \DateTimeImmutable $now
     * @param int|null $expiration
     * @return \DateTimeImmutable
     * @throws InvalidConfigException
     */
    private function resolveTokenExpiration(\DateTimeImmutable $now, int $expiration = null): \DateTimeImmutable
    {
        if ($expiration === null) {
            $expiration = Jwt::getInstance()->getSettings()->getRouteTokenDuration();
        }

        return $now->modify((int)$expiration . ' seconds');
    }
}
