<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\filters;

use craft\elements\User;
use flipbox\craft\jwt\Jwt;
use yii\filters\auth\AuthMethod;
use yii\web\IdentityInterface;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 1.0.0
 */
class JwtHttpBearerAuth extends AuthMethod
{
    /**
     * @var string A "realm" attribute MAY be included to indicate the scope
     * of protection in the manner described in HTTP/1.1 [RFC2617].  The "realm"
     * attribute MUST NOT appear more than once.
     */
    public $realm = 'api';

    /**
     * @var string Authorization header schema, default 'Bearer'
     */
    public $schema = 'Bearer';

    /**
     * @inheritdoc
     *
     * @throws \craft\errors\SiteNotFoundException
     * @throws \yii\web\UnauthorizedHttpException
     */
    public function authenticate($user, $request, $response)
    {
        $authHeader = $request->getHeaders()->get('Authorization');
        if ($authHeader === null || preg_match('/^' . $this->schema . '\s+(.*?)$/', $authHeader, $matches) === false) {
            return null;
        }

        // Header does not match schema
        if (empty($matches)) {
            return null;
        }

        // Header schema is a match, but no token
        if (!isset($matches[1])) {
            $this->handleFailure($response);
        }

        // JWT token could not be claimed
        if (false === ($identity = Jwt::getInstance()->getIdentity()->claim($matches[1]))) {
            $this->handleFailure($response);
        }

        if ($this->canLogin($identity)) {
            $user->login($identity);
        }

        return $identity instanceof IdentityInterface ? $identity : true;
    }

    /**
     * @param IdentityInterface $identity
     * @return bool
     */
    protected function canLogin(IdentityInterface $identity = null): bool
    {
        if ($identity === null || empty($identity->getId())) {
            return false;
        }

        return $identity instanceof User && $identity->getStatus() === User::STATUS_ACTIVE;
    }

    /**
     * @inheritdoc
     */
    public function challenge($response)
    {
        $response->getHeaders()->set(
            'WWW-Authenticate',
            "{$this->schema} realm=\"{$this->realm}\", error=\"invalid_token\"," .
            " error_description=\"The access token invalid or expired\""
        );
    }
}
