<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\filters;

use flipbox\craft\jwt\Jwt;
use yii\filters\auth\AuthMethod;

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
     */
    public function authenticate($user, $request, $response)
    {
        $authHeader = $request->getHeaders()->get('Authorization');
        if ($authHeader === null || preg_match('/^' . $this->schema . '\s+(.*?)$/', $authHeader, $matches) === false) {
            return null;
        }

        if (!isset($matches[1])) {
            $this->handleFailure($response);
        }

        if (null === ($identity = Jwt::getInstance()->getSelfConsumable()->claim($matches[1]))) {
            $this->handleFailure($response);
        }

        $user->login($identity);
        return $identity;
    }

    /**
     * @inheritdoc
     */
    public function challenge($response)
    {
        $response->getHeaders()->set(
            'WWW-Authenticate',
            "{$this->schema} realm=\"{$this->realm}\", error=\"invalid_token\",".
            " error_description=\"The access token invalid or expired\""
        );
    }
}
