<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\services;

use flipbox\craft\jwt\helpers\TokenHelper;

/**
 * @deprecated - Use the Identity class
 */
class SelfConsumable extends Identity
{
    /**
     * The CSRF claim identifier
     * @deprecated
     */
    const CLAIM_CSRF = TokenHelper::CLAIM_CSRF;

    /**
     * The Audience claim identifier
     * @deprecated
     */
    const CLAIM_AUDIENCE = TokenHelper::CLAIM_AUDIENCE;

    /**
     * The Issuer claim identifier
     * @deprecated
     */
    const CLAIM_ISSUER = TokenHelper::CLAIM_ISSUER;

    /**
     * The Identity claim identifier
     * @deprecated
     */
    const CLAIM_IDENTITY = TokenHelper::CLAIM_IDENTITY;
}
