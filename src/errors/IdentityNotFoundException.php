<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\errors;

use yii\base\Exception;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 5.0.0
 */
class IdentityNotFoundException extends Exception
{
    /**
     * @return string the user-friendly name of this exception
     */
    public function getName(): string
    {
        return 'Identity not found';
    }
}
