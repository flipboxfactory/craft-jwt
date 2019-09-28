<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\helpers;

use Craft;
use craft\helpers\User;
use yii\web\IdentityInterface;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 1.0.0
 */
class UserHelper extends User
{
    /**
     * @param $user
     * @return IdentityInterface|null
     */
    public static function resolveUser($user)
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
