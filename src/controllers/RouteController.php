<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\controllers;

use Craft;
use craft\web\Controller;
use flipbox\craft\jwt\actions\RouteAction;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 1.2.0
 */
class RouteController extends Controller
{
    /**
     * @inheritdoc
     */
    protected int|bool|array $allowAnonymous = ['index'];

    /**
     * @param string|null $jwt
     * @return mixed
     * @throws \yii\base\InvalidConfigException
     * @throws \yii\web\BadRequestHttpException
     */
    public function actionIndex(string|null $jwt = null): mixed
    {
        $jwt = $jwt ?? Craft::$app->getRequest()->getRequiredParam('jwt');

        /** @var RouteAction $action */
        $action = Craft::createObject([
            'class' => RouteAction::class
        ], [
            'index',
            $this
        ]);

        return $action->runWithParams([
            'token' => $jwt
        ]);
    }
}
