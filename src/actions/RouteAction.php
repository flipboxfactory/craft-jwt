<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\actions;

use flipbox\craft\jwt\Jwt;
use yii\base\Action;
use Craft;
use yii\web\NotFoundHttpException;
use yii\web\Response;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 1.0.0
 */
class RouteAction extends Action
{
    /**
     * @param string $token
     * @return \craft\web\Response|int|\yii\console\Response|Response|null
     * @throws NotFoundHttpException
     * @throws \craft\errors\SiteNotFoundException
     * @throws \yii\base\InvalidRouteException
     * @throws \yii\console\Exception
     */
    public function run(string $token)
    {
        if(false === ($route = Jwt::getInstance()->getRoute()->claim($token))) {
            throw new NotFoundHttpException("Invalid token.");
        }

        $params = [];
        if (is_array($route)) {
            list($route, $params) = $route;
        }

        $result = Craft::$app->runAction($route, $params);

        if ($result instanceof Response) {
            return $result;
        }

        $response = Craft::$app->getResponse();
        if ($result !== null) {
            $response->data = $result;
        }

        return $response;
    }
}
