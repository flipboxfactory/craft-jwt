<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt;

use Craft;
use craft\base\Plugin;
use craft\web\twig\variables\CraftVariable;
use flipbox\craft\jwt\models\Settings as SettingsModel;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Claim\Factory as ClaimFactory;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Parsing\Decoder;
use Lcobucci\JWT\Parsing\Encoder;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\ValidationData;
use yii\base\Event;
use yii\log\Logger;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 1.0.0
 *
 * @property services\Identity identity
 * @property services\Route route
 *
 * @method SettingsModel getSettings()
 */
class Jwt extends Plugin
{
    /**
     * The plugin category
     *
     * @var string
     */
    public static $category = 'jwt';

    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();

        // Components
        $this->setComponents([
            'identity' => services\Identity::class,
            'route' => services\Route::class
        ]);

        // Template variables
        Event::on(
            CraftVariable::class,
            CraftVariable::EVENT_INIT,
            function (Event $event) {
                /** @var CraftVariable $variable */
                $variable = $event->sender;
                $variable->set('jwt', self::getInstance());
            }
        );
    }

    /**
     * @inheritdoc
     */
    public function createSettingsModel(): SettingsModel
    {
        return new SettingsModel();
    }

    /*******************************************
     * SERVICES
     *******************************************/

    /**
     * @noinspection PhpDocMissingThrowsInspection
     * @return services\Identity
     */
    public function getIdentity(): services\Identity
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        /** @noinspection PhpIncompatibleReturnTypeInspection */
        return $this->get('identity');
    }

    /**
     * @noinspection PhpDocMissingThrowsInspection
     * @return services\Route
     */
    public function getRoute(): services\Route
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        /** @noinspection PhpIncompatibleReturnTypeInspection */
        return $this->get('route');
    }

    /**
     * @deprecated
     */
    public function getSelfConsumable(): services\Identity
    {
        Craft::$app->getDeprecator()->log(
            self::class . '::getSelfConsumable',
            self::class . '::getSelfConsumable() has been deprecated. Use getIdentity() instead.'
        );
        return $this->getIdentity();
    }

    /*******************************************
     * JWT
     *******************************************/

    /**
     * @param Encoder|null $encoder
     * @param ClaimFactory|null $claimFactory
     *
     * @see [[Lcobucci\JWT\Builder::__construct()]]
     * @return Builder
     */
    public function getBuilder(Encoder $encoder = null, ClaimFactory $claimFactory = null): Builder
    {
        return new Builder($encoder, $claimFactory);
    }

    /**
     * @param Decoder|null $decoder
     * @param ClaimFactory|null $claimFactory
     *
     * @see [[Lcobucci\JWT\Parser::__construct()]]
     * @return Parser
     */
    public function getParser(Decoder $decoder = null, ClaimFactory $claimFactory = null): Parser
    {
        return new Parser($decoder, $claimFactory);
    }

    /**
     * @param int|null $currentTime
     *
     * @see [[Lcobucci\JWT\ValidationData::__construct()]]
     * @return ValidationData
     */
    public function getValidationData(int $currentTime = null): ValidationData
    {
        return new ValidationData($currentTime);
    }

    /**
     * @param Token $token
     * @param int|null $currentTime
     * @return bool
     */
    public function validateToken(Token $token, int $currentTime = null): bool
    {
        return $token->validate(
            $this->getValidationData($currentTime)
        );
    }


    /*******************************************
     * LOGGING
     *******************************************/

    /**
     * The log categories
     *
     * @param string|null $category
     * @param bool $audit flag as an audit message.
     * @return string
     */
    protected static function loggerCategory(string $category = null, bool $audit = false): string
    {
        /** @noinspection PhpUndefinedFieldInspection */
        $prefix = static::$category ? (static::$category . ($audit ? ':audit' : '')) : '';

        if (empty($category)) {
            return $prefix;
        }

        return ($prefix ? $prefix . ':' : '') . $category;
    }

    /**
     * Logs a debug message.
     * Trace messages are logged mainly for development purpose to see
     * the execution work flow of some code. This method will only log
     * a message when the application is in debug mode.
     * @param string|array $message the message to be logged. This can be a simple string or a more
     * complex data structure, such as array.
     * @param string $category the category of the message.
     * @param bool $audit flag as an audit message.
     * @since 2.0.0
     */
    public static function debug($message, $category = 'general', bool $audit = false)
    {
        Craft::getLogger()->log($message, Logger::LEVEL_TRACE, static::loggerCategory($category, $audit));
    }

    /**
     * Logs an error message.
     * An error message is typically logged when an unrecoverable error occurs
     * during the execution of an application.
     * @param string|array $message the message to be logged. This can be a simple string or a more
     * complex data structure, such as array.
     * @param string $category the category of the message.
     * @param bool $audit flag as an audit message.
     * @since 2.0.0
     */
    public static function error($message, $category = 'general', bool $audit = false)
    {
        Craft::getLogger()->log($message, Logger::LEVEL_ERROR, static::loggerCategory($category, $audit));
    }

    /**
     * Logs a warning message.
     * A warning message is typically logged when an error occurs while the execution
     * can still continue.
     * @param string|array $message the message to be logged. This can be a simple string or a more
     * complex data structure, such as array.
     * @param string $category the category of the message.
     * @param bool $audit flag as an audit message.
     * @since 2.0.0
     */
    public static function warning($message, $category = 'general', bool $audit = false)
    {
        Craft::getLogger()->log($message, Logger::LEVEL_WARNING, static::loggerCategory($category, $audit));
    }

    /**
     * Logs an informative message.
     * An informative message is typically logged by an application to keep record of
     * something important (e.g. an administrator logs in).
     * @param string|array $message the message to be logged. This can be a simple string or a more
     * complex data structure, such as array.
     * @param string $category the category of the message.
     * @param bool $audit flag as an audit message.
     * @since 2.0.0
     */
    public static function info($message, $category = 'general', bool $audit = false)
    {
        Craft::getLogger()->log($message, Logger::LEVEL_INFO, static::loggerCategory($category, $audit));
    }
}
