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
use Lcobucci\JWT\ClaimsFormatter;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Encoding\ChainedFormatter;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Builder;
use Lcobucci\JWT\Token\Parser;
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
    public static string $category = 'jwt';

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
     *
     * @return SettingsModel
     */
    public function createSettingsModel(): ?craft\base\Model
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
        return $this->get('identity');
    }

    /**
     * @noinspection PhpDocMissingThrowsInspection
     * @return services\Route
     */
    public function getRoute(): services\Route
    {
        /** @noinspection PhpUnhandledExceptionInspection */
        return $this->get('route');
    }

    /*******************************************
     * JWT
     *******************************************/

    /**
     * @param Encoder|null $encoder
     * @param ClaimsFormatter|null $claimFormatter
     *
     * @return Builder
     * @see [[Lcobucci\JWT\Builder::__construct()]]
     */
    public function getBuilder(Encoder|null $encoder = null, ClaimsFormatter|null $claimFormatter = null): Builder
    {
        return new Builder($encoder ?: new JoseEncoder(), $claimFormatter ?: ChainedFormatter::default());
    }

    /**
     * @param Decoder|null $decoder
     *
     * @return Parser
     * @see [[Lcobucci\JWT\Parser::__construct()]]
     */
    public function getParser(Decoder|null $decoder = null): Parser
    {
        return new Parser($decoder ?: new JoseEncoder());
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
    protected static function loggerCategory(string|null $category = null, bool $audit = false): string
    {
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
