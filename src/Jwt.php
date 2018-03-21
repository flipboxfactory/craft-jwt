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
use flipbox\craft\jwt\services\SelfConsumable;
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
 * @method SettingsModel getSettings()
 */
class Jwt extends Plugin
{
    /**
     * @inheritdoc
     */
    public function init()
    {
        parent::init();

        // Twig variables
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
     * @return services\SelfConsumable
     */
    public function getSelfConsumable(): SelfConsumable
    {
        return $this->get('authorization');
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
     * Logs a trace message.
     * Trace messages are logged mainly for development purpose to see
     * the execution work flow of some code.
     * @param string $message the message to be logged.
     * @param string $category the category of the message.
     */
    public static function trace($message, string $category = null)
    {
        Craft::getLogger()->log($message, Logger::LEVEL_TRACE, self::normalizeCategory($category));
    }

    /**
     * Logs an error message.
     * An error message is typically logged when an unrecoverable error occurs
     * during the execution of an application.
     * @param string $message the message to be logged.
     * @param string $category the category of the message.
     */
    public static function error($message, string $category = null)
    {
        Craft::getLogger()->log($message, Logger::LEVEL_ERROR, self::normalizeCategory($category));
    }

    /**
     * Logs a warning message.
     * A warning message is typically logged when an error occurs while the execution
     * can still continue.
     * @param string $message the message to be logged.
     * @param string $category the category of the message.
     */
    public static function warning($message, string $category = null)
    {
        Craft::getLogger()->log($message, Logger::LEVEL_WARNING, self::normalizeCategory($category));
    }

    /**
     * Logs an informative message.
     * An informative message is typically logged by an application to keep record of
     * something important (e.g. an administrator logs in).
     * @param string $message the message to be logged.
     * @param string $category the category of the message.
     */
    public static function info($message, string $category = null)
    {
        Craft::getLogger()->log($message, Logger::LEVEL_INFO, self::normalizeCategory($category));
    }

    /**
     * @param string|null $category
     * @return string
     */
    private static function normalizeCategory(string $category = null)
    {
        $normalizedCategory = 'JWT';

        if ($category === null) {
            return $normalizedCategory;
        }

        return $normalizedCategory . ': ' . $category;
    }
}
