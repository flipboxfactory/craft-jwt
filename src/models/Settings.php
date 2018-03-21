<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\models;

use Craft;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha384;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use yii\base\InvalidArgumentException;
use yii\base\Model;

/**
 * @author Flipbox Factory <hello@flipboxfactory.com>
 * @since 1.0.0
 */
class Settings extends Model
{
    /**
     * Supported algorithms
     *
     * @var array
     */
    public $algorithms = [
        'HS256' => Sha256::class,
        'HS384' => Sha384::class,
        'HS512' => Sha512::class,
    ];

    /**
     * The selected algorithm
     *
     * @var string
     */
    public $algorithm = 'HS512';

    /**
     * The key used for token signature
     *
     * @var string
     */
    private $key;

    /**
     * The default token Expiration
     * @var int
     */
    public $tokenExpiration = 3600;

    /**
     * The default audience
     *
     * @var string
     */
    private $selfConsumableAudience = null;

    /**
     * The available audiences
     *
     * @var array
     */
    public $selfConsumableIssuers = [];

    /** The default target
     *
     * @var int
     */
    private $issuer = null;

    /**
     * @return string
     */
    public function getKey(): string
    {
        if (null === $this->key) {
            Craft::$app->getConfig()->getGeneral()->securityKey;
            throw new InvalidArgumentException("Key must be implemented");
        }
        return $this->key;
    }

    /**
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    public function getSelfConsumableAudience(): string
    {
        if (null === $this->selfConsumableAudience) {
            return Craft::$app->getSites()->getCurrentSite()->baseUrl;
        }
        return (string)$this->selfConsumableAudience;
    }

    /**
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    public function getIssuer(): string
    {
        if (null === $this->issuer) {
            return Craft::$app->getSites()->getCurrentSite()->baseUrl;
        }
        return (string)$this->issuer;
    }

    /**
     * Creates a Signer class based on the configured algorithm
     *
     * @return Signer
     * @throws \yii\base\InvalidConfigException
     */
    public function getSigner(): Signer
    {
        return $this->resolveSigner($this->algorithm);
    }

    /**
     * Resolves a Signer class based on an algorithm key
     *
     * @param $key
     * @return Signer
     * @throws \yii\base\InvalidConfigException
     */
    public function resolveSigner($key): Signer
    {
        if (empty($this->algorithms[$key])) {
            throw new InvalidArgumentException('Algorithm not supported');
        }

        /** @var Signer $signer */
        $signer = Craft::createObject(
            $this->algorithms[$key]
        );

        return $signer;
    }
}
