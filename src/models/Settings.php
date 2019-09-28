<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\models;

use Craft;
use craft\helpers\ConfigHelper;
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

    /** The entity issuing the token
     *
     * @var string
     */
    private $issuer = null;

    /**
     * The default audience
     *
     * @var string
     */
    private $identityAudience = null;

    /**
     * The available audiences
     *
     * @var array
     */
    private $identityIssuers = [];

    /**
     * The self consumable token duration.  Defaults to GeneralConfig::$userSessionDuration
     *
     * @var int
     */
    private $identityTokenDuration;


    /**
     * The default audience
     *
     * @var string
     */
    private $routeAudience = null;

    /**
     * The available audiences
     *
     * @var array
     */
    private $routeIssuers = [];

    /**
     * The self consumable token duration.  Defaults to GeneralConfig::$userSessionDuration
     *
     * @var int
     */
    private $routeTokenDuration;


    /*******************************************
     * KEY
     *******************************************/

    /**
     * @return string
     */
    public function getKey(): string
    {
        if (empty($this->key)) {
            return Craft::$app->getConfig()->getGeneral()->securityKey;
        }
        return $this->key;
    }


    /*******************************************
     * ISSUER
     *******************************************/

    /**
     * @param string|null $issuer
     * @return $this
     */
    public function setIssuer(string $issuer = null)
    {
        $this->issuer = $issuer;
        return $this;
    }

    /**
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    public function getIssuer(): string
    {
        if (null === $this->issuer) {
            return Craft::$app->getSites()->getCurrentSite()->getBaseUrl();
        }
        return (string)$this->issuer;
    }


    /*******************************************
     * SIGNER
     *******************************************/

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


    /*******************************************
     * IDENTITY
     *******************************************/

    /**
     * @param $duration
     * @return $this
     */
    public function setIdentityTokenDuration($duration)
    {
        $this->identityTokenDuration = $duration;
        return $this;
    }

    /**
     * @return int
     * @throws \yii\base\InvalidConfigException
     *
     * @deprecated
     */
    public function getSelfConsumableTokenDuration(): int
    {
        return $this->getIdentityTokenDuration();
    }

    /**
     * @return int
     * @throws \yii\base\InvalidConfigException
     */
    public function getIdentityTokenDuration(): int
    {
        if ($this->identityTokenDuration === null) {
            $this->identityTokenDuration = Craft::$app->getConfig()->getGeneral()->userSessionDuration;
        };

        return ConfigHelper::durationInSeconds($this->identityTokenDuration);
    }


    /**
     * @param array|null $issuers
     * @return $this
     *
     * @deprecated
     */
    public function setSelfConsumableIssuers(array $issuers = [])
    {
        return $this->setIdentityIssuers($issuers);
    }

    /**
     * @param array|null $issuers
     * @return $this
     */
    public function setIdentityIssuers(array $issuers = [])
    {
        $this->identityIssuers = $issuers;
        return $this;
    }

    /**
     * @return array
     * @throws \craft\errors\SiteNotFoundException
     *
     * @deprecated
     */
    public function getSelfConsumableIssuers(): array
    {
        return $this->getIdentityIssuers();
    }

    /**
     * @return array
     * @throws \craft\errors\SiteNotFoundException
     */
    public function getIdentityIssuers(): array
    {
        if (empty($this->identityIssuers)) {
            return [Craft::$app->getSites()->getCurrentSite()->getBaseUrl()];
        }
        return (array)$this->identityIssuers;
    }


    /**
     * @param string|null $audience
     * @return $this
     *
     * @deprecated
     */
    public function setSelfConsumableAudience(string $audience = null)
    {
        return $this->setIdentityAudience($audience);
    }

    /**
     * @param string|null $audience
     * @return $this
     */
    public function setIdentityAudience(string $audience = null)
    {
        $this->identityAudience = $audience;
        return $this;
    }

    /**
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     *
     * @deprecated
     */
    public function getSelfConsumableAudience(): string
    {
        return $this->getIdentityAudience();
    }

    /**
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    public function getIdentityAudience(): string
    {
        if (null === $this->identityAudience) {
            return Craft::$app->getSites()->getCurrentSite()->getBaseUrl();
        }
        return (string)$this->identityAudience;
    }


    /*******************************************
     * ROUTE
     *******************************************/

    /**
     * @param $duration
     * @return $this
     */
    public function setRouteTokenDuration($duration)
    {
        $this->routeTokenDuration = $duration;
        return $this;
    }

    /**
     * @return int
     * @throws \yii\base\InvalidConfigException
     */
    public function getRouteTokenDuration(): int
    {
        if ($this->routeTokenDuration === null) {
            $this->routeTokenDuration = Craft::$app->getConfig()->getGeneral()->userSessionDuration;
        };

        return ConfigHelper::durationInSeconds($this->routeTokenDuration);
    }

    /**
     * @param string|null $audience
     * @return $this
     */
    public function setRouteAudience(string $audience = null)
    {
        $this->routeAudience = $audience;
        return $this;
    }

    /**
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    public function getRouteAudience(): string
    {
        if (null === $this->routeAudience) {
            return Craft::$app->getSites()->getCurrentSite()->getBaseUrl();
        }
        return (string)$this->routeAudience;
    }

    /**
     * @param array|null $issuers
     * @return $this
     */
    public function setRouteIssuers(array $issuers = [])
    {
        $this->routeIssuers = $issuers;
        return $this;
    }

    /**
     * @return array
     * @throws \craft\errors\SiteNotFoundException
     */
    public function getRouteIssuers(): array
    {
        if (empty($this->routeIssuers)) {
            return [Craft::$app->getSites()->getCurrentSite()->getBaseUrl()];
        }
        return (array)$this->routeIssuers;
    }
    

    /*******************************************
     * SELF CONSUMABLE AUDIENCE
     *******************************************/
    /**
     * @param int $duration
     * @return $this
     *
     * @deprecated
     */
    public function setTokenExpiration(int $duration)
    {
        $this->identityTokenDuration = $duration;
        return $this;
    }

    /*******************************************
     * ATTRIBUTES
     *******************************************/

    /**
     * @inheritdoc
     */
    public function attributes()
    {
        return array_merge(
            parent::attributes(),
            [
                'key',
                'identityTokenExpiration',
                'identityAudience',
                'identityIssuers',
                'routeTokenExpiration',
                'routeAudience',
                'routeIssuers',
                'issuer'
            ]
        );
    }
}
