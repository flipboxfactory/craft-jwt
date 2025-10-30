<?php

/**
 * @copyright  Copyright (c) Flipbox Digital Limited
 * @license    https://flipboxfactory.com/software/jwt/license
 * @link       https://www.flipboxfactory.com/jwt/organization/
 */

namespace flipbox\craft\jwt\models;

use Craft;
use craft\base\Model;
use craft\helpers\ConfigHelper;
use craft\helpers\UrlHelper;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Hmac\Sha384;
use Lcobucci\JWT\Signer\Hmac\Sha512;
use yii\base\InvalidArgumentException;

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
     * @var string|null
     */
    private ?string $key = null;

    /** The entity issuing the token
     *
     * @var string|null
     */
    private ?string $issuer = null;

    /**
     * The default audience
     *
     * @var string|null
     */
    private ?string $identityAudience = null;

    /**
     * The available audiences
     *
     * @var array
     */
    private array $identityIssuers = [];

    /**
     * The identity token duration.  Defaults to GeneralConfig::$userSessionDuration
     *
     * @var int|null
     */
    private ?int $identityTokenDuration;

    /**
     * The default identity token duration.  Used if a session duration is set to anything less than 0.
     *
     * @var int|float
     */
    public int|float $defaultTokenDuration = 60 * 60 * 24;


    /**
     * The default audience
     *
     * @var string|null
     */
    private ?string $routeAudience = null;

    /**
     * The available audiences
     *
     * @var array
     */
    private array $routeIssuers = [];

    /**
     * The self consumable token duration.  Defaults to GeneralConfig::$userSessionDuration
     *
     * @var int|null
     */
    private ?int $routeTokenDuration;


    /*******************************************
     * KEY
     *******************************************/

    /**
     * @param string|null $key
     * @return $this
     */
    public function setKey(string $key = null): static
    {
        $this->key = $key;
        return $this;
    }

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
    public function setIssuer(string $issuer = null): static
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
            return $this->getDefaultUrl();
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
    public function setIdentityTokenDuration($duration): static
    {
        $this->identityTokenDuration = $duration;
        return $this;
    }

    /**
     * @return int
     * @throws \yii\base\InvalidConfigException
     */
    public function getIdentityTokenDuration(): int
    {
        if ($this->identityTokenDuration === null) {
            $this->identityTokenDuration = Craft::$app->getConfig()->getGeneral()->userSessionDuration;
        }

        if ($this->identityTokenDuration <= 0) {
            $this->identityTokenDuration = $this->defaultTokenDuration;
        }

        return ConfigHelper::durationInSeconds($this->identityTokenDuration);
    }

    /**
     * @param array $issuers
     * @return $this
     */
    public function setIdentityIssuers(array $issuers = []): static
    {
        $this->identityIssuers = $issuers;
        return $this;
    }

    /**
     * @return array
     * @throws \craft\errors\SiteNotFoundException
     */
    public function getIdentityIssuers(): array
    {
        if (empty($this->identityIssuers)) {
            return [$this->getDefaultUrl()];
        }
        return (array)$this->identityIssuers;
    }

    /**
     * @param string|null $audience
     * @return $this
     */
    public function setIdentityAudience(string $audience = null): static
    {
        $this->identityAudience = $audience;
        return $this;
    }

    /**
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    public function getIdentityAudience(): string
    {
        if (null === $this->identityAudience) {
            return $this->getDefaultUrl();
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
    public function setRouteTokenDuration($duration): static
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
            $this->routeTokenDuration = $this->defaultTokenDuration;
        }

        return ConfigHelper::durationInSeconds($this->routeTokenDuration);
    }

    /**
     * @param string|null $audience
     * @return $this
     */
    public function setRouteAudience(string $audience = null): static
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
            return $this->getDefaultUrl();
        }
        return (string)$this->routeAudience;
    }

    /**
     * @param array $issuers
     * @return $this
     */
    public function setRouteIssuers(array $issuers = []): static
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
            return [$this->getDefaultUrl()];
        }
        return (array)$this->routeIssuers;
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

    /**
     * @return string
     * @throws \craft\errors\SiteNotFoundException
     */
    private function getDefaultUrl(): string
    {
        return Craft::$app->getSites()->getCurrentSite()->getBaseUrl() ?? UrlHelper::baseRequestUrl();
    }
}
