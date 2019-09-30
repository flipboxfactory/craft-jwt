# JWT Tokens for Craft CMS
[![Join the chat at https://gitter.im/flipboxfactory/craft-jwt](https://badges.gitter.im/flipboxfactory/craft-jwt.svg)](https://gitter.im/flipboxfactory/craft-jwt?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)
[![Latest Version](https://img.shields.io/github/release/flipboxfactory/craft-jwt.svg?style=flat-square)](https://github.com/flipboxfactory/craft-jwt/releases)
[![Software License](https://img.shields.io/badge/license-MIT-brightgreen.svg?style=flat-square)](LICENSE.md)
[![Build Status](https://img.shields.io/travis/flipboxfactory/craft-jwt/master.svg?style=flat-square)](https://travis-ci.com/flipboxfactory/craft-jwt)
[![Coverage Status](https://img.shields.io/scrutinizer/coverage/g/flipboxfactory/craft-jwt.svg?style=flat-square)](https://scrutinizer-ci.com/g/flipboxfactory/craft-jwt/code-structure)
[![Quality Score](https://img.shields.io/scrutinizer/g/flipboxfactory/craft-jwt.svg?style=flat-square)](https://scrutinizer-ci.com/g/flipboxfactory/craft-jwt)
[![Total Downloads](https://img.shields.io/packagist/dt/flipboxfactory/craft-jwt.svg?style=flat-square)](https://packagist.org/packages/flipboxfactory/craft-jwt)

JWT (JSON Web Token) for Craft CMS assists in issuing and claiming tokens.  The intent is to issue a token which, at a later time, can be claimed and used to perform various actions.  
The life of a JWT is defined upon creation and 

## Use Cases
* Protected downloads
* Protected pages/content
* Authorization to API
* Tracking actions (by user)
* Sharing downloads/pages to guests

To learn more about JWT visit [JWT.IO](https://jwt.io/introduction/)

## Requirements
This plugin requires Craft CMS 3.0 or later.

## Installation

Simply run the following command from your project root:

```
composer require flipboxfactory/craft-jwt
```

Once the plugin is included in your project, navigate to the Control Panel, go to Settings → Plugins and click the “Install” button for the [JWT Plugin].

### Templating
The `craft.jwt` template variable provides access to the entire [JWT] plugin.  To access the services, you may use:

Identity Service:
```twig
{% set token = craft.jwt.identity.issue(currentUser) %} {# To generate a token (store the identity) #}
{% set claim = craft.jwt.identity.claim(token|trim) %} {# To claim a token (retrieve the identity) #}
```

Route Service:
```twig
{% set token = craft.jwt.route.issue('action/path') %} {# To generate a token (store the action path) #}
{% set claim = craft.jwt.route.claim(token|trim) %} {# To claim a token (retrieve the action path) #}
```

## Examples
Common usages of this plugin are as follows:

### Self-Consumable API (Hybrid API - calling your own API)
Making calls to your own API is a great candidate for JWT Identity tokens.  The flow works something like this:
1. Set a JavaScript variable: `let jwt = '{{ craft.jwt.identity.issue(currentUser) }}'`
2. Using [Axois](https://github.com/axios/axios) (or other HTTP client library), make a call to your own API using the JWT token created in step 1.
3. Apply the Authentication filter to your API controller(s).
```php
/**
 * @inheritdoc
 */
public function behaviors()
{
    return \craft\helpers\ArrayHelper::merge(
        parent::behaviors(),
        [
            'authenticator' => [
                'authMethods' => [
                    \flipbox\craft\jwt\filters\JwtHttpBearerAuth::class
                ]
            ]
        ]
    );
}
```
A full example of the Authentication filter implementation can be found in our [RESTful API for Craft CMS](https://github.com/flipboxfactory/craft-restful/blob/master/src/controllers/AbstractController.php)


### Protected Downloads (or page access)
Perhaps a user needs to access a protected page or file download.  To circumvent exposing the url publicly, issue a JWT Route token. 

##### Render template: 
```twig
{% set token  = craft.jwt.route.issue(['templates/render', {'template': '_protected/template'}], currentUser)
{# the link will automatically render the template #}
<a href="{{ actionUrl("jwt/route", {jwt: token|trim}) }}">View Protected Page</a>
```

##### File Download
```twig
{% set asset = craft.assets.one() %}
{% set token  = craft.jwt.route.issue(['assets/thumb', {'uid': asset.uid, width: 100, height: 100}], currentUser) %}
<a href="{{ actionUrl("jwt/route", {jwt: token|trim}) }}">Download Protected File</a>
```

Note: It's important to note that in the File Download example, we're also passing the `currentUser` param when generating
the token.  As a result, when the action is processed we're assuming the identity of the user who issued the token prior to performing the action.  This means a user
doesn't have to be logged in to Craft.


## Caution
JWTs created by this plugin are technically JWS (JSON Web Signature) tokens.  The contents of a token can be 
easily decoded and viewed using tools such as [jwt.io](https://jwt.io).  It is important **NOT** to store sensitive data
in a token.  The Craft '[security key](https://docs.craftcms.com/v3/installation.html#step-3-set-a-security-key)' is used to sign each token; ensuring the contents have not been
tampered with.

A token is valid for 

## Contributing
Please see [CONTRIBUTING](https://github.com/flipboxfactory/craft-jwt/blob/master/CONTRIBUTING.md) for details.

## Credits
- [Flipbox Digital](https://github.com/flipbox)

## License
The MIT License (MIT). Please see [License File](https://github.com/flipboxfactory/craft-jwt/blob/master/LICENSE) for more information.

[Plugin Store]: https://plugins.craftcms.com/jwt
[JWT for Craft CMS]: https://github.com/flipboxfactory/craft-jwt
[JWT]: https://github.com/flipboxfactory/craft-jwt
[JWT Plugin]: https://github.com/flipboxfactory/craft-jwt