Changelog
=========

## Unreleased
### Fixed
- URL settings would throw an exception if Craft was not specifying a `baseUrl`.

### Changed
- Default identity token expiration duration is set to a default value if the Craft session duration is set to zero.

## 1.0.0 - 2019-09-30
> {warning} The 'SelfConsumable' service class has been renamed to 'Identity'.  Please change any references in your Plugins, Module or TWIG - such as `craft.jwt.selfConsumable.*` to `craft.jwt.identity.*`

### Added
- Route token handling, you can create and execute a route based on a jwt token

### Changed
- `SelfConsumable` service class was renamed to `Identity`
- The Authentication filter no longer performs a full login unless explicitly told to

## 1.0.0-rc.5 - 2018-10-29
### Fixed
- JwtHttpBearerAuth behavior was evaluating the incorrect 'active' status.

## 1.0.0-rc.4 - 2018-08-19
### Changed
- Self consumable service will now return a token even when a user is not logged in.

### Removed
- `Settings::$tokenDuration` has been deprecated.  Use `Settings::getSelfConsumableTokenDurationn()`

## 1.0.0-rc.3 - 2018-05-16
### Fixed
- Exception when 'Authorization Bearer' was the only header value passed (no token)

## 1.0.0-rc.2 - 2018-03-21
### Changed
- Authorization server name to SelfConsumable as it's targeted and more appropriate

### Added
- Logging to SelfConsumable verifications
- Issuer, Audience verifications
- Settings for SelfConsumable verifications

## 1.0.0-rc.1 - 2018-03-20
### Added
- icons

## 1.0.0-rc - 2018-03-20
Initial release.
