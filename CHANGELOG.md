Changelog
=========

## UNRELEASED
### Added
- Route token handling, you can create and execute a route based on a jwt token

### Changed
- `SelfConsumable` service class was renamed to `Identity`

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
