# IFSTA Provider for OAuth 2.0 Client

[![Join the chat](https://img.shields.io/badge/gitter-join-1DCE73.svg)](https://gitter.im/osufpp/oauth2-ifsta)
[![Build Status](https://img.shields.io/travis/osufpp/oauth2-ifsta.svg)](https://travis-ci.org/osufpp/oauth2-ifsta)
[![Code Coverage](https://img.shields.io/coveralls/osufpp/oauth2-ifsta.svg)](https://coveralls.io/r/osufpp/oauth2-ifsta)
[![Code Quality](https://img.shields.io/scrutinizer/g/thephpleague/oauth2-google.svg)](https://scrutinizer-ci.com/g/thephpleague/oauth2-google/)
[![License](https://img.shields.io/packagist/l/osufpp/oauth2-ifsta.svg)](https://github.com/osufpp/oauth2-ifsta/blob/master/LICENSE)
[![Latest Stable Version](https://img.shields.io/packagist/v/osufpp/oauth2-ifsta.svg)](https://packagist.org/packages/osufpp/oauth2-ifsta)

This package provides IFSTA OAuth 2.0 support for the PHP League's [OAuth 2.0 Client](https://github.com/thephpleague/oauth2-client).

This package is compliant with [PSR-1][], [PSR-2][] and [PSR-4][]. If you notice compliance oversights, please send
a patch via pull request.

[PSR-1]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-1-basic-coding-standard.md
[PSR-2]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-2-coding-style-guide.md
[PSR-4]: https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-4-autoloader.md

## Requirements

The following versions of PHP are supported.

* PHP 5.5
* PHP 5.6
* PHP 7.0
* HHVM

## Installation

To install, use composer:

```
composer require osufpp/oauth2-ifsta
```

## Usage

### Authorization Code Flow

```php
$provider = new Osufpp\OAuth2\Client\Provider\Ifsta([
    'clientId'     => '{ifsta-client-id}',
    'clientSecret' => '{ifsta-client-secret}',
    'redirectUri'  => 'https://example.com/callback-url',
    'hostedDomain' => 'https://example.com',
]);

if (!empty($_GET['error'])) {

    // Got an error, probably user denied access
    exit('Got error: ' . htmlspecialchars($_GET['error'], ENT_QUOTES, 'UTF-8'));

} elseif (empty($_GET['code'])) {

    // If we don't have an authorization code then get one
    $authUrl = $provider->getAuthorizationUrl();
    $_SESSION['oauth2state'] = $provider->getState();
    header('Location: ' . $authUrl);
    exit;

} elseif (empty($_GET['state']) || ($_GET['state'] !== $_SESSION['oauth2state'])) {

    // State is invalid, possible CSRF attack in progress
    unset($_SESSION['oauth2state']);
    exit('Invalid state');

} else {

    // Try to get an access token (using the authorization code grant)
    $token = $provider->getAccessToken('authorization_code', [
        'code' => $_GET['code']
    ]);

    // Optional: Now you have a token you can look up a users profile data
    try {

        // We got an access token, let's now get the owner details
        $ownerDetails = $provider->getResourceOwner($token);

        // Use these details to create a new profile
        printf('Hello %s!', $ownerDetails->getFirstName());

    } catch (Exception $e) {

        // Failed to get user details
        exit('Something went wrong: ' . $e->getMessage());

    }

    // Use this to interact with an API on the users behalf
    echo $token->getToken();

    // Use this to get a new access token if the old one expires
    echo $token->getRefreshToken();

    // Number of seconds until the access token will expire, and need refreshing
    echo $token->getExpires();
}
```

## Testing

``` bash
$ ./vendor/bin/phpunit
```

## Contributing

Please see [CONTRIBUTING](https://github.com/osufpp/oauth2-ifsta/blob/master/CONTRIBUTING.md) for details.


## Credits

- [Aaron Bean](https://github.com/aaronbean)
- [All Contributors](https://github.com/osufpp/oauth2-ifsta/contributors)


## License

The MIT License (MIT). Please see [License File](https://github.com/thephpleague/oauth2-google/blob/master/LICENSE) for more information.
