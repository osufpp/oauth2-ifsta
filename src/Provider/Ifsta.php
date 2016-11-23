<?php namespace Osufpp\OAuth2\Client\Provider;

use Guzzle\Http\Exception\BadResponseException;
use League\OAuth2\Client\Entity\User;
use League\OAuth2\Client\Exception\IDPException;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Token\AccessToken;

class Ifsta extends AbstractProvider
{
    public $domain = 'https://auth-test.ifsta.org';
    public $uidKey = 'id';

    /**
     * Get authorization URL to begin OAuth flow
     *
     * @return string
     */
    public function urlAuthorize()
    {
        return $this->domain . '/dialog/authorize';
    }

    /**
     * Get access token URL to retrieve token
     *
     * @return string
     */
    public function urlAccessToken()
    {
        return $this->domain . '/oauth/token';
    }

    /**
     * Get provider URL to fetch user details
     *
     * @param AccessToken $token
     * @return string
     */
    public function urlUserDetails(\League\OAuth2\Client\Token\AccessToken $token)
    {
        return $this->domain . '/api/userinfo?access_token=' . $token;
    }

    /**
     * @param object $response
     * @param AccessToken $token
     * @return User
     */
    public function userDetails($response, \League\OAuth2\Client\Token\AccessToken $token)
    {
        $user = new User();

        $name = (isset($response->name)) ? $response->name : null;
        $firstName = (isset($name)) ? $name->givenName : null;
        $lastName = (isset($name)) ? $name->familyName : null;
        $emails = (isset($response->emails)) ? $response->emails : null;
        $email = ((isset($emails)) && (count($emails) > 0)) ? $emails[0]->value : null;
        $photos = (isset($response->photos)) ? $response->photos : null;
        $photo = ((isset($photos)) && (count($photos) > 0)) ? $photos[0]->value : null;

        $user->exchangeArray([
            'uid' => $response->id,
            'name' => $response->displayName,
            'firstname' => $firstName,
            'lastname' => $lastName,
            'email' => $email,
            'imageurl' => $photo
        ]);

        return $user;
    }
}
