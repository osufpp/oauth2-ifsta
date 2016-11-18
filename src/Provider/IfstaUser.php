<?php namespace Osufpp\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\ResourceOwnerInterface;

class IfstaUser implements ResourceOwnerInterface {
    /**
     * @var array
     */
    protected $response;

    /**
     * @param array $response
     */
    public function __construct(array $response) {
        $this->response = $response;
    }

    public function getId() {
        return $this->response['id'];
    }

    /**
     * Get preferred display name.
     *
     * @return string
     */
    public function getName() {
        return $this->response['displayName'];
    }

    /**
     * Get preferred first name.
     *
     * @return string
     */
    public function getFirstName() {
        return $this->response['name']['givenName'];
    }

    /**
     * Get preferred last name.
     *
     * @return string
     */
    public function getLastName() {
        return $this->response['name']['familyName'];
    }

    /**
     * Get email address.
     *
     * @return string|null
     */
    public function getEmail() {
        if (!empty($this->response['emails'])) {
            return $this->response['emails'][0]['value'];
        }
    }

    /**
     * Get avatar image URL.
     *
     * @return string|null
     */
    public function getAvatar() {
        if (!empty($this->response['photos'])) {
            return $this->response['photos'][0]['value'];
        }
    }

    /**
     * Get user data as an array.
     *
     * @return array
     */
    public function toArray() {
        return $this->response;
    }
}
