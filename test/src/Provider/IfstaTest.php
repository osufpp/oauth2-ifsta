<?php namespace Osufpp\OAuth2\Client\Test\Provider;

use Mockery as m;

class IfstaTest extends \PHPUnit_Framework_TestCase {
    protected $provider;

    protected function setUp() {
        $this->provider = new \Osufpp\OAuth2\Client\Provider\Ifsta([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'none',
        ]);
    }

    public function tearDown() {
        m::close();
        parent::tearDown();
    }

    public function testAuthorizationUrl() {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);
        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testScopes() {
        $options = ['scope' => [uniqid(), uniqid()]];
        $url = $this->provider->getAuthorizationUrl($options);
        $this->assertContains(urlencode(implode(',', $options['scope'])), $url);
    }

    public function testGetAuthorizationUrl() {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        $this->assertEquals('/dialog/authorize', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl() {
        $params = [];
        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);
        $this->assertEquals('/oauth/token', $uri['path']);
    }

    public function testGetAccessToken() {
        $response = m::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn('{"access_token":"mock_access_token", "scope":"repo,gist", "token_type":"bearer"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertNull($token->getExpires());
        $this->assertNull($token->getRefreshToken());
        $this->assertNull($token->getResourceOwnerId());
    }

    public function testUserData() {
        $userId = rand(1000, 9999);
        $familyName = uniqid();
        $givenName = uniqid();
        $displayName = uniqid();
        $email = uniqid();
        $imageUrl = uniqid();
        $response = json_decode('{"emails": [{"value": "' . $email . '"}],"id": ' . $userId . ',"displayName": "' . $displayName . '","name": {"familyName": "' . $familyName . '","givenName": "' . $givenName . '"},"photos": [{"value": "' . $imageUrl . '"}]}', true);
        $provider = m::mock('Osufpp\OAuth2\Client\Provider\Ifsta[fetchResourceOwnerDetails]')
            ->shouldAllowMockingProtectedMethods();
        $provider->shouldReceive('fetchResourceOwnerDetails')
            ->times(1)
            ->andReturn($response);
        $token = m::mock('League\OAuth2\Client\Token\AccessToken');
        $user = $provider->getResourceOwner($token);
        $this->assertInstanceOf('League\OAuth2\Client\Entity\User', $user);
        $this->assertEquals($userId, $user['uid']);
        $this->assertEquals($displayName, $user['name']);
        $this->assertEquals($givenName, $user['firstname']);
        $this->assertEquals($familyName, $user['lastname']);
        $this->assertEquals($email, $user['email']);
        $this->assertEquals($imageUrl, $user['imageurl']);
    }

}
