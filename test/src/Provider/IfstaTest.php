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
        $this->assertNotNull($this->provider->state);
    }

    public function testUrlAccessToken() {
        $url = $this->provider->urlAccessToken();
        $uri = parse_url($url);
        $this->assertEquals('/oauth/token', $uri['path']);
    }

    public function testGetAccessToken() {
        $response = m::mock('Guzzle\Http\Message\Response');
        $response->shouldReceive('getBody')->times(1)->andReturn('access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&uid=1');
        $client = m::mock('Guzzle\Service\Client');
        $client->shouldReceive('setBaseUrl')->times(1);
        $client->shouldReceive('post->send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $this->assertEquals('mock_access_token', $token->accessToken);
        $this->assertLessThanOrEqual(time() + 3600, $token->expires);
        $this->assertGreaterThanOrEqual(time(), $token->expires);
        $this->assertEquals('mock_refresh_token', $token->refreshToken);
        $this->assertEquals('1', $token->uid);
    }

    /**
     * @ticket 230
     * @expectedException \InvalidArgumentException
     * @expectedExceptionMessage Required option not passed: access_token
     */
    public function testGetAccessTokenWithInvalidJson() {
        $response = m::mock('Guzzle\Http\Message\Response');
        $response->shouldReceive('getBody')->times(1)->andReturn('invalid');
        $client = m::mock('Guzzle\Service\Client');
        $client->shouldReceive('setBaseUrl')->times(1);
        $client->shouldReceive('post->send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $this->provider->responseType = 'json';
        $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }

    public function testGetAccessTokenSetResultUid() {
        $this->provider->uidKey = 'otherKey';
        $response = m::mock('Guzzle\Http\Message\Response');
        $response->shouldReceive('getBody')->times(1)->andReturn('access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&otherKey={1234}');
        $client = m::mock('Guzzle\Service\Client');
        $client->shouldReceive('setBaseUrl')->times(1);
        $client->shouldReceive('post->send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $this->assertEquals('mock_access_token', $token->accessToken);
        $this->assertLessThanOrEqual(time() + 3600, $token->expires);
        $this->assertGreaterThanOrEqual(time(), $token->expires);
        $this->assertEquals('mock_refresh_token', $token->refreshToken);
        $this->assertEquals('{1234}', $token->uid);
    }

    public function testScopes() {
        $this->provider->setScopes(['user', 'repo']);
        $this->assertEquals(['user', 'repo'], $this->provider->getScopes());
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
        $user = $provider->getUserDetails($token);
        $this->assertInstanceOf('League\OAuth2\Client\Entity\User', $user);
        $this->assertEquals($userId, $user['uid']);
        $this->assertEquals($displayName, $user['name']);
        $this->assertEquals($givenName, $user['firstname']);
        $this->assertEquals($familyName, $user['lastname']);
        $this->assertEquals($email, $user['email']);
        $this->assertEquals($imageUrl, $user['imageurl']);
    }

    public function testGetAuthorizationUrl() {
        $url = $this->provider->urlAuthorize();
        $uri = parse_url($url);
        $this->assertEquals('/dialog/authorize', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl() {
        $url = $this->provider->urlAccessToken();
        $uri = parse_url($url);
        $this->assertEquals('/oauth/token', $uri['path']);
    }

}
