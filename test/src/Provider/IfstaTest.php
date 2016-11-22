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
        $response->shouldReceive('getBody')->times(1)->andReturn('{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');
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
        $postResponse = m::mock('Guzzle\Http\Message\Response');
        $postResponse->shouldReceive('getBody')->times(1)->andReturn('{"access_token": "mock_access_token", "expires": 3600, "refresh_token": "mock_refresh_token", "uid": 1}');
        $getResponse = m::mock('Guzzle\Http\Message\Response');
        $getResponse->shouldReceive('getBody')->times(4)->andReturn('{"emails": [{"value": "' . $email . '"}],"id": ' . $userId . ',"displayName": "' . $displayName . '","name": {"familyName": "' . $familyName . '","givenName": "' . $givenName . '"},"photos": [{"value": "' . $imageUrl . '"}]}');
        $client = m::mock('Guzzle\Service\Client');
        $client->shouldReceive('setBaseUrl')->times(5);
        $client->shouldReceive('setDefaultOption')->times(4);
        $client->shouldReceive('post->send')->times(1)->andReturn($postResponse);
        $client->shouldReceive('get->send')->times(4)->andReturn($getResponse);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getUserDetails($token);
        $this->assertEquals($userId, $this->provider->getUserUid($token));
        $this->assertEquals([$givenName, $familyName], $this->provider->getUserScreenName($token));
        $this->assertEquals($email, $this->provider->getUserEmail($token));
        $this->assertEquals($email, $user->email);
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
