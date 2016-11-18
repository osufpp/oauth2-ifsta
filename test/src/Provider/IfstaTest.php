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
        $this->assertEquals('/login/oauth/authorize', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl() {
        $params = [];
        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);
        $this->assertEquals('/login/oauth/access_token', $uri['path']);
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
        $this->assertInstanceOf('League\OAuth2\Client\Provider\ResourceOwnerInterface', $user);
        $this->assertEquals($userId, $user->getId());
        $this->assertEquals($displayName, $user->getName());
        $this->assertEquals($givenName, $user->getFirstName());
        $this->assertEquals($familyName, $user->getLastName());
        $this->assertEquals($email, $user->getEmail());
        $this->assertEquals($imageUrl, $user->getAvatar());
        $user = $user->toArray();
        $this->assertArrayHasKey('id', $user);
        $this->assertArrayHasKey('displayName', $user);
        $this->assertArrayHasKey('emails', $user);
        $this->assertArrayHasKey('photos', $user);
        $this->assertArrayHasKey('name', $user);
    }

    /**
     * @expectedException League\OAuth2\Client\Provider\Exception\IdentityProviderException
     **/
    public function testExceptionThrownWhenErrorObjectReceived() {
        $status = rand(400, 600);
        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')->andReturn('{"message": "Validation Failed","errors": [{"resource": "Issue","field": "title","code": "missing_field"}]}');
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $postResponse->shouldReceive('getStatusCode')->andReturn($status);
        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn($postResponse);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }

    /**
     * @expectedException League\OAuth2\Client\Provider\Exception\IdentityProviderException
     **/
    public function testExceptionThrownWhenOAuthErrorReceived() {
        $status = 200;
        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')->andReturn('{"error": "bad_verification_code","error_description": "The code passed is incorrect or expired.","error_uri": "https://developer.github.com/v3/oauth/#bad-verification-code"}');
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $postResponse->shouldReceive('getStatusCode')->andReturn($status);
        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn($postResponse);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }
}
