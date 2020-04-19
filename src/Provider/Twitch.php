<?php

namespace Depotwarehouse\OAuth2\Client\Twitch\Provider;

use Depotwarehouse\OAuth2\Client\Twitch\Entity\TwitchUser;
use League\OAuth2\Client\Provider\AbstractProvider;
use Depotwarehouse\OAuth2\Client\Twitch\Provider\Exception\TwitchIdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Psr\Http\Message\ResponseInterface;

class Twitch extends AbstractProvider
{
    const API_DOMAIN = 'https://id.twitch.tv';
    const AUTHORIZE_URL = self::API_DOMAIN . '/oauth2/authorize';
    const TOKEN_URL = self::API_DOMAIN . '/oauth2/token';

    /**
     * Get authorization url to begin OAuth flow
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return self::AUTHORIZE_URL;
    }

    /**
     * Get access token url to retrieve token
     *
     * @param  array $params
     *
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return self::TOKEN_URL;
    }

    /**
     * Get provider url to fetch user details
     *
     * @param  AccessToken $token
     *
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->getAuthenticatedUrlForEndpoint('/kraken/user', $token);
    }

    /**
     * Get the full uri with appended oauth_token query string
     *
     * @param string $endpoint | with leading slash
     * @param AccessToken $token
     * @return string
     */
    public function getAuthenticatedUrlForEndpoint($endpoint, AccessToken $token)
    {
        return self::API_DOMAIN.$endpoint.'?oauth_token='.$token->getToken();
    }

    /**
     * Get the full urls that do not require authentication
     *
     * @param $endpoint
     * @return string
     */
    public function getUrlForEndpoint($endpoint)
    {
        return self::API_DOMAIN.$endpoint;
    }

    protected function getScopeSeparator()
    {
        return ' ';
    }

    protected function getDefaultScopes()
    {
        return [];
    }

    /**
     * Checks response
     *
     * @param ResponseInterface $response
     * @param array|string $data
     * @throws \League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() >= 400)
        {
            throw TwitchIdentityProviderException::clientException($response, $data);
        }
        elseif (\array_key_exists('error', $data))
        {
            throw TwitchIdentityProviderException::oauthException($response, $data);
        }
    }

    /**
     * Generate a user object from a successful user details request.
     *
     * @param array $response
     * @param AccessToken $token
     * @return TwitchUser
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        return new TwitchUser((array) $response);
    }
}
