<?php

namespace JwtOAuth2Bundle\Repository;

use JwtOAuth2Bundle\Entity\AccessTokenEntity;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
    }

    public function revokeAccessToken(string $tokenId): void
    {
    }

    public function isAccessTokenRevoked($tokenId): bool
    {
        return false;
    }

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
    {
        $accessToken = new AccessTokenEntity();

        $accessToken->setClient($clientEntity);

        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        if ($userIdentifier !== null) {
            $accessToken->setUserIdentifier((string) $userIdentifier);
        }

        return $accessToken;
    }
}
