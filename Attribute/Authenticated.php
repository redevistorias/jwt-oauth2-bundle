<?php

namespace JwtOAuth2Bundle\Attribute;

use Attribute;

#[Attribute(Attribute::TARGET_METHOD | Attribute::TARGET_CLASS)]
class Authenticated
{
    private $scopes;

    public function __construct(array $scopes = null)
    {
        $this->scopes = $scopes;
    }

    public function getScopes()
    {
        return $this->scopes;
    }
}