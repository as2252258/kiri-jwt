<?php

namespace Kiri\Jwt;

use Lcobucci\JWT\UnencryptedToken;


/**
 * @mixin JWTAuth
 */
interface JWTAuthInterface
{


    /**
     * @param string $jwt
     * @return UnencryptedToken
     */
    public function parsing(string $jwt): UnencryptedToken;


    /**
     * @param string $jwt
     * @param array $constraints
     * @return bool|UnencryptedToken
     */
    public function validating(string $jwt, array $constraints = []): bool|UnencryptedToken;


    /**
     * @param string $jwt
     * @return string
     */
    public function refresh(string $jwt): string;


    /**
     * @param string $value
     * @return string
     */
    public function create(string $value): string;


    /**
     * @param string $jwt
     * @return int|string
     */
    public function getUniqueId(string $jwt): int|string;


}
