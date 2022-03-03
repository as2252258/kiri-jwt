<?php
declare(strict_types=1);


namespace Kiri\Jwt;


use Kiri\Annotation\Inject;
use Kiri;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\NotFoundExceptionInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Kiri\Message\Constrict\ResponseInterface;
use ReflectionException;

/**
 * Class CoreMiddleware
 * @package Kiri\Route
 * 跨域中间件
 */
class JWTAuthMiddleware implements MiddlewareInterface
{


	/** @var int */
	public int $zOrder = 0;


	/**
	 * @param ResponseInterface $response
	 * @param JWTAuth $auth
	 */
	public function __construct(public ResponseInterface  $response, public JWTAuth $auth)
	{
	}


	/**
     * @param ServerRequestInterface $request
     * @param RequestHandlerInterface $handler
     * @return \Psr\Http\Message\ResponseInterface
     * @throws ContainerExceptionInterface
     * @throws NotFoundExceptionInterface
     */
	public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): \Psr\Http\Message\ResponseInterface
	{
		$authorization = $request->getHeaderLine('Authorization');
		if (empty($authorization)) {
			return $this->response->json(['code' => 401, 'JWT voucher cannot be empty.']);
		}
		if (!str_starts_with($authorization, 'Bearer ')) {
			return $this->response->json(['code' => 401, 'JWT Voucher Format Error.']);
		}
		$authorization = str_replace('Bearer ', '', $authorization);
		if (!$this->auth->validating($authorization)) {
			return $this->response->json(['code' => 401, 'JWT Validator fail.']);
		}
		return $handler->handle($request);
	}

}
