<?php

namespace Kiri\Jwt;

use Database\Model;
use Exception;
use Kiri\Abstracts\Config;
use Kiri\Error\Logger;
use Kiri\Exception\ConfigException;
use Kiri\Kiri;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Hmac\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\StrictValidAt;
use Psr\Container\ContainerExceptionInterface;
use Psr\Container\ContainerInterface;
use Psr\Container\NotFoundExceptionInterface;

class JWTAuth implements JWTAuthInterface
{

	/**
	 * @var string
	 */
	public string $iss = 'http://example.com';

	/**
	 * @var string
	 */
	public string $aud = 'http://example.org';

	/**
	 * @var string
	 */
	public string $jti = '4f1g23a12aa';

	/**
	 * @var string
	 */
	private string $iat = \DateTimeImmutable::class;

	/**
	 * @var array
	 */
	public array $nbf = [1, 'second'];

	/**
	 * @var array|string[]
	 */
	public array $exp = [2, 'hour'];

	/**
	 * @var string
	 */
	public string $claim = 'userId';

	/**
	 * @var array|string[]
	 */
	public array $headers = ['foo' => 'bar'];


	/**
	 * @var string|Model
	 */
	public string|Model $model;


	/**
	 * @var Configuration
	 */
	private Configuration $configuration;


	/**
	 * @var ContainerInterface
	 */
	private ContainerInterface $container;


	/**
	 * @var Builder|null
	 */
	private ?Builder $builder = NULL;


	/**
	 * @var array
	 */
	public array $sso = [];


	/**
	 *
	 * @throws ConfigException
	 */
	public function init(): void
	{
		$this->configuration = Configuration::forSymmetricSigner(new Sha256(),
			InMemory::base64Encoded('mBC5v1sOKVvbdEitdSBenu59nfNfhwkedkJVNabosTw='));
		$this->configuration->setValidationConstraints(...[
			new SignedWith($this->configuration->signer(), $this->configuration->signingKey()),
			new StrictValidAt(new SystemClock(new \DateTimeZone('Asia/Shanghai'))),
		]);
		$this->container = Kiri::getDi();
		$this->configure();
	}


	/**
	 * @throws ConfigException
	 */
	private function configure()
	{
		$config = Config::get('jwt', []);
		if (empty($config)) {
			return;
		}
		Kiri::configure($this, $config);
	}


	/**
	 * @param $key
	 * @param $value
	 * @return $this
	 */
	public function withHeader($key, $value): static
	{
		$this->headers[$key] = $value;
		return $this;
	}


	/**
	 * @param int|string|null $value
	 * @return string
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 */
	public function create(int|string $value = NULL): string
	{
		if (!$this->builder) {
			$this->_create();
		}
		return $this->builder->withClaim($this->claim, $value)
			->getToken($this->configuration->signer(), $this->configuration->signingKey())
			->toString();
	}


	/**
	 * @param string $jwt
	 * @return string
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 * @throws Exception
	 */
	public function refresh(string $jwt): string
	{
		$value = $this->getUniqueId($jwt);

		return $this->create($value);
	}


	/**
	 * @param string $jwt
	 * @return UnencryptedToken
	 * @throws Exception
	 */
	public function parsing(string $jwt): UnencryptedToken
	{
		$parsing = $this->configuration->parser()->parse($jwt);

		assert($parsing instanceof UnencryptedToken);

		return $parsing;
	}


	/**
	 * @param string $jwt
	 * @return int|string
	 * @throws Exception
	 */
	public function getUniqueId(string $jwt): int|string
	{
		return $this->parsing($jwt)->claims()->get($this->claim);
	}


	/**
	 * @param string $jwt
	 * @param array $constraints
	 * @return bool|UnencryptedToken
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 */
	public function validating(string $jwt, array $constraints = []): bool|UnencryptedToken
	{
		try {
			$parse = $this->parsing($jwt);
			if (empty($constraints)) {
				$constraints = $this->configuration->validationConstraints();
			}
			$bool = $this->configuration->validator()->validate($parse, ...$constraints);
			if (!$bool) {
				return FALSE;
			}
			return $parse;
		} catch (\Throwable $e) {
			$this->container->get(Logger::class)->error($e->getMessage());
			return FALSE;
		}
	}


	/**
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 */
	private function _create(): void
	{
		$this->builder = $this->configuration->builder()->issuedBy($this->iss)
			->permittedFor($this->aud)->identifiedBy($this->jti)
			->withClaim($this->claim, 1)
			->withHeader('foo', 'bar');

		$this->_date();
		if (empty($this->headers) || !is_array($this->headers)) {
			return;
		}
		foreach ($this->headers as $key => $header) {
			$this->builder->withHeader($key, $header);
		}
	}


	/**
	 * @throws ContainerExceptionInterface
	 * @throws NotFoundExceptionInterface
	 */
	private function _date(): void
	{
		/** @var \DateTimeImmutable $dateTimeImmutable */
		$dateTimeImmutable = $this->container->get($this->iat);
		$this->builder->issuedAt($dateTimeImmutable);
		if (is_array($this->nbf) && count($this->nbf) == 2) {
			[$nb1, $nb2] = $this->nbf;
			$this->builder->canOnlyBeUsedAfter($dateTimeImmutable->modify('+' . $nb1 . ' ' . $nb2));
		}
		if (is_array($this->exp) && count($this->exp) == 2) {
			[$nb1, $nb2] = $this->exp;
			$this->builder->expiresAt($dateTimeImmutable->modify('+' . $nb1 . ' ' . $nb2));
		}
	}


}
