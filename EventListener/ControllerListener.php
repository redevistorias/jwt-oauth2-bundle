<?php

namespace JwtOAuth2Bundle\EventListener;

use Doctrine\ORM\EntityManagerInterface;
use JwtOAuth2Bundle\Attribute\Authenticated;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\ResourceServer;
use Nyholm\Psr7\Factory\Psr17Factory;
use Symfony\Bridge\PsrHttpMessage\Factory\PsrHttpFactory;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\Exception\HttpException;
use Symfony\Component\HttpKernel\KernelEvents;
use JwtOAuth2Bundle\Repository\AccessTokenRepository;

class ControllerListener implements EventSubscriberInterface
{
    protected $container;
    private $em;

    public function __construct(ContainerInterface $container, EntityManagerInterface $em)
    {
        $this->container = $container;
        $this->em = $em;
    }

    public function onKernelController(ControllerEvent $event)
    {
        $controller = $event->getController();
        if (!is_array($controller)) {
            return;
        }
        $attribute = $this->getAttribute($controller);
        $authorizationRequired = $attribute !== null;
        if ($authorizationRequired) {
            $authorizedScopes = $this->getAuthorizedScopes($attribute);
            $authorizationData = $this->getAuthorizationData($event->getRequest());
            if ($authorizedScopes) {
                $this->checkIfRequestScopeIsAuthorized($authorizationData['scopes'], $authorizedScopes);
            }
            $this->addAuthorizationDataInRequest($event->getRequest(), $authorizationData);
        }
    }

    public static function getSubscribedEvents()
    {
        return [
            KernelEvents::CONTROLLER => 'onKernelController'
        ];
    }

    public function setConfig($repositoryName, $publicKey)
    {
        $this->repository = new $repositoryName();
        $this->publicKey = $publicKey;
    }

    private function getAuthorizedScopes($attribute)
    {
        return $attribute->getScopes();
    }

    private function getAttribute($controller)
    {
        $reflectionClass = new \ReflectionClass($controller[0]);
        $reflectionMethod = $reflectionClass->getMethod($controller[1]);

        $methodAttributes = $reflectionMethod->getAttributes(Authenticated::class);
        if (!empty($methodAttributes)) {
            return $methodAttributes[0]->newInstance();
        }

        $classAttributes = $reflectionClass->getAttributes(Authenticated::class);
        if (!empty($classAttributes)) {
            return $classAttributes[0]->newInstance();
        }

        return null;
    }

    private function getAuthorizationData(Request $request)
    {
        $publicKey = $this->container->getParameter('jwt_o_auth2.public_key.file');
        $accessTokenRepository = new AccessTokenRepository();
        if (!empty($this->container->hasParameter('jwt_o_auth2.access_token_repository.class'))) {
            $repositoryName = $this->container->getParameter('jwt_o_auth2.access_token_repository.class');
            $accessTokenRepository = $this->em->getRepository($repositoryName);
        }

        $server = new ResourceServer($accessTokenRepository, $publicKey);

        $psr17Factory = new Psr17Factory();
        $psrHttpFactory = new PsrHttpFactory($psr17Factory, $psr17Factory, $psr17Factory, $psr17Factory);
        $psr7Request = $psrHttpFactory->createRequest($request);
        try {
            $psr7Request = $server->validateAuthenticatedRequest($psr7Request);
        } catch (OAuthServerException $e) {
            throw new HttpException($e->getHttpStatusCode(), $e->getMessage());
        }

        return [
            'scopes'      => $psr7Request->getAttribute('oauth_scopes'),
            'client_id'   => $psr7Request->getAttribute('oauth_client_id'),
            'user_id'     => $psr7Request->getAttribute('oauth_user_id')
        ];
    }

    private function checkIfRequestScopeIsAuthorized($requestScopes, $authorizedScopes)
    {
        foreach ($requestScopes as $requestScope) {
            if (in_array($requestScope, $authorizedScopes)) {
                return true;
            }
        }
        throw new AccessDeniedHttpException("Access Denied by scope.");
    }

    private function addAuthorizationDataInRequest(Request $request, $authorizationData)
    {
        $request->request->add([
            'oauth_scopes'      => $authorizationData['scopes'],
            'oauth_client_id'   => $authorizationData['client_id'],
            'oauth_user_id'     => $authorizationData['user_id']
        ]);
    }
}
