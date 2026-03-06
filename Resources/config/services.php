<?php

use JwtOAuth2Bundle\EventListener\ControllerListener;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

return static function (ContainerConfigurator $container): void {
    $parameters = $container->parameters();
    $parameters->set('jwt_o_auth2.access_token_repository.class', '');
    $parameters->set('jwt_o_auth2.public_key.file', '');

    $services = $container->services();
    $services->set('jwt_o_auth2.controller.listener', ControllerListener::class)
        ->tag('kernel.event_subscriber')
        ->args([
            service('parameter_bag'),
            service('doctrine.orm.entity_manager'),
        ])
        ->public(false);
};
