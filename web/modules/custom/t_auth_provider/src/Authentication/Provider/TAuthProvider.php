<?php

namespace Drupal\t_auth_provider\Authentication\Provider;

use Drupal\Core\Authentication\AuthenticationProviderInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\google_login_handler\JwtTokenHandlerService;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\DependencyInjection\ContainerInterface;
use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException;



/**
 * Class that handles the authentication process
 */
class TAuthProvider implements AuthenticationProviderInterface {

  /**
   * The config factory.
   *
   * @var \Drupal\Core\Config\ConfigFactoryInterface
   */
  protected $configFactory;

  /**
   * The entity type manager.
   *
   * @var \Drupal\Core\Entity\EntityTypeManagerInterface
   */
  protected $entityTypeManager;

  /**
   * The JWT Token service.
   *
   * @var \Drupal\google_login_handler\JwtTokenHandlerService
   */
  protected $jwtTokenService;

  /**
   * Constructs a HTTP basic authentication provider object.
   *
   * @param \Drupal\Core\Config\ConfigFactoryInterface $config_factory
   *   The config factory.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entity_type_manager
   *   The entity manager service.
   */
  public function __construct(ConfigFactoryInterface $config_factory, EntityTypeManagerInterface $entity_type_manager) {
    $this->configFactory = $config_factory;
    $this->entityTypeManager = $entity_type_manager;
    $this->jwtTokenService = \Drupal::service('google_login_handler.jwt_token_handler');
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('google_login_handler.jwt_token_handler'),
      $container->get('entity_type.manager')
    );
  }

  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    $auth = $request->headers->get('x-access-token');
    return preg_match('/^Bearer .+/', $auth);
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {

    $config = $this->configFactory->get('t_auth_provider.settings');
    $allowed_ip_consumers = $config->get('allowed_ip_consumers');

    // Determine if list of IP is a white list or black list
    $whitelisted = $config->get('list_type');
    $ip_list = array_map('trim', explode("\n", $allowed_ip_consumers));
    $consumer_ip = $request->getClientIp(TRUE);
    $token = $request->headers->get('x-access-token');

    // White list logic
    if ($whitelisted) {
      if (in_array($consumer_ip, $ip_list)) {
        $user_uuid = $this->jwtTokenService->validate_request_token($token);
        if(!$user_uuid) {
          return null;
        }
        return $this->entityTypeManager->getStorage('user')->load(0);
      }
      else {
        throw new AccessDeniedHttpException();
        return null;
      }
    }
    // Black list logic
    else {
      if (!in_array($consumer_ip, $ip_list)) {
        $user_uuid = $this->jwtTokenService->validate_request_token($token);
        if(!$user_uuid) {
          return null;
        }
        return $this->entityTypeManager->getStorage('user')->load(0);
      }
      else {
        throw new AccessDeniedHttpException();
        return null;
      }
    }
  }

  public function cleanup(Request $request) {

  }

  /**
   * {@inheritdoc}
   */
  public function handleException(GetResponseForExceptionEvent $event) {
    $exception = $event->getException();
    if($exception instanceof AccessDeniedHttpException) {
      $event->setException(new UnauthorizedHttpException('Invalid consumer origin.', $exception));

      return true;
    }
    return false;
  }

}
