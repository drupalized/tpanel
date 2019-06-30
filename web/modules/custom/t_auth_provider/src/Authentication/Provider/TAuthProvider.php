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
   * User Auth interface.
   * 
   * @var \Drupal\user\UserAuth
   */
  protected $userAuth;

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
  }

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container) {
    return new static(
      $container->get('google_login_handler.jwt_token_handler'),
      $container->get('entity_type.manager'),
      $container->get('user.auth')
    );
  }
  
  /**
   * {@inheritdoc}
   */
  public function applies(Request $request) {
    //if ($request->query->has('key'))
    return false;
    
  }

  /**
   * {@inheritdoc}
   */
  public function authenticate(Request $request) {

    //$user = $this->entityTypeManager->getStorage('user')->load(2);
    $user = \Drupal::service('user.auth')->authenticate('admin', 'admin');
    return user_load($user);
    //return $user;

    // $config = $this->configFactory->get('t_auth_provider.settings');
    // $allowed_ip_consumers = $config->get('allowed_ip_consumers');
    // // Determine if list of IP is a white list or black list
    // $type = $config->get('list_type');
    // $ips = array_map('trim', explode( "\n", $allowed_ip_consumers));
    // $consumer_ip = $request->getClientIp(TRUE);

    // // White list logic
    // if($type) {
    //   if (in_array($consumer_ip, $ips)) {
    //     return $this->entityTypeManager->getStorage('user')->load(1);
    //   }
    //   else {
    //     throw new AccessDeniedHttpException();
    //     return null;
    //   }
    // }
    // // Black list logic
    // else {
    //   if (!in_array($consumer_ip, $ips)) {
    //     return $this->entityTypeManager->getStorage('user')->load(1);
    //   }
    //   else {
    //     throw new AccessDeniedHttpException();
    //     return null;
    //   }
    // }
  }

  public function cleanup(Request $request) {
    
  }
  
}
