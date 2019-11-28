<?php

namespace Drupal\t_auth_provider\Form;

use Drupal\Core\Form\ConfigFormBase;
use Drupal\Core\Form\FormStateInterface;

/**
 * The Form Class
 */
class TAuthProviderForm extends ConfigFormBase {

  /**
   * @var string config settings
   */
  const SETTINGS = 't_auth_provider.settings';

  /**
   * {@inheritdoc}
   */
  public function getFormID() {
    return 't_auth_provider_form';
  }

  /**
   * {@inheritdoc}
   */
  public function buildForm(array $form, FormStateInterface $form_state) {
    //Default settings
    $config = $this->config(static::SETTINGS);

    $form['allowed_ip_consumers'] = [
      '#type' => 'textfield',
      '#title' => $this->t('Allowed IP Consumers:'),
      '#default_value' => $config->get('t_auth_provider.allowed_ip_consumers'),
      '#description' => $this->t('Place one IP address per line.')
    ];

    $options = [0 => t('Blacklist'), 1 => t('Whitelist')];
    $form['list_type'] = [
      '#type' => 'radios',
      '#title' => t('Type of IP list'),
      '#default_value' => $config->get('list_type'),
      '#options' => $options,
      '#description' => t('Define in what way the IP list will be used in Authorization logic.'),
      '#required' => TRUE
    ];

    return parent::buildForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function validate(array &$form, FromStateInterface $form_state) {

  }

  /**
   * {@inheritdoc}
   */
  public function submitForm(array &$form, FormStateInterface $form_state) {
    $this->configFactory->getEditable(static::SETTINGS)
      ->set('t_auth_provider.allowed_ip_consumers', $form_state->getValue('allowed_ip_consumers'))
      ->set('t_auth_provider.list_type', $form_state->getValue('list_type'))
      ->save();

    return parent::submitForm($form, $form_state);
  }

  /**
   * {@inheritdoc}
   */
  public function getEditableConfigNames() {
    return [static::SETTINGS];
  }
}
