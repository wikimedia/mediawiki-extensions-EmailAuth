<?php

namespace MediaWiki\Extension\EmailAuth\AccountRecovery\Special;

use FormSpecialPage;
use MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk\ZendeskClient;
use MediaWiki\Parser\Sanitizer;
use MediaWiki\Status\Status;

class SpecialAccountRecovery extends FormSpecialPage {

	private ZendeskClient $zendeskClient;

	public function __construct( ZendeskClient $zendeskClient ) {
		parent::__construct( 'AccountRecovery' );
		$this->zendeskClient = $zendeskClient;
	}

	/**
	 * Do not list this special page on Special:SpecialPages.
	 *
	 * @return bool
	 */
	public function isListed() {
		return false;
	}

	/**
	 * Restrict this page to logged-out users only.
	 * Logged-in users don't need account recovery.
	 *
	 * @param \User $user
	 * @return bool
	 */
	public function userCanExecute( \User $user ) {
		return !$user->isRegistered();
	}

	/**
	 * Override execute to check if account recovery is enabled.
	 *
	 * @param string|null $par
	 */
	public function execute( $par ) {
		if ( !$this->getConfig()->get( 'EmailAuthEnableAccountRecovery' ) ) {
			$this->setHeaders();
			$this->getOutput()->addWikiMsg( 'emailauth-accountrecovery-disabled' );
			return;
		}

		parent::execute( $par );
	}

	/**
	 * Strict email validation for contact emails that will be sent to Zendesk.
	 * More restrictive than MediaWiki's default validation to ensure Zendesk acceptance.
	 *
	 * @param string $email Email address to validate
	 * @return bool True if email is valid and acceptable by Zendesk
	 */
	private function validateStrictEmail( string $email ): bool {
		// First check with MediaWiki's validator
		if ( !Sanitizer::validateEmail( $email ) ) {
			return false;
		}

		// Ensure email has proper structure: localpart@domain.tld
		// Must have a domain with at least one dot (TLD)
		if ( !preg_match( '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $email ) ) {
			return false;
		}

		// Reject emails with multiple consecutive dots or dots at start/end of local part
		[ $local, $domain ] = explode( '@', $email, 2 );
		if ( $local === '' || $domain === '' ) {
			return false;
		}
		if ( str_contains( $local, '..' ) || $local[0] === '.' || substr( $local, -1 ) === '.' ) {
			return false;
		}

		return true;
	}

	/**
	 * Specify form field definitions for the account recovery form.
	 *
	 * @return array Form field configuration array
	 */
	protected function getFormFields() {
		return [
			'username' => [
				'type' => 'user',
				'label-message' => 'emailauth-accountrecovery-username-label',
				'exists' => true,
				'required' => true,
				'maxlength' => 255,
				'filter-callback' => static function ( $value ) {
					return is_string( $value ) ? trim( $value ) : $value;
				},
			],
			'contact_email' => [
				'type' => 'email',
				'label-message' => 'emailauth-accountrecovery-contactemail-label',
				'required' => true,
				'maxlength' => 254,
				'filter-callback' => static function ( $value ) {
					return is_string( $value ) ? trim( $value ) : $value;
				},
				'validation-callback' => function ( $value ) {
					if ( !$this->validateStrictEmail( $value ) ) {
						return $this->msg( 'emailauth-accountrecovery-invalid-email' )->text();
					}
					return true;
				},
			],
			'contact_email_confirm' => [
				'type' => 'email',
				'label-message' => 'emailauth-accountrecovery-contactemail-confirm-label',
				'required' => true,
				'maxlength' => 254,
				'filter-callback' => static function ( $value ) {
					return is_string( $value ) ? trim( $value ) : $value;
				},
				'validation-callback' => function ( $value, $alldata ) {
					// Validate email format with strict rules
					if ( !$this->validateStrictEmail( $value ) ) {
						return $this->msg( 'emailauth-accountrecovery-invalid-email' )->text();
					}

					// Compare emails case-insensitively (both already trimmed by filter-callback)
					if ( strcasecmp( $value, $alldata['contact_email'] ) !== 0 ) {
						return $this->msg( 'emailauth-accountrecovery-email-mismatch' )->text();
					}

					return true;
				},
			],
			'registered_email' => [
				'type' => 'email',
				'label-message' => 'emailauth-accountrecovery-registeredemail-label',
				'required' => false,
				'maxlength' => 254,
				'filter-callback' => static function ( $value ) {
					return is_string( $value ) ? trim( $value ) : $value;
				},
				'validation-callback' => function ( $value ) {
					// Only validate if provided (optional field)
					if ( $value !== '' && !Sanitizer::validateEmail( $value ) ) {
						return $this->msg( 'emailauth-accountrecovery-invalid-email' )->text();
					}
					return true;
				},
			],
			'description' => [
				'type' => 'textarea',
				'label-message' => 'emailauth-accountrecovery-description-label',
				'required' => false,
				'maxlength' => 5000,
				'filter-callback' => static function ( $value ) {
					return is_string( $value ) ? trim( $value ) : $value;
				},
				'rows' => 4,
			]
		];
	}

	/**
	 * Get the description for this special page.
	 *
	 * @return \Message Page description message
	 */
	public function getDescription() {
		return $this->msg( 'emailauth-accountrecovery-intro' );
	}

	/**
	 * Handle form submission.
	 *
	 * @param array $data Form data submitted by the user
	 * @return true|Status True on success, Status object on failure
	 */
	public function onSubmit( array $data ) {
		if ( $this->getUser()->pingLimiter( 'accountrecovery-submit' ) ) {
			return Status::newFatal( 'emailauth-accountrecovery-rate-limited' );
		}

		try {
			// Defense-in-depth: Trim and validate server-side (independent of field validation)
			$contactEmail = trim( $data['contact_email'] );
			if ( !$this->validateStrictEmail( $contactEmail ) ) {
				return Status::newFatal( 'emailauth-accountrecovery-invalid-email' );
			}

			// Validate registered email if provided
			$registeredEmail = null;
			if ( !empty( $data['registered_email'] ) ) {
				$registeredEmail = trim( $data['registered_email'] );
				if ( !Sanitizer::validateEmail( $registeredEmail ) ) {
					return Status::newFatal( 'emailauth-accountrecovery-invalid-email' );
				}
			}

			// Build clean ticket payload from validated and trimmed data
			$ticketData = [
				'requester_email' => $contactEmail,
				'requester_name' => trim( $data['username'] ),
				'registered_email' => $registeredEmail,
				'description' => isset( $data['description'] ) ? trim( $data['description'] ) : null,
			];

			$result = $this->zendeskClient->createTicket( $ticketData );

			if ( $result->isOK() ) {
				return true;
			}

			return Status::wrap( $result );
		} catch ( \Throwable $e ) {
			wfDebugLog( 'EmailAuth', 'AccountRecovery exception: ' . $e->getMessage() );
			return Status::newFatal( 'emailauth-accountrecovery-error-generic' );
		}
	}

	public function onSuccess() {
		$this->getOutput()->addWikiMsg( 'emailauth-accountrecovery-success' );
	}

	/**
	 * Specify the display format for the form.
	 *
	 * @return string Display format ('ooui' or 'vform')
	 */
	protected function getDisplayFormat() {
		return 'ooui';
	}

	/**
	 * Specify the group name for this special page.
	 *
	 * @return string Group name for categorization on Special:SpecialPages
	 */
	protected function getGroupName() {
		return 'login';
	}
}
