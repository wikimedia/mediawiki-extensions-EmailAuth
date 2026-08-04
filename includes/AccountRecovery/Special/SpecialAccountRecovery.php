<?php
declare( strict_types=1 );

namespace MediaWiki\Extension\EmailAuth\AccountRecovery\Special;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Exception\PermissionsError;
use MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk\ZendeskClient;
use MediaWiki\Extension\EmailAuth\EmailAuthCheckUserLogger;
use MediaWiki\Html\Html;
use MediaWiki\Language\FormatterFactory;
use MediaWiki\Language\RawMessage;
use MediaWiki\Mail\IEmailer;
use MediaWiki\Mail\MailAddress;
use MediaWiki\MainConfigNames;
use MediaWiki\Message\Message;
use MediaWiki\Parser\Sanitizer;
use MediaWiki\SpecialPage\FormSpecialPage;
use MediaWiki\Status\Status;
use MediaWiki\User\User;
use MediaWiki\User\UserFactory;
use MediaWiki\User\UserIdentityLookup;
use MediaWiki\Utils\MWCryptRand;
use Psr\Log\LoggerInterface;
use Throwable;
use Wikimedia\Message\MessageSpecifier;
use Wikimedia\ObjectCache\BagOStuff;

class SpecialAccountRecovery extends FormSpecialPage {

	public function __construct(
		private readonly ZendeskClient $zendeskClient,
		private readonly IEmailer $emailer,
		private readonly BagOStuff $microStash,
		private readonly FormatterFactory $formatterFactory,
		private readonly LoggerInterface $logger,
		private readonly EmailAuthCheckUserLogger $checkUserLogger,
		private readonly UserIdentityLookup $userIdentityLookup,
		private readonly AuthManager $authManager,
		private readonly UserFactory $userFactory,
	) {
		parent::__construct( 'AccountRecovery' );
	}

	/** @inheritDoc */
	public function execute( $par ) {
		if ( !$this->getConfig()->get( 'EmailAuthEnableAccountRecovery' ) ) {
			$this->setHeaders();
			$this->getOutput()->addWikiMsg( 'emailauth-accountrecovery-disabled' );
			return;
		}

		$matches = null;
		if ( $par && preg_match( '/^confirm\/([0-9a-fA-F]+)$/', $par, $matches ) ) {
			$this->setHeaders();
			$this->outputHeader();
			$this->handleConfirmationLink( $matches[1] );
			return;
		}

		// Don't execute this page if we are logged out and have no EmailAuth challenge.
		if ( !$this->getUser()->isRegistered() && !$this->getUsernameFromEmailAuthChallenge() ) {
			$this->setHeaders();
			$this->getOutput()->addWikiMsg( 'emailauth-accountrecovery-no-emailauth' );
			return;
		}

		parent::execute( $par );
	}

	/**
	 * Display a custom error message when a logged-in user tries to access this page.
	 *
	 * @inheritDoc
	 */
	public function displayRestrictionError() {
		throw new PermissionsError(
			null,
			[ 'emailauth-accountrecovery-logged-in' ]
		);
	}

	/**
	 * Do not list this special page on Special:SpecialPages.
	 *
	 * @inheritDoc
	 */
	public function isListed() {
		return false;
	}

	/**
	 * Restrict this page to logged-out users only.
	 * Logged-in users don't need account recovery.
	 *
	 * @inheritDoc
	 */
	public function userCanExecute( User $user ) {
		return !$user->isNamed();
	}

	/**
	 * Strict email validation for contact emails that will be sent to Zendesk.
	 * More restrictive than MediaWiki's default validation to ensure Zendesk acceptance.
	 *
	 * @param string $email Email address to validate
	 * @return bool True if email is valid and acceptable by Zendesk
	 */
	private function validateStrictEmail( string $email ): bool {
		if (
			// First check with MediaWiki's validator
			!Sanitizer::validateEmail( $email ) ||
			// Ensure email has the proper structure: localpart@domain.tld
			// Must have a domain with at least one dot (TLD)
			!preg_match( '/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/', $email )
		) {
			return false;
		}

		// Reject emails with multiple consecutive dots or dots at start/end of local part
		[ $local, $domain ] = explode( '@', $email, 2 );

		return $local !== '' &&
			$domain !== '' &&
			!str_contains( $local, '..' ) &&
			$local[0] !== '.' &&
			!str_ends_with( $local, '.' );
	}

	/** @inheritDoc */
	protected function getFormFields() {
		$challengeUsername = $this->getUsernameFromEmailAuthChallenge();
		return [
			'username_display' => [
				'type' => 'info',
				'label-message' => 'emailauth-accountrecovery-username-label',
				'default' => Html::element( 'strong', [], $challengeUsername ?? '' ),
				'raw' => true,
			],
			'contact_email' => [
				'type' => 'email',
				'label-message' => 'emailauth-accountrecovery-contactemail-label',
				'required' => true,
				'maxlength' => 254,
				'filter-callback' => [ $this, 'trimValueIfString' ],
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
				'filter-callback' => [ $this, 'trimValueIfString' ],
				'validation-callback' => function ( $value, $alldata ) {
					// Validate the email format with strict rules
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
				'filter-callback' => [ $this, 'trimValueIfString' ],
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
				'filter-callback' => [ $this, 'trimValueIfString' ],
				'rows' => 4,
			]
		];
	}

	/**
	 * @param mixed|string $value
	 * @return mixed|string
	 */
	public function trimValueIfString( $value ) {
		return is_string( $value ) ? trim( $value ) : $value;
	}

	/** @inheritDoc */
	public function getDescription() {
		return $this->msg( 'emailauth-accountrecovery-intro' );
	}

	/** @inheritDoc */
	public function onSubmit( array $data ) {
		if ( $this->getUser()->pingLimiter( 'accountrecovery-submit' ) ) {
			return Status::newFatal( 'emailauth-accountrecovery-rate-limited' );
		}

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

		// Validate user has an active EmailAuth challenge
		$challengeUsername = $this->getUsernameFromEmailAuthChallenge();
		if ( !$challengeUsername ) {
			return Status::newFatal( 'emailauth-accountrecovery-no-emailauth' );
		}

		// Build a clean ticket payload from validated and trimmed data
		$ticketData = [
			'requester_email' => $contactEmail,
			'requester_name' => $challengeUsername,
			'registered_email' => $registeredEmail,
			'description' => isset( $data['description'] ) ? trim( $data['description'] ) : null,
		];

		$targetUser = $this->userFactory->newFromName( $challengeUsername );

		if ( $targetUser && $targetUser->isNamed() ) {
			$this->checkUserLogger->logAccountRecoverySubmission( $targetUser, $this->getUser() );

			// And then supplement the ticket data with user data that is useful
			// (if the user exists) to help verify a request!
			$ticketData += [
				// Email account attached to the account
				'user_email' => $targetUser->getEmail(),
			];
		}

		return $this->sendConfirmationEmail( $ticketData, false );
	}

	public function onSuccess() {
		$this->getOutput()->addWikiMsg( 'emailauth-accountrecovery-confirmation-needed' );
	}

	/**
	 * Generate a token, stash the ticket data, and send a confirmation email to the user.
	 * @phpcs:ignore Generic.Files.LineLength.TooLong
	 * @param array{requester_email:string,requester_name:string,registered_email:?string,description:?string,user_email:?string} $ticketData
	 */
	private function sendConfirmationEmail( array $ticketData, bool $resend ): Status {
		// Generate a validation token
		$token = MWCryptRand::generateHex( 32 );
		// Stash the ticket data in MicroStash, using the token as a key
		$stashData = [
			'ticketData' => $ticketData,
			'generated' => time()
		];
		$this->microStash->set(
			$this->microStash->makeKey( 'accountrecovery', $token ),
			$stashData,
			// We require the user to confirm their email within a short time
			// ($wgEmailAuthAccountRecoveryTokenExpiry), but we also want to allow them to
			// gracefully retry, so we have to store the data for a little longer
			$this->microStash::TTL_DAY
		);

		$this->logger->info(
			'Account recovery request submitted for {username}',
			[
				'username' => $ticketData['requester_name'],
				'email' => $ticketData['requester_email'],
				'token' => substr( $token, 0, 4 ) . '...',
				...$this->getRequest()->getSecurityLogContext()
			]
		);

		if (
			!$resend &&
			( isset( $ticketData['user_email'] ) && $ticketData['user_email'] !== '' )
		) {
			$sender = $this->getConfig()->get( 'EmailAuthAccountRecoveryNotificationSender' )
				?: $this->getConfig()->get( MainConfigNames::PasswordSender );

			$sv = $this->emailer->send(
				new MailAddress( $ticketData['user_email'] ),
				new MailAddress( $sender ),
				$this->msg( 'emailauth-accountrecovery-usernotification-subject' )->text(),
				$this->msg( 'emailauth-accountrecovery-usernotification-body' )
					->params(
						$ticketData['requester_name']
					)
					->text()
			);
			if ( !$sv->isGood() ) {
				$this->logger->info(
					'Account recovery request original email notification failed for {username}',
					[
						'username' => $ticketData['requester_name'],
						'email' => $ticketData['requester_email'],
						'user_email' => $ticketData['user_email'],
						'status' => $sv->getMessages(),
						...$this->getRequest()->getSecurityLogContext()
					]
				);
			}
		}

		// Send the email
		return Status::wrap( $this->emailer->send(
			new MailAddress( $ticketData['requester_email'] ),
			new MailAddress(
				$this->getConfig()->get( MainConfigNames::PasswordSender ),
				$this->msg( 'emailsender' )->text()
			),
			$this->msg( 'emailauth-accountrecovery-confirmation-subject' )->text(),
			$this->msg( 'emailauth-accountrecovery-confirmation-body' )
				->params(
					$ticketData['requester_name'],
					Message::durationParam( $this->getConfig()->get( 'EmailAuthAccountRecoveryTokenExpiry' ) ),
					$this->getPageTitle( "confirm/$token" )->getFullURL( '', false, PROTO_CANONICAL )
				)
				->text()
		) );
	}

	private function handleConfirmationLink( string $token ) {
		$stashKey = $this->microStash->makeKey( 'accountrecovery', $token );
		$stashedData = $this->microStash->get( $stashKey );
		if ( !$stashedData ) {
			$this->showError( 'emailauth-accountrecovery-error-badtoken' );
			return;
		}

		if ( time() - $stashedData['generated'] > $this->getConfig()->get( 'EmailAuthAccountRecoveryTokenExpiry' ) ) {
			// If the token is too old, generate and send a new token
			$emailResult = $this->sendConfirmationEmail( $stashedData['ticketData'], true );
			if ( $emailResult->isOK() ) {
				// Delete the entry for the old token
				$this->microStash->delete( $stashKey );
				$this->getOutput()->addWikiMsg( 'emailauth-accountrecovery-confirmation-resent' );
			} else {
				$this->showError(
					( new RawMessage( '$1' ) )->rawParams(
						$this->formatterFactory->getStatusFormatter( $this )->getHTML( $emailResult )
					)
				);
			}
			return;
		}

		// Submit the ticket data to Zendesk
		try {
			$result = $this->zendeskClient->createTicket( $stashedData['ticketData'] );
		} catch ( Throwable $e ) {
			wfDebugLog( 'EmailAuth', 'AccountRecovery exception: ' . $e->getMessage() );
			$result = Status::newFatal( 'emailauth-accountrecovery-error-generic' );
		}
		if ( $result->isOK() ) {
			// Delete the stash entry
			$this->microStash->delete( $stashKey );
			$this->getOutput()->addWikiMsg( 'emailauth-accountrecovery-success' );
		} else {
			// Don't delete the stash entry upon error, so the user can retry
			$this->showError(
				( new RawMessage( '$1' ) )->rawParams(
					$this->formatterFactory->getStatusFormatter( $this )->getHTML( $result )
				)
			);
		}
	}

	private function showError( string|MessageSpecifier $message ) {
		$this->getOutput()->showErrorPage(
			$this->getDescription(),
			$message,
			[],
			$this->getPageTitle()
		);
	}

	/**
	 * Check if the current session has an active emailauth challenge
	 * (i.e. the user is in the middle of a login flow that requires
	 * email verification) and return the associated username.
	 *
	 * @return string|null Username if an emailauth challenge is in progress, null otherwise
	 */
	private function getUsernameFromEmailAuthChallenge(): ?string {
		$challengeUserId = $this->authManager->getAuthenticationSessionData( 'EmailAuthChallengeUserID' );

		if ( $challengeUserId !== null ) {
			return $this->userIdentityLookup->getUserIdentityByUserId( $challengeUserId )->getName();
		}

		return null;
	}

	/** @inheritDoc */
	protected function getDisplayFormat() {
		return 'ooui';
	}

	/** @inheritDoc */
	protected function getGroupName() {
		return 'login';
	}

	/**
	 * @inheritDoc
	 * @codeCoverageIgnore Merely declarative
	 */
	public function doesWrites() {
		return true;
	}
}
