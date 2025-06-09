<?php

namespace MediaWiki\Extension\EmailAuth;

use MediaWiki\Auth\AbstractSecondaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Context\RequestContext;
use MediaWiki\Deferred\DeferredUpdates;
use MediaWiki\Html\Html;
use MediaWiki\Html\TemplateParser;
use MediaWiki\Language\FormatterFactory;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\MainConfigNames;
use MediaWiki\MediaWikiServices;
use MediaWiki\Message\Message;
use MediaWiki\User\User;

class EmailAuthSecondaryAuthenticationProvider extends AbstractSecondaryAuthenticationProvider {
	/** Fail the login attempt after this many retries */
	private const RETRIES = 3;

	private FormatterFactory $formatterFactory;

	public function __construct(
		FormatterFactory $formatterFactory
	) {
		$this->formatterFactory = $formatterFactory;
	}

	/** @inheritDoc */
	public function getAuthenticationRequests( $action, array $options ) {
		return [];
	}

	/** @inheritDoc */
	public function beginSecondaryAuthentication( $user, array $reqs ) {
		$token = $this->generateToken();
		$messages = $this->runEmailAuthRequireToken( $user, $token );
		if ( !$messages ) {
			return AuthenticationResponse::newPass();
		}
		/** @var Message $formMessage */
		/** @var string $subject */
		/** @var string $body */
		/** @var string $bodyHtml */
		[ $formMessage, $subject, $body, $bodyHtml ] = $messages;

		LoggerFactory::getInstance( 'EmailAuth' )->info( 'Verification requested for {user}', [
			'user' => $user->getName(),
			'ip' => $user->getRequest()->getIP(),
			'eventType' => 'emailauth-login-verification-requested',
			'ua' => $user->getRequest()->getHeader( 'User-Agent' ),
			'emailVerified' => $user->isEmailConfirmed(),
		] );

		$this->manager->setAuthenticationSessionData( 'EmailAuthToken', $token );
		$this->manager->setAuthenticationSessionData( 'EmailAuthFailures', 0 );
		if ( !$user->isEmailConfirmed() ) {
			// If they manage to enter the verification code, that confirms they own the address.
			$this->manager->setAuthenticationSessionData( 'EmailAuthConfirmEmail', $user->getEmail() );
		}

		// Do not use on-wiki message overrides which can be used to exfiltrate the code.
		// Extensions replacing the message with a complex one, e.g. using parameters that are
		// themselves messages, are responsible for disabling on-wiki overrides for the replacement.
		$status = $user->sendMail( $subject, [
			'text' => $body,
			'html' => $bodyHtml,
		] );
		if ( !$status->isOK() ) {
			LoggerFactory::getInstance( 'EmailAuth' )->error( 'Could not email {user}', [
				'user' => $user->getName(),
				'eventType' => 'emailauth-login-email-error',
				'errorMessage' => $this->formatterFactory->getStatusFormatter( RequestContext::getMain() )
					->getWikiText( $status, [ 'lang' => 'en' ] ),
			] );
		}
		return AuthenticationResponse::newUI( [ new EmailAuthAuthenticationRequest() ], $formMessage );
	}

	/** @inheritDoc */
	public function continueSecondaryAuthentication( $user, array $reqs ) {
		$token = $this->manager->getAuthenticationSessionData( 'EmailAuthToken' );
		/** @var EmailAuthAuthenticationRequest $req */
		$req = AuthenticationRequest::getRequestByClass( $reqs, EmailAuthAuthenticationRequest::class );
		$logger = LoggerFactory::getInstance( 'EmailAuth' );
		if ( $req && hash_equals( $token, $req->token ) ) {
			$logger->info( 'Successful verification for {user}', [
				'user' => $user->getName(),
				'eventType' => 'emailauth-login-successful-verification',
				'ip' => $user->getRequest()->getIP(),
				'emailVerified' => $user->isEmailConfirmed(),
			] );

			$stashedEmail = $this->manager->getAuthenticationSessionData( 'EmailAuthConfirmEmail' );
			if ( $stashedEmail ) {
				DeferredUpdates::addCallableUpdate( static function () use ( $user, $logger, $stashedEmail ) {
					if ( $user->isEmailConfirmed() ) {
						// Maybe confirmed in parallel on a different device? Either way, nothing to do.
						return;
					} elseif ( $stashedEmail === $user->getEmail() ) {
						// Confirm the user's email, since inputting the token is proof that
						// the user controls the email address on the account.
						$user->confirmEmail();
						$user->saveSettings();
						$logger->info( 'Marked email as confirmed for {user}', [
							'user' => $user->getName(),
							'eventType' => 'emailauth-mark-email-confirmed',
							'ip' => $user->getRequest()->getIP(),
						] );
					} else {
						// A bug or a race condition or an attack - a smart attacker could log in on
						// a different device and change their email address between receiving and
						// entering the confirmation code.
						$logger->info( 'Stashed email does not match user email for {user}', [
							'user' => $user->getName(),
							'eventType' => 'emailauth-login-email-mismatch',
							'ip' => $user->getRequest()->getIP(),
							'stashedEmail' => $stashedEmail,
							'actualEmail' => $user->getEmail(),
							'actualEmailTimestamp' => $user->getEmailAuthenticationTimestamp() ?? '',
						] );
					}
				} );
			}
			return AuthenticationResponse::newPass();
		}

		if ( $req && $req->token ) {
			// do not log if the code is simply missing - accidental enter or confused bot
			$logger->info( 'Failed verification for {user}', [
				'user' => $user->getName(),
				'ip' => $user->getRequest()->getIP(),
				'eventType' => 'emailauth-login-failed-verification',
				'ua' => $user->getRequest()->getHeader( 'User-Agent' ),
				'emailVerified' => $user->isEmailConfirmed(),
			] );
		}

		$failures = $this->manager->getAuthenticationSessionData( 'EmailAuthFailures' );
		if ( $failures >= self::RETRIES ) {
			$logger->info( 'Failed verification for {user} over retry limit', [
					'user' => $user->getName(),
					'ip' => $user->getRequest()->getIP(),
					'eventType' => 'emailauth-login-retry-limit',
					'ua' => $user->getRequest()->getHeader( 'User-Agent' ),
					'emailVerified' => $user->isEmailConfirmed(),
				] );
			return AuthenticationResponse::newFail( wfMessage( 'emailauth-login-retry-limit' ) );
		}
		$this->manager->setAuthenticationSessionData( 'EmailAuthFailures', $failures + 1 );
		return AuthenticationResponse::newUI( [ new EmailAuthAuthenticationRequest() ],
			wfMessage( 'emailauth-login-failure' ), 'error' );
	}

	/** @inheritDoc */
	public function beginSecondaryAccountCreation( $user, $creator, array $reqs ) {
		return AuthenticationResponse::newAbstain();
	}

	/**
	 * @param User $user
	 * @param string $token
	 * @return array{0:Message,1:string,2:string,3:string}|bool
	 *   [ form message, email subject, email body text, email body HTML ] or false if
	 *   no verification should happen
	 */
	protected function runEmailAuthRequireToken( User $user, $token ) {
		global $wgSitename;

		// We need an email (confirmed or unconfirmed) to do something.
		if ( !$user->getEmail() ) {
			LoggerFactory::getInstance( 'EmailAuth' )->info( '{user} without email logging in', [
				'user' => $user->getName(),
				'ip' => $user->getRequest()->getIP(),
				'eventType' => 'emailauth-login-no-email',
				'ua' => $user->getRequest()->getHeader( 'User-Agent' ),
			] );
			return false;
		}

		$verificationRequired = false;

		$maskedEmail = $this->maskEmail( $user->getEmail() );
		$formMessage = wfMessage( 'emailauth-login-message', wfEscapeWikiText( $maskedEmail ) );

		$helpUrl = wfMessage( 'emailauth-email-help-url' )->text();
		// Do not allow on-wiki modification of these messages (except the help URL above).
		// A malicious email text could trick the user into sending the code to the attacker.
		$subject = wfMessage( 'emailauth-email-subject', $wgSitename )->useDatabase( false )->text();
		$introMessage = wfMessage( 'emailauth-email-body-intro', $user->getName(), $wgSitename );
		$codeTextMessage = wfMessage( 'emailauth-email-body-code-text' );
		$warningMessage = wfMessage( 'emailauth-email-body-warning',
			Message::durationParam( $this->config->get( MainConfigNames::ObjectCacheSessionExpiry ) ) );
		$attackHeadingMessage = wfMessage( 'emailauth-email-body-attack-heading' );
		$attackP1Message = wfMessage( 'emailauth-email-body-attack-p1' );
		$attackP2Message = wfMessage( 'emailauth-email-body-attack-p2' );
		$helpTextMessage = wfMessage( 'emailauth-email-body-help-text', $helpUrl );
		$helpHtmlMessage = wfMessage( 'emailauth-email-body-help-text',
			Html::element( 'a', [ 'href' => $helpUrl ], $helpUrl ) );
		$templateData = [
			'code' => $token,
			'subject' => $subject,
			'intro' => $introMessage->useDatabase( false )->text(),
			'code-text' => $codeTextMessage->useDatabase( false )->text(),
			'warning' => $warningMessage->useDatabase( false )->text(),
			'attack-heading' => $attackHeadingMessage->useDatabase( false )->text(),
			'attack-p1' => $attackP1Message->useDatabase( false )->text(),
			'attack-p2' => $attackP2Message->useDatabase( false )->text(),
			'help-text' => $helpTextMessage->useDatabase( false )->text(),
			'help-html' => $helpHtmlMessage->useDatabase( false )->text(),
		];
		$templateParser = new TemplateParser( __DIR__ . '/../templates' );
		$body = $templateParser->processTemplate( 'email-text', $templateData );
		$bodyHtml = $templateParser->processTemplate( 'email-html', $templateData );

		MediaWikiServices::getInstance()->getHookContainer()->run(
			'EmailAuthRequireToken',
			[ $user, &$verificationRequired, &$formMessage, &$subject, &$body, &$bodyHtml ]
		);

		// @phan-suppress-next-line PhanImpossibleCondition
		return $verificationRequired ? [ $formMessage, $subject, $body, $bodyHtml ] : false;
	}

	/**
	 * Generate a random token
	 *
	 * Returns a 6-digit integer with leading zeros, if necessary
	 *
	 * @return string 6-digit random integer with padding
	 */
	protected function generateToken(): string {
		return str_pad( (string)random_int( 0, 999999 ), 6, '0', STR_PAD_LEFT );
	}

	/**
	 * Fully masks a domain unless found in unmaskedDomains.json
	 *
	 * Returns a masked domain string, if necessary
	 *
	 * @param string $domain the full domain, SLD + TLD
	 * @return string Masked domain
	 */
	private function maskDomain( string $domain ): string {
		$fallback_domain_mask = '***.***';

		if ( preg_match( "/^((?!-)[A-Za-z0-9-]{1, 63}(?<!-)\\.)+[A-Za-z]{2, 6}$/", $domain ) ) {
			// error on the side of caution if invalid domain
			return $fallback_domain_mask;
		}

		$cfg = MediaWikiServices::getInstance()->getConfigFactory()->makeConfig( 'emailauth' );
		$unmaskedDomains = $cfg->get( 'UnmaskedDomains' );

		if ( is_array( $unmaskedDomains ) && in_array( $domain, $unmaskedDomains ) ) {
			return $domain;
		} else {
			return $fallback_domain_mask;
		}
	}

	/**
	 * Mask the local-part of an email address for privacy.  Also mask the SLD
	 * of the domain if it does not appear in unmaskedDomains.json.
	 *
	 * Returns a masked version of the email (e.g. "j***@domain.com") with only the first
	 * character of the local part visible. If the email is invalid or empty, a fallback
	 * placeholder address is returned instead.
	 *
	 * @param string $email Email address to mask
	 * @return string Masked email or fallback placeholder
	 */
	private function maskEmail( string $email ): string {
		$fallback = '***@***.***';

		$atPos = strrpos( $email, '@' );
		if ( $atPos === false || $atPos === 0 || $atPos === strlen( $email ) - 1 ) {
			return $fallback;
		}

		// @phan-suppress-next-line PhanSuspiciousBinaryAddLists
		[ $local, $domain ] = explode( '@', $email, 2 ) + [ '', '' ];
		if ( $local === '' || $domain === '' ) {
			return $fallback;
		}

		$domain = $this->maskDomain( $domain );

		if ( strlen( $local ) <= 1 ) {
			$maskedLocal = '*';
		} else {
			$maskedLocal = substr( $local, 0, 1 ) . '***';
		}

		return $maskedLocal . '@' . $domain;
	}
}
