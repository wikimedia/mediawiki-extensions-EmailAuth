<?php

namespace MediaWiki\Extension\EmailAuth;

use MediaWiki\Auth\AbstractSecondaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Deferred\DeferredUpdates;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\MediaWikiServices;
use MediaWiki\Message\Message;
use MediaWiki\User\User;
use MWCryptRand;

class EmailAuthSecondaryAuthenticationProvider extends AbstractSecondaryAuthenticationProvider {
	/** Fail the login attempt after this many retries */
	private const RETRIES = 3;

	/** @inheritDoc */
	public function getAuthenticationRequests( $action, array $options ) {
		return [];
	}

	/** @inheritDoc */
	public function beginSecondaryAuthentication( $user, array $reqs ) {
		$token = MWCryptRand::generateHex( 6 );
		$messages = $this->runEmailAuthRequireToken( $user, $token );
		if ( !$messages ) {
			return AuthenticationResponse::newPass();
		}
		/** @var Message $formMessage */
		/** @var Message $subjectMessage */
		/** @var Message $bodyMessage */
		[ $formMessage, $subjectMessage, $bodyMessage ] = $messages;

		LoggerFactory::getInstance( 'EmailAuth' )->info( 'Verification requested for {user}', [
			'user' => $user->getName(),
			'ip' => $user->getRequest()->getIP(),
			'eventType' => 'emailauth-login-verification-requested',
			'ua' => $user->getRequest()->getHeader( 'User-Agent' ),
			'formMessageKey' => $formMessage->getKey(),
			'subjectMessageKey' => $subjectMessage->getKey(),
			'bodyMessageKey' => $bodyMessage->getKey(),
			'emailVerified' => $user->isEmailConfirmed(),
		] );

		$this->manager->setAuthenticationSessionData( 'EmailAuthToken', $token );
		$this->manager->setAuthenticationSessionData( 'EmailAuthFailures', 0 );
		$this->manager->setAuthenticationSessionData( 'EmailAuthEmail', $user->getEmail() );
		$user->sendMail( $subjectMessage, $bodyMessage );
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
			// Handle scenario where user may have set their email to a new unconfirmed address
			// but is inputting a token associated with an old address. Make sure that the
			// $user email matches what has been stashed in the session data before confirming
			// the new email.
			$stashedEmail = $this->manager->getAuthenticationSessionData( 'EmailAuthEmail' );
			if ( $stashedEmail === $user->getEmail() && !$user->isEmailConfirmed() ) {
				DeferredUpdates::addCallableUpdate( static function () use ( $user, $logger ) {
					// Confirm the user's email, since inputting the token is proof that
					// the user controls the email address on the account.
					$user->confirmEmail();
					$user->saveSettings();
					$logger->info( 'Marked email as confirmed for for {user}', [
						'user' => $user->getName(),
						'eventType' => 'emailauth-mark-email-confirmed',
						'ip' => $user->getRequest()->getIP(),
						'emailVerified' => $user->isEmailConfirmed(),
					] );
				} );
			} else {
				$logger->info( 'Stashed email does not match user email for {user}', [
					'user' => $user->getName(),
					'eventType' => 'emailauth-login-email-mismatch',
					'ip' => $user->getRequest()->getIP(),
					'emailVerified' => $user->isEmailConfirmed(),
				] );
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
	 * @return Message[]|bool [ form message, email subject, email body ] or false if no
	 *  verification should happen
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
		// TODO: emailauth-login-message is currently unused. We may reintroduce
		// it later, when we figure out how we want to mask the email address
		// (T390780)
		$formMessage = wfMessage( 'emailauth-login-message-no-email' );
		$subjectMessage = wfMessage( 'emailauth-email-subject', $wgSitename );
		$bodyMessage = wfMessage( 'emailauth-email-body', $wgSitename );

		MediaWikiServices::getInstance()->getHookContainer()->run(
			'EmailAuthRequireToken',
			[ $user, &$verificationRequired, &$formMessage, &$subjectMessage, &$bodyMessage ]
		);
		$bodyMessage->params( $token );

		// @phan-suppress-next-line PhanImpossibleCondition
		return $verificationRequired
			? [ $formMessage, $subjectMessage, $bodyMessage ]
			: false;
	}
}
