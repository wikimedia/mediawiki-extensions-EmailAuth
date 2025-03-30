<?php

namespace MediaWiki\Extension\EmailAuth;

use MediaWiki\Auth\AbstractSecondaryAuthenticationProvider;
use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
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
		$formMessage = wfMessage( 'emailauth-login-message', $user->getEmail() );
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
