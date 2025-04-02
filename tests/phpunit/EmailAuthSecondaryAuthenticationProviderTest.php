<?php

namespace MediaWiki\Extension\EmailAuth;

use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\Auth\AuthenticationResponse;
use MediaWiki\Auth\AuthManager;
use MediaWiki\Config\HashConfig;
use MediaWiki\MainConfigNames;
use MediaWiki\User\User;
use MediaWiki\User\UserNameUtils;
use MediaWikiIntegrationTestCase;
use PHPUnit\Framework\MockObject\MockObject;
use Psr\Log\LoggerInterface;
use Wikimedia\ObjectCache\HashBagOStuff;
use Wikimedia\TestingAccessWrapper;

/**
 * @covers \MediaWiki\Extension\EmailAuth\EmailAuthSecondaryAuthenticationProvider
 * @group Database
 */
class EmailAuthSecondaryAuthenticationProviderTest extends MediaWikiIntegrationTestCase {
	/** @var EmailAuthSecondaryAuthenticationProvider|MockObject */
	protected $provider;
	/** @var AuthManager|MockObject */
	protected $manager;
	/** @var HashBagOStuff */
	protected $session;
	/** @var LoggerInterface|MockObject */
	protected $logger;

	protected function setUp(): void {
		parent::setUp();

		$this->setTemporaryHook( 'EmailAuthRequireToken', static function () {
		} );

		$this->provider = new EmailAuthSecondaryAuthenticationProvider();

		$this->logger = $this->getMockBuilder( LoggerInterface::class )->getMockForAbstractClass();

		$this->manager = $this->getMockBuilder( AuthManager::class )->disableOriginalConstructor()
			->getMock();
		$this->session = new HashBagOStuff();
		$this->manager->method( 'setAuthenticationSessionData' )
			->willReturnCallback( function ( $key, $value ) {
				$this->session->set( $key, $value );
			} );
		$this->manager->method( 'getAuthenticationSessionData' )
			->willReturnCallback( function ( $key ) {
				return $this->session->get( $key );
			} );
		$this->provider->init(
			$this->logger,
			$this->manager,
			$this->createHookContainer(),
			new HashConfig( [ MainConfigNames::ObjectCacheSessionExpiry => 3600 ] ),
			$this->createNoOpMock( UserNameUtils::class )
		);
	}

	public function testGetAuthenticationRequests() {
		$reqs = $this->provider->getAuthenticationRequests( AuthManager::ACTION_LOGIN,
			[ 'username' => 'Foo' ] );
		$this->assertSame( [], $reqs );
	}

	public function testSecondaryAuthentication() {
		// no action by default
		$user = $this->getMockUser( true );
		$response = $this->provider->beginSecondaryAuthentication( $user, [] );
		$this->assertSame( AuthenticationResponse::PASS, $response->status );

		// require token when instructed by hook
		$this->setTemporaryHook( 'EmailAuthRequireToken', static function ( $user, &$verificationRequired ) {
			$verificationRequired = true;
		} );
		$this->session->clear();
		$user = $this->getMockUser( true );
		$user->expects( $this->once() )->method( 'sendMail' );
		$response = $this->provider->beginSecondaryAuthentication( $user, [] );
		$this->assertSame( AuthenticationResponse::UI, $response->status );
		$response = $this->provider->continueSecondaryAuthentication( $user,
			AuthenticationRequest::loadRequestsFromSubmission( $response->neededRequests,
				[ 'token' => '123abc' ] ) );
		$this->assertSame( AuthenticationResponse::UI, $response->status );
		$this->assertSame( 'error', $response->messageType );
		$response = $this->provider->continueSecondaryAuthentication( $user,
			AuthenticationRequest::loadRequestsFromSubmission( $response->neededRequests,
				[ 'token' => $this->manager->getAuthenticationSessionData( 'EmailAuthToken' ) ] ) );
		$this->assertSame( AuthenticationResponse::PASS, $response->status );

		// abort after 4 failed attempts
		$this->session->clear();
		$user = $this->getMockUser( true );
		$response = $this->provider->beginSecondaryAuthentication( $user, [] );
		$this->assertSame( AuthenticationResponse::UI, $response->status );
		$this->assertSame( 'warning', $response->messageType );
		foreach ( range( 1, 3 ) as $i ) {
			$response = $this->provider->continueSecondaryAuthentication( $user,
				AuthenticationRequest::loadRequestsFromSubmission( $response->neededRequests,
					[ 'token' => 'false' ] ) );
			$this->assertSame( AuthenticationResponse::UI, $response->status );
			$this->assertSame( 'error', $response->messageType );
		}
		$response = $this->provider->continueSecondaryAuthentication( $user,
			AuthenticationRequest::loadRequestsFromSubmission( $response->neededRequests,
				[ 'token' => 'false' ] ) );
		$this->assertSame( AuthenticationResponse::FAIL, $response->status );

		// allows users with no confirmed email address, and confirm their email on success
		$this->session->clear();
		$user = $this->getMockUser( false );
		$user->expects( $this->once() )->method( 'sendMail' )
			->willReturnCallback( static function ( $s, $b ) use ( &$body ) {
				$body = $b;
			} );
		$response = $this->provider->beginSecondaryAuthentication( $user, [] );
		$this->assertSame( AuthenticationResponse::UI, $response->status );

		$token = $this->session->get( 'EmailAuthToken' );
		$response = $this->provider->continueSecondaryAuthentication( $user,
			AuthenticationRequest::loadRequestsFromSubmission( $response->neededRequests,
				[ 'token' => $token ] ) );
		$this->assertSame( AuthenticationResponse::PASS, $response->status );

		// ignores users with no email address
		$this->session->clear();
		$user = $this->getMockUserNoEmail();
		$response = $this->provider->beginSecondaryAuthentication( $user, [] );
		$this->assertSame( AuthenticationResponse::PASS, $response->status );

		// messages can be changed
		$this->setTemporaryHook( 'EmailAuthRequireToken', static function ( $user, &$verificationRequired,
			&$formMessage, &$subjectMessage, &$bodyMessage, &$bodyMessageHtml
		) {
			$verificationRequired = true;
			$formMessage = wfMessage( 'form' );
			$subjectMessage = 'subject';
			$bodyMessage = 'body';
			$bodyMessageHtml = 'body-html';
		} );
		$this->session->clear();
		$user = $this->getMockUser( true );
		$user->expects( $this->once() )->method( 'sendMail' )
			->willReturnCallback( static function ( $s, $b ) use ( &$subject2, &$bodyText2, &$bodyHtml2 ) {
				$subject2 = $s;
				$bodyText2 = $b['text'];
				$bodyHtml2 = $b['html'];
			} );
		$response = $this->provider->beginSecondaryAuthentication( $user, [] );
		$this->assertSame( AuthenticationResponse::UI, $response->status );
		$this->assertSame( 'form', $response->message->getKey() );
		$this->assertSame( 'subject', $subject2 );
		$this->assertSame( 'body', $bodyText2 );
		$this->assertSame( 'body-html', $bodyHtml2 );
	}

	public function testBeginSecondaryAccountCreation() {
		$response = $this->provider->beginSecondaryAccountCreation( User::newFromName( 'Foo' ),
			User::newFromName( 'Bar' ), [] );
		$this->assertThat( $response->status, $this->logicalOr( $this->identicalTo(
			AuthenticationResponse::PASS ), $this->identicalTo( AuthenticationResponse::ABSTAIN ) ) );
	}

	protected function getMockUser( $isEmailConfirmed ) {
		$user = $this->getMockBuilder( User::class )
			->onlyMethods( [
				'isEmailConfirmed', 'sendMail', 'getEmail', 'confirmEmail', 'saveSettings'
			] )->getMock();
		$user->expects( $this->any() )->method( 'isEmailConfirmed' )->willReturn( $isEmailConfirmed );
		$user->expects( $this->any() )->method( 'getEmail' )->willReturn( 'a@b.com' );
		if ( !$isEmailConfirmed ) {
			$user->expects( $this->once() )->method( 'confirmEmail' );
			$user->expects( $this->once() )->method( 'saveSettings' );
		} else {
			$user->expects( $this->never() )->method( 'confirmEmail' );
			$user->expects( $this->never() )->method( 'saveSettings' );
		}
		/** @var User $user */
		$user->mName = 'Foo';
		$user->mFrom = 'name';
		TestingAccessWrapper::newFromObject( $user )->setItemLoaded( 'name' );
		return $user;
	}

	private function getMockUserNoEmail() {
		$user = $this->getMockBuilder( User::class )
			->onlyMethods( [ 'getEmail', 'isEmailConfirmed', 'sendMail' ] )->getMock();
		$user->expects( $this->any() )->method( 'isEmailConfirmed' )->willReturn( false );
		$user->expects( $this->any() )->method( 'getEmail' )->willReturn( '' );
		/** @var User $user */
		$user->mName = 'Foo';
		$user->mFrom = 'name';
		TestingAccessWrapper::newFromObject( $user )->setItemLoaded( 'name' );
		return $user;
	}
}
