<?php
declare( strict_types=1 );

namespace MediaWiki\Extension\EmailAuth\Tests\Integration;

use MediaWiki\Auth\AuthManager;
use MediaWiki\Exception\PermissionsError;
use MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk\ZendeskClient;
use MediaWiki\Extension\EmailAuth\EmailAuthCheckUserLogger;
use MediaWiki\Mail\IEmailer;
use MediaWiki\MainConfigNames;
use MediaWiki\Request\FauxRequest;
use MediaWiki\Status\Status;
use MediaWiki\Tests\Specials\SpecialPageTestBase;
use PHPUnit\Framework\MockObject\MockObject;
use StatusValue;
use Wikimedia\TestingAccessWrapper;

/**
 * @covers \MediaWiki\Extension\EmailAuth\AccountRecovery\Special\SpecialAccountRecovery
 *
 * @group Database
 */
class SpecialAccountRecoveryTest extends SpecialPageTestBase {

	/** @var MockObject&ZendeskClient */
	private $zendeskMock;
	/** @var MockObject&IEmailer */
	private $emailerMock;

	protected function setUp(): void {
		parent::setUp();

		$this->overrideConfigValue( 'RateLimits', [] );

		// Mock ZendeskClient
		$this->zendeskMock = $this->createMock( ZendeskClient::class );
		$this->zendeskMock->method( 'createTicket' )
			->willReturn( Status::newGood() );

		// Mock Emailer
		$this->emailerMock = $this->createMock( IEmailer::class );
		$this->emailerMock->method( 'send' )->willReturn( StatusValue::newGood() );

		// Ensure the special page resolves our mocks via the service container
		$this->setService( 'EmailAuth.ZendeskClient', $this->zendeskMock );
		$this->setService( 'Emailer', $this->emailerMock );

		$this->overrideConfigValues( [
			'EmailAuthEnableAccountRecovery' => true,
			'EmailAuthAccountRecoveryTokenExpiry' => 900,
			MainConfigNames::PasswordSender => 'admin@wiki.example',
			MainConfigNames::CanonicalServer => 'https://example.org',
			MainConfigNames::ArticlePath => '/wiki/$1'
		] );
	}

	protected function newSpecialPage() {
		return $this->getServiceContainer()->getSpecialPageFactory()->getPage( 'AccountRecovery' );
	}

	private function setupAuthManagerWithChallenge( int $challengeUserId ): void {
		$authManager = $this->createMock( AuthManager::class );
		$authManager->method( 'getAuthenticationSessionData' )
			->willReturnCallback( static function ( $key ) use ( $challengeUserId ) {
				if ( $key === 'EmailAuthChallengeUserID' ) {
					return $challengeUserId;
				}
				return null;
			} );
		$this->setService( 'AuthManager', $authManager );
	}

	public function testSuccessfulFormSubmission(): void {
		$user = $this->getTestUser()->getUser();
		$this->setupAuthManagerWithChallenge( $user->getId() );

		// Assert that an email is sent when we submit the form
		$capturedToken = null;
		$this->emailerMock->expects( $this->once() )
			->method( 'send' )
			->with(
				$this->callback( function ( $to ) use ( $user ) {
					$this->assertSame( $user->getEmail(), $to->address );
					return true;
				} ),
				$this->callback( function ( $sender ) {
					$this->assertSame( 'admin@wiki.example', $sender->address );
					$this->assertSame( '(emailsender)', $sender->name );
					return true;
				} ),
				'(emailauth-accountrecovery-confirmation-subject)',
				$this->callback( function ( $body ) use ( $user, &$capturedToken ) {
					$escapedUserName = preg_quote( $user->getName(), '/' );
					$regex = "/^\(emailauth-accountrecovery-confirmation-body: $escapedUserName, " .
						"\(duration-minutes: 15\), " .
						"https:\/\/example.org\/wiki\/Special:AccountRecovery\/confirm\/([0-9a-fA-F]+)\)$/";
					$this->assertMatchesRegularExpression( $regex, $body );

					$matches = null;
					preg_match( $regex, $body, $matches );
					$capturedToken = $matches[ 1 ];
					return true;
				} )
			);

		[ $html ] = $this->executeSpecialPage( '', new FauxRequest( [
			'wpusername' => $user->getName(),
			'wpcontact_email' => $user->getEmail(),
			'wpcontact_email_confirm' => $user->getEmail(),
			// ensures spaces are trimmed
			'wpregistered_email' => ' old@example.org ',
			'wpdescription' => '  please help  '
		], true ) );

		$this->assertStringContainsString( '(emailauth-accountrecovery-confirmation-needed)', $html );

		// Verify createTicket() is called once with the normalized payload
		$this->zendeskMock->expects( $this->once() )
			->method( 'createTicket' )
			->with( $this->callback( function ( array $payload ) use ( $user ) {
				$this->assertSame( $user->getName(), $payload['requester_name'] );
				// contact email goes to requester_email unchanged
				$this->assertSame( $user->getEmail(), $payload['requester_email'] );
				// registered email is trimmed by onSubmit()
				$this->assertSame( 'old@example.org', $payload['registered_email'] );
				// description is trimmed
				$this->assertSame( 'please help', $payload['description'] );
				return true;
			} ) )
			->willReturn( Status::newGood() );

		[ $html ] = $this->executeSpecialPage( "confirm/$capturedToken" );
		$this->assertStringContainsString( '(emailauth-accountrecovery-success)', $html );
	}

	public function testFormSubmissionLogsToCheckUser(): void {
		$user = $this->getTestUser()->getUser();
		$this->setupAuthManagerWithChallenge( $user->getId() );

		$checkUserLogger = $this->createMock( EmailAuthCheckUserLogger::class );
		$checkUserLogger->expects( $this->once() )
			->method( 'logAccountRecoverySubmission' )
			->with(
				$this->callback( function ( $identity ) use ( $user ) {
					$this->assertSame( $user->getName(), $identity->getName() );
					return true;
				} ),
				$this->callback( function ( $performer ) {
					$this->assertTrue( $performer->isAnon() );
					return true;
				} )
			);
		$this->setService( 'EmailAuth.CheckUserLogger', $checkUserLogger );

		[ $html ] = $this->executeSpecialPage( '', new FauxRequest( [
			'wpusername' => $user->getName(),
			'wpcontact_email' => $user->getEmail(),
			'wpcontact_email_confirm' => $user->getEmail(),
			'wpregistered_email' => '',
		], true ) );

		$this->assertStringContainsString( '(emailauth-accountrecovery-confirmation-needed)', $html );
	}

	public function testConfirmBadToken() {
		$this->setupAuthManagerWithChallenge( $this->getTestUser()->getUser()->getId() );
		$this->zendeskMock->expects( $this->never() )->method( 'createTicket' );

		[ $html ] = $this->executeSpecialPage( 'confirm/123abc' );
		$this->assertStringContainsString( '(emailauth-accountrecovery-error-badtoken)', $html );
	}

	public function testNoFormWhenLoggedIn() {
		$user = $this->getTestUser()->getUser();
		$this->expectException( PermissionsError::class );
		[ $html ] = $this->executeSpecialPage( '', null, null, $user );
	}

	public function testNoFormWhenNoChallengeIsActive(): void {
		// getAuthenticationSessionData returns null by default (no challenge)

		[ $html ] = $this->executeSpecialPage( '' );
		$this->assertStringContainsString( '(emailauth-accountrecovery-no-emailauth)', $html );
	}

	public function testGetFormFieldsPrePopulatesUsernameWhenChallengeActive(): void {
		$testUser = $this->getTestUser()->getUser();
		$this->setupAuthManagerWithChallenge( $testUser->getId() );

		$page = $this->newSpecialPage();
		$wrapped = TestingAccessWrapper::newFromObject( $page );
		$fields = $wrapped->getFormFields();

		$this->assertStringContainsString( $testUser->getName(), $fields['username_display']['default'] );
	}

	public function testOnSubmitUsesSessionUsernameNotFormData(): void {
		$challengeUser = $this->getTestUser()->getUser();
		$this->setupAuthManagerWithChallenge( $challengeUser->getId() );

		$this->emailerMock->expects( $this->once() )
			->method( 'send' )
			->with(
				$this->anything(),
				$this->anything(),
				$this->anything(),
				$this->callback( function ( $body ) use ( $challengeUser ) {
					// Assert that we use the username from the challenge, not the username sent in the form.
					$this->assertStringContainsString( $challengeUser->getName(), $body );
					return true;
				} )
			);

		$otherUser = $this->getTestUser( [ 'sysop' ] )->getUser();

		$page = $this->newSpecialPage();
		$result = $page->onSubmit( [
			'username' => $otherUser->getName(),
			'contact_email' => $otherUser->getEmail(),
			'contact_email_confirm' => $otherUser->getEmail(),
			'registered_email' => '',
			'description' => '',
		] );
		$this->assertTrue( $result->isOK() );
	}

	public function testOnSubmitRejectsWithoutActiveChallenge(): void {
		// No setupAuthManagerWithChallenge call — simulates no active EmailAuth challenge
		$user = $this->getTestUser()->getUser();
		$this->emailerMock->expects( $this->never() )->method( 'send' );

		$page = $this->newSpecialPage();
		$result = $page->onSubmit( [
			'username' => $user->getName(),
			'contact_email' => $user->getEmail(),
			'contact_email_confirm' => $user->getEmail(),
			'registered_email' => '',
			'description' => '',
		] );

		$this->assertFalse( $result->isOK() );
		$this->assertSame( 'emailauth-accountrecovery-no-emailauth', $result->getErrors()[0]['message'] );
	}
}
