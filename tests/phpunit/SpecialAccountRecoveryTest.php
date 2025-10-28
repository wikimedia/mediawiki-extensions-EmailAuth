<?php

namespace MediaWiki\Extension\EmailAuth\Tests\Integration;

use MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk\ZendeskClient;
use MediaWiki\Mail\IEmailer;
use MediaWiki\MainConfigNames;
use MediaWiki\Request\FauxRequest;
use MediaWiki\Status\Status;
use SpecialPageTestBase;
use StatusValue;

/**
 * @group Database
 */
class SpecialAccountRecoveryTest extends SpecialPageTestBase {

	/** @var \PHPUnit\Framework\MockObject\MockObject&ZendeskClient */
	private $zendeskMock;
	/** @var \PHPUnit\Framework\MockObject\MockObject&IEmailer */
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
			MainConfigNames::Server => 'https://example.org',
			MainConfigNames::ArticlePath => '/wiki/$1'
		] );
	}

	protected function newSpecialPage() {
		$factory = $this->getServiceContainer()->getSpecialPageFactory();
		return $factory->getPage( 'AccountRecovery' );
	}

	/**
	 * @covers \MediaWiki\Extension\EmailAuth\AccountRecovery\Special\SpecialAccountRecovery::onSubmit
	 * @covers \MediaWiki\Extension\EmailAuth\AccountRecovery\Special\SpecialAccountRecovery::handleConfirmationLink
	 */
	public function testSuccessfulFormSubmission(): void {
		$user = $this->getTestUser()->getUser();

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

	/**
	 * @covers \MediaWiki\Extension\EmailAuth\AccountRecovery\Special\SpecialAccountRecovery::handleConfirmationLink
	 */
	public function testConfirmBadToken() {
		$this->zendeskMock->expects( $this->never() )->method( 'createTicket' );

		[ $html ] = $this->executeSpecialPage( 'confirm/123abc' );
		$this->assertStringContainsString( '(emailauth-accountrecovery-error-badtoken)', $html );
	}
}
