<?php

namespace MediaWiki\Extension\EmailAuth\Tests\Integration;

use MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk\ZendeskClient;
use MediaWiki\Status\Status;
use SpecialPageTestBase;

/**
 * @group Database
 */
class SpecialAccountRecoveryTest extends SpecialPageTestBase {

	/** @var \PHPUnit\Framework\MockObject\MockObject&ZendeskClient */
	private $zendeskMock;

	protected function setUp(): void {
		parent::setUp();

		$this->overrideConfigValue( 'RateLimits', [] );
		$this->setContentLang( 'en' );

		// Mock ZendeskClient
		$this->zendeskMock = $this->createMock( ZendeskClient::class );
		$this->zendeskMock->method( 'createTicket' )
			->willReturn( Status::newGood() );

		// Ensure the special page resolves our mock via the service container
		$this->setService( 'EmailAuth.ZendeskClient', $this->zendeskMock );
	}

	protected function newSpecialPage() {
		$factory = $this->getServiceContainer()->getSpecialPageFactory();
		$page = $factory->getPage( 'AccountRecovery' );

		return $page;
	}

	/**
	 * @covers \MediaWiki\Extension\EmailAuth\AccountRecovery\Special\SpecialAccountRecovery::onSubmit
	 */
	public function testSuccessfulFormSubmission(): void {
		// Verify createTicket() is called once with the normalized payload
		$this->zendeskMock->expects( $this->once() )
			->method( 'createTicket' )
			->with( $this->callback( function ( array $payload ) {
				$this->assertSame( 'Alice', $payload['requester_name'] );
				// contact email goes to requester_email unchanged
				$this->assertSame( 'alice@example.org', $payload['requester_email'] );
				// registered email is trimmed by onSubmit()
				$this->assertSame( 'old@example.org', $payload['registered_email'] );
				// description is trimmed
				$this->assertSame( 'please help', $payload['description'] );
				return true;
			} ) )
			->willReturn( Status::newGood() );

		$page = $this->newSpecialPage();

		$data = [
			'username' => 'Alice',
			'contact_email' => 'alice@example.org',
			'contact_email_confirm' => 'alice@example.org',
			// ensures spaces are trimmed
			'registered_email' => ' old@example.org ',
			'description' => '  please help  ',
		];

		$res = $page->onSubmit( $data );
		$this->assertTrue( $res );
	}
}
