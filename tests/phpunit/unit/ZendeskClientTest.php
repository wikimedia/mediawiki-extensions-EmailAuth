<?php

namespace MediaWiki\Extension\EmailAuth\Tests\Unit;

use MediaWiki\Config\ServiceOptions;
use MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk\ZendeskClient;
use MediaWiki\Http\HttpRequestFactory;
use MediaWikiUnitTestCase;
use Psr\Log\LoggerInterface;
use Status;

/**
 * @covers \MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk\ZendeskClient
 */
class ZendeskClientTest extends MediaWikiUnitTestCase {

	private ServiceOptions $serviceOptions;
	private LoggerInterface $logger;
	private HttpRequestFactory $httpRequestFactory;
	private object $request;

	private function makeClient( array $overrides = [] ): ZendeskClient {
		$defaults = [
			'EmailAuthZendeskUrl' => 'https://example.zendesk.com',
			'EmailAuthZendeskHTTPProxy' => $overrides['proxy'] ?? null,
			'EmailAuthZendeskSubjectLine' => 'Account Recovery',
			'EmailAuthZendeskEmail' => 'bot@example.org',
			'EmailAuthZendeskToken' => 'TOKEN123',
			'EmailAuthZendeskTicketFormId' => 1234567890,
			'EmailAuthZendeskCustomFields' => $overrides['customFields'] ?? [],
			'EmailAuthZendeskTags' => $overrides['tags'] ?? [],
		];

		$this->serviceOptions = $this->createMock( ServiceOptions::class );
		$this->serviceOptions->expects( $this->once() )
			->method( 'assertRequiredOptions' )
			->with( ZendeskClient::CONSTRUCTOR_OPTIONS );

		$this->serviceOptions->method( 'get' )->willReturnCallback(
			static fn ( string $k ) => $defaults[$k]
		);

		$this->logger = $this->createMock( LoggerInterface::class );
		$this->httpRequestFactory = $this->createMock( HttpRequestFactory::class );

		// Build a lightweight request mock with the exact methods we call
		$this->request = $this->getMockBuilder( \stdClass::class )
			->addMethods( [ 'setHeader', 'execute', 'getStatus', 'getContent', 'getResponseHeader' ] )
			->getMock();

		return new ZendeskClient(
			$this->httpRequestFactory,
			$this->logger,
			$this->serviceOptions
		);
	}

	public function testCreateTicketBuildsRequestAndReturnsOk(): void {
		$client = $this->makeClient( [
			'customFields' => [
				[ 'id' => 100, 'value' => 'static_value' ],
				[ 'id' => 200, 'value' => '{username}' ],
				[ 'id' => 300, 'value' => '{registered_email}' ],
			],
			'tags' => [ 'test_tag' ],
		] );

		$capturedUrl = null;
		$capturedOptions = null;

		$this->httpRequestFactory->method( 'create' )
			->willReturnCallback( function ( string $url, array $options ) use ( &$capturedUrl, &$capturedOptions ) {
				$capturedUrl = $url;
				$capturedOptions = $options;
				return $this->request;
			} );

		$this->request->method( 'execute' )->willReturn( Status::newGood() );

		$this->request->expects( $this->exactly( 3 ) )->method( 'setHeader' );

		$status = $client->createTicket( [
			'requester_email' => 'user@domain.test',
			'requester_name' => 'Alice',
			'registered_email' => 'alice@registered.test',
			'description' => 'Help please',
		] );

		// URL
		$this->assertSame( 'https://example.zendesk.com/api/v2/requests.json', $capturedUrl );

		// Auth + method
		$this->assertSame( 'POST', $capturedOptions['method'] );
		$this->assertSame( 'bot@example.org/token', $capturedOptions['username'] );
		$this->assertSame( 'TOKEN123', $capturedOptions['password'] );
		$this->assertArrayHasKey( 'proxy', $capturedOptions );
		$this->assertNull( $capturedOptions['proxy'] );

		// Payload
		$payload = json_decode( $capturedOptions['postData'], true );
		$this->assertSame( 'Account Recovery', $payload['request']['subject'] );
		$this->assertSame( 'incident', $payload['request']['type'] );
		$this->assertSame( 'normal', $payload['request']['priority'] );
		$this->assertSame( 1234567890, $payload['request']['ticket_form_id'] );
		$this->assertSame( 'user@domain.test', $payload['request']['requester']['email'] );
		$this->assertNotEmpty( $payload['request']['comment']['body'] );

		// Conditional fields
		$this->assertSame( 'Alice', $payload['request']['requester']['name'] );

		// Custom fields should have placeholders replaced
		$this->assertContains(
			[ 'id' => 100, 'value' => 'static_value' ],
			$payload['request']['custom_fields']
		);
		$this->assertContains(
			[ 'id' => 200, 'value' => 'Alice' ],
			$payload['request']['custom_fields']
		);
		$this->assertContains(
			[ 'id' => 300, 'value' => 'alice@registered.test' ],
			$payload['request']['custom_fields']
		);

		// Tags should be configured
		$this->assertSame( [ 'test_tag' ], $payload['request']['tags'] );

		// Success StatusValue
		$this->assertTrue( $status->isOK() );
	}

	/**
	 * Data provider for Zendesk error code mapping test.
	 *
	 * @return array<string, array{string, string}>
	 */
	public static function provideZendeskErrorCodes(): array {
		return [
			'InvalidEmail' => [
				'InvalidEmail',
				'emailauth-accountrecovery-error-invalid-data',
			],
			'RecordInvalid' => [
				'RecordInvalid',
				'emailauth-accountrecovery-error-invalid-data',
			],
			'TooManyRequests' => [
				'TooManyRequests',
				'emailauth-accountrecovery-rate-limited',
			],
			'RateLimited' => [
				'RateLimited',
				'emailauth-accountrecovery-rate-limited',
			],
			'Unauthorized' => [
				'Unauthorized',
				'emailauth-accountrecovery-error-service-unavailable',
			],
			'Forbidden' => [
				'Forbidden',
				'emailauth-accountrecovery-error-service-unavailable',
			],
			'UnknownError' => [
				'SomeUnmappedError',
				'emailauth-accountrecovery-error-generic',
			],
		];
	}

	/**
	 * Test that Zendesk API error codes are correctly mapped to MediaWiki message keys.
	 *
	 * @dataProvider provideZendeskErrorCodes
	 */
	public function testCreateTicketMapsZendeskErrorCodes(
		string $zendeskError,
		string $expectedMessageKey
	): void {
		$client = $this->makeClient();

		$this->httpRequestFactory->method( 'create' )->willReturn( $this->request );

		// Mock a 400-level error response with JSON body matching Zendesk API format
		$this->request->method( 'execute' )->willReturn( Status::newFatal( 'http-bad-status' ) );
		$this->request->method( 'getStatus' )->willReturn( 400 );
		$this->request->method( 'getResponseHeader' )->willReturn( 'application/json' );
		$this->request->method( 'getContent' )->willReturn( json_encode( [
			'error' => $zendeskError,
			'description' => 'Test error description',
		] ) );

		$status = $client->createTicket( [
			'requester_email' => 'user@example.test',
			'requester_name' => 'TestUser',
		] );

		$this->assertFalse( $status->isOK() );

		$errors = $status->getErrors();
		$this->assertCount( 1, $errors );
		$this->assertSame( $expectedMessageKey, $errors[0]['message'] );
	}

}
