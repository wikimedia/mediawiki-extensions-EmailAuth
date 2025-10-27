<?php

namespace MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk;

use MediaWiki\Config\ServiceOptions;
use MediaWiki\Http\HttpRequestFactory;
use Psr\Log\LoggerInterface;
use StatusValue;

/**
 * Client class to create Zendesk tickets from Account Recovery requests.
 */
class ZendeskClient {

	public const CONSTRUCTOR_OPTIONS = [
		'EmailAuthZendeskUrl',
		'EmailAuthZendeskHTTPProxy',
		'EmailAuthZendeskSubjectLine',
		'EmailAuthZendeskEmail',
		'EmailAuthZendeskToken',
		'EmailAuthZendeskTicketFormId',
		'EmailAuthZendeskCustomFields',
		'EmailAuthZendeskTags'
	];

	public function __construct(
		private readonly HttpRequestFactory $httpRequestFactory,
		private readonly LoggerInterface $logger,
		private readonly ServiceOptions $serviceOptions,
	) {
		$serviceOptions->assertRequiredOptions( self::CONSTRUCTOR_OPTIONS );
	}

	/**
	 * Create a Zendesk ticket for the given account recovery request.
	 *
	 * @param array $ticketData Ticket data with keys:
	 *   - requester_email: string Email address to contact the requester
	 *   - requester_name: string Username of the account to recover
	 *   - registered_email: string|null Email registered with the account (optional)
	 *   - description: string|null Additional comments from the requester (optional)
	 * @return StatusValue
	 */
	public function createTicket( array $ticketData ): StatusValue {
		$subject = $this->serviceOptions->get( 'EmailAuthZendeskSubjectLine' );

		$body = $this->formatTicketBody( $ticketData );

		// Refer to https://developer.zendesk.com/api-reference/ticketing/tickets/ticket-requests/#create-request
		// for the exact payload taken by the request creation endpoint.
		$tags = $this->serviceOptions->get( 'EmailAuthZendeskTags' ) ?? [];
		$customFields = $this->serviceOptions->get( 'EmailAuthZendeskCustomFields' ) ?? [];

		// Process custom fields: replace placeholders with actual values from ticket data
		$processedCustomFields = [];
		foreach ( $customFields as $field ) {
			$value = $field['value'] ?? '';

			// Replace placeholders with actual values
			$value = str_replace( '{username}', $ticketData['requester_name'] ?? '', $value );
			$value = str_replace( '{registered_email}', $ticketData['registered_email'] ?? '', $value );

			// Only include fields with non-empty values
			if ( $value !== '' ) {
				$processedCustomFields[] = [
					'id' => $field['id'],
					'value' => $value
				];
			}
		}

		$payload = [
			'request' => [
				'subject' => $subject,
				'type' => 'incident',
				'priority' => 'normal',
				'tags' => $tags,
				'ticket_form_id' => $this->serviceOptions->get( 'EmailAuthZendeskTicketFormId' ),
				'comment' => [
					'body' => $body,
				],
				'requester' => [
					'email' => $ticketData['requester_email'],
				],
				'custom_fields' => $processedCustomFields,
			],
		];

		// Add requester name if username is provided
		if ( !empty( $ticketData['requester_name'] ) ) {
			$payload['request']['requester']['name'] = $ticketData['requester_name'];
		}

		$url = $this->serviceOptions->get( 'EmailAuthZendeskUrl' ) . '/api/v2/requests.json';

		$email = $this->serviceOptions->get( 'EmailAuthZendeskEmail' );
		$token = $this->serviceOptions->get( 'EmailAuthZendeskToken' );

		$requestOptions = [
			'method' => 'POST',
			'postData' => json_encode( $payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES ),
			'proxy' => $this->serviceOptions->get( 'EmailAuthZendeskHTTPProxy' ),
			'username' => $email . '/token',
			'password' => $token,
			'timeout' => 30,
			'connectTimeout' => 10,
		];

		$request = $this->httpRequestFactory->create( $url, $requestOptions, __METHOD__ );
		$request->setHeader( 'Content-Type', 'application/json' );
		$request->setHeader( 'Accept', 'application/json' );
		$request->setHeader( 'User-Agent', 'MediaWiki-EmailAuth/1.0' );

		$response = $request->execute();

		if ( $response->isOK() ) {
			$this->logger->info( 'Zendesk ticket created for account recovery request' );
			return StatusValue::newGood();
		}

		$httpStatus = $request->getStatus();
		$responseContent = $request->getContent() ?? '';
		$contentType = $request->getResponseHeader( 'Content-Type' ) ?? '';
		$isJSON = str_starts_with( strtolower( $contentType ), 'application/json' );

		// Handle HTTP 429 (Too Many Requests) explicitly
		// This ensures rate limiting is detected even without valid JSON response
		if ( $httpStatus === 429 ) {
			$this->logger->warning(
				'Zendesk rate limit hit for account recovery',
				[ 'status' => $httpStatus ]
			);
			return StatusValue::newFatal( 'emailauth-accountrecovery-rate-limited' );
		}

		// Attempt to parse Zendesk API errors if we get a JSON error response back with a 4xx status.
		// https://developer.zendesk.com/api-reference/introduction/requests/#400-range
		if ( $isJSON && $httpStatus >= 400 && $httpStatus < 500 ) {
			$errorJson = json_decode( $responseContent, true );
			if ( $errorJson !== null ) {
				$error = $errorJson['error'] ?? 'Unknown error';
				$description = $errorJson['description'] ?? 'No description';

				$this->logger->error(
					"Zendesk error while creating account recovery ticket: \"$error\" ($description)",
					[ 'status' => $httpStatus, 'error_code' => $error ]
				);

				// Map common Zendesk errors to user-friendly messages
				$errorMessageKey = match ( $error ) {
					'InvalidEmail', 'RecordInvalid' => 'emailauth-accountrecovery-error-invalid-data',
					'TooManyRequests', 'RateLimited' => 'emailauth-accountrecovery-rate-limited',
					'Unauthorized', 'Forbidden' => 'emailauth-accountrecovery-error-service-unavailable',
					default => 'emailauth-accountrecovery-error-generic',
				};

				return StatusValue::newFatal( $errorMessageKey );
			}
		}

		$this->logger->error(
			'Unknown Zendesk error while creating account recovery ticket',
			[
				'status' => $httpStatus,
				'content_length' => strlen( $responseContent ),
				'content_hash' => hash( 'sha256', $responseContent )
			]
		);

		return StatusValue::newFatal( 'emailauth-accountrecovery-error-generic' );
	}

	/**
	 * Format the ticket data into a ticket body.
	 *
	 * @param array $ticketData Ticket data with requester_name, registered_email, requester_email, description
	 * @return string
	 */
	private function formatTicketBody( array $ticketData ): string {
		$subject = $this->serviceOptions->get( 'EmailAuthZendeskSubjectLine' );
		$body = $subject . "\n\n";

		if ( !empty( $ticketData['requester_name'] ) ) {
			$body .= "Username: " . $ticketData['requester_name'] . "\n";
		}

		if ( !empty( $ticketData['registered_email'] ) ) {
			$body .= "Email registered with account: " . $ticketData['registered_email'] . "\n";
		}

		$body .= "Contact email: " . $ticketData['requester_email'] . "\n\n";

		$body .= "Additional comments:\n" . ( $ticketData['description'] ?? 'None provided' );

		return $body;
	}
}
