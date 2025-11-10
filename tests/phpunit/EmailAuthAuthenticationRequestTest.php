<?php

namespace MediaWiki\Extension\EmailAuth\Tests;

use MediaWiki\Extension\EmailAuth\EmailAuthAuthenticationRequest;
use MediaWiki\Tests\Auth\AuthenticationRequestTestCase;

/**
 * @covers \MediaWiki\Extension\EmailAuth\EmailAuthAuthenticationRequest
 */
class EmailAuthAuthenticationRequestTest extends AuthenticationRequestTestCase {
	protected function getInstance( array $args = [] ) {
		return new EmailAuthAuthenticationRequest();
	}

	public static function provideLoadFromSubmission() {
		return [
			[ [], [], false ],
			[ [], [ 'token' => 'foo' ], [ 'token' => 'foo' ] ],
			[ [], [ 'token' => ' foo ' ], [ 'token' => 'foo' ] ],
			[ [], [ 'token' => "foo\n" ], [ 'token' => 'foo' ] ],
		];
	}
}
