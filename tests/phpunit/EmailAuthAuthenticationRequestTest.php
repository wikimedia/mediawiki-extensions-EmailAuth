<?php

namespace MediaWiki\Extensions\EmailAuth;

use MediaWiki\Auth\AuthenticationRequestTestCase;

class EmailAuthAuthenticationRequestTest extends AuthenticationRequestTestCase {
	protected function getInstance( array $args = [] ) {
		return new EmailAuthAuthenticationRequest();
	}

	public function provideLoadFromSubmission() {
		return [
			[ [], [], false ],
			[ [], [ 'token' => 'foo' ], [ 'token' => 'foo' ] ],
		];
	}
}
