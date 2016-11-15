<?php

namespace MediaWiki\Extensions\EmailAuth;

use MediaWiki\Auth\AuthenticationRequest;
use Message;

class EmailAuthAuthenticationRequest extends AuthenticationRequest  {
	public $token;

	public function getFieldInfo() {
		return [
			'token' => [
				'type' => 'string',
				'label' => wfMessage( 'emailauth-token-label' ),
				'help' => wfMessage( 'emailauth-token-help' ),
			],
		];
	}
}
