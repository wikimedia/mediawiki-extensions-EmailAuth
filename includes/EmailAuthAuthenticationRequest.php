<?php

namespace MediaWiki\Extension\EmailAuth;

use MediaWiki\Auth\AuthenticationRequest;

class EmailAuthAuthenticationRequest extends AuthenticationRequest {
	/** @var string */
	public $token;

	/**
	 * @inheritDoc
	 */
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
