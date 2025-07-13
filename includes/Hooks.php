<?php

namespace MediaWiki\Extension\EmailAuth;

use MediaWiki\Auth\AuthenticationRequest;
use MediaWiki\SpecialPage\Hook\AuthChangeFormFieldsHook;

class Hooks implements AuthChangeFormFieldsHook {

	/** @inheritDoc */
	public function onAuthChangeFormFields(
		$requests, $fieldInfo, &$formDescriptor, $action
	) {
		if ( AuthenticationRequest::getRequestByClass( $requests, EmailAuthAuthenticationRequest::class ) ) {
			$formDescriptor['token'] += [
				'id' => 'mw-emailauth-verification-code',
				'class' => HTMLVerificationCodeField::class,
				'code-length' => 6,
				'help' => wfMessage( 'emailauth-login-help' ),
			];
		}
	}
}
