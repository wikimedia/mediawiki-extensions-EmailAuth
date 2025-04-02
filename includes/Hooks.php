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
				'size' => 6,
				'autofocus' => true,
				'persistent' => false,
				'autocomplete' => false,
				'spellcheck' => false,
				'help' => wfMessage( 'emailauth-login-help' )
			];
		}
	}
}
