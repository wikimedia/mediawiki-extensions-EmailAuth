<?php

namespace MediaWiki\Extension\EmailAuth;

use MediaWiki\HTMLForm\Field\HTMLTextField;

/**
 * Form field for entering a numeric verification code.
 */
class HTMLVerificationCodeField extends HTMLTextField {

	/** Number of digits in the code */
	private int $codeLength;

	/**
	 * Apart from normal HTMLTextField parameters, recognizes the following keys:
	 * - code-length: the number of digits in the verification code
	 * @see HTMLTextField
	 */
	public function __construct( array $params ) {
		$this->codeLength = $params['code-length'];
		$params += [
			'autofocus' => true,

			// expect numeric input
			'size' => $this->codeLength,
			'inputmode' => 'numeric',
			// '*' is more widely understood than '{n}'
			'pattern' => '[0-9]*',

			// disable autofill etc.
			'persistent' => false,
			'autocomplete' => 'one-time-code',
			'spellcheck' => false,
		];
		parent::__construct( $params );
	}

	/** @inheritDoc */
	public function getInputCodex( $value, $hasErrors ) {
		$out = $this->mParent->getOutput();
		$out->addModules( 'ext.emailauth' );
		return parent::getInputCodex( $value, $hasErrors );
	}

}
