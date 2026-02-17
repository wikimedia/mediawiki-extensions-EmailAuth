<?php

namespace MediaWiki\Extension\EmailAuth;

use MediaWiki\CheckUser\Services\CheckUserInsert;
use MediaWiki\Logging\ManualLogEntry;
use MediaWiki\MediaWikiServices;
use MediaWiki\Page\PageReferenceValue;
use MediaWiki\Registration\ExtensionRegistry;
use MediaWiki\User\UserIdentity;

class EmailAuthCheckUserLogger {

	public function __construct(
		private readonly ExtensionRegistry $extensionRegistry,
	) {
	}

	/**
	 * Creates a CheckUser-only log entry for a failed email verification attempt.
	 *
	 * This method performs database writes. It should only be called in a POST
	 * request context to avoid TransactionProfiler warnings (see T417629).
	 */
	public function logFailedVerification( UserIdentity $user ): void {
		if ( !$this->extensionRegistry->isLoaded( 'CheckUser' ) ) {
			return;
		}

		$logEntry = new ManualLogEntry( 'emailauth', 'verify-failed' );
		$logEntry->setPerformer( $user );
		$logEntry->setTarget(
			PageReferenceValue::localReference( NS_USER, $user->getName() )
		);

		/** @var CheckUserInsert $checkUserInsert */
		$checkUserInsert = MediaWikiServices::getInstance()->get( 'CheckUserInsert' );
		$checkUserInsert->updateCheckUserData( $logEntry->getRecentChange() );
	}
}
