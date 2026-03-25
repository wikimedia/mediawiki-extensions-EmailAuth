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
	 * Creates a CheckUser-only log entry for a successful email verification.
	 *
	 * This method performs database writes. It should only be called in a POST
	 * request context to avoid TransactionProfiler warnings (see T417629).
	 */
	public function logSuccessfulVerification( UserIdentity $user ): void {
		$this->log( $user, $user, 'verify-success' );
	}

	/**
	 * Creates a CheckUser-only log entry for a failed email verification attempt.
	 *
	 * This method performs database writes. It should only be called in a POST
	 * request context to avoid TransactionProfiler warnings (see T417629).
	 */
	public function logFailedVerification( UserIdentity $user, UserIdentity $performer ): void {
		$this->log( $user, $performer, 'verify-failure' );
	}

	/**
	 * Creates a CheckUser-only log entry for an account recovery request submission.
	 *
	 * This method performs database writes. It should only be called in a POST
	 * request context to avoid TransactionProfiler warnings (see T417629).
	 */
	public function logAccountRecoverySubmission( UserIdentity $user, UserIdentity $performer ): void {
		$this->log( $user, $performer, 'account-recovery-submit' );
	}

	private function log( UserIdentity $user, UserIdentity $performer, string $action ): void {
		if ( !$this->extensionRegistry->isLoaded( 'CheckUser' ) ) {
			return;
		}

		$logEntry = new ManualLogEntry( 'emailauth', $action );
		$logEntry->setPerformer( $performer );
		$logEntry->setTarget(
			PageReferenceValue::localReference( NS_USER, $user->getName() )
		);
		$logEntry->setParameters( [ '4:user-link:user' => $user->getName() ] );

		/** @var CheckUserInsert $checkUserInsert */
		$checkUserInsert = MediaWikiServices::getInstance()->get( 'CheckUserInsert' );
		$checkUserInsert->updateCheckUserData( $logEntry->getRecentChange() );
	}
}
