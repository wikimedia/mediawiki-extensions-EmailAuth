<?php

use MediaWiki\Config\ServiceOptions;
use MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk\ZendeskClient;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\MediaWikiServices;

/**
 * Service wiring for EmailAuth extension
 * @phpcs-require-sorted-array
 */
return [
	'EmailAuth.ZendeskClient' => static function ( MediaWikiServices $services ): ZendeskClient {
		return new ZendeskClient(
			$services->getHttpRequestFactory(),
			LoggerFactory::getInstance( 'EmailAuth' ),
			new ServiceOptions(
				ZendeskClient::CONSTRUCTOR_OPTIONS,
				$services->getMainConfig()
			)
		);
	},
];
