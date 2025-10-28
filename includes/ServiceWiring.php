<?php

use MediaWiki\Config\ServiceOptions;
use MediaWiki\Extension\EmailAuth\AccountRecovery\Zendesk\ZendeskClient;
use MediaWiki\Logger\LoggerFactory;
use MediaWiki\MediaWikiServices;
use Psr\Log\LoggerInterface;

/**
 * Service wiring for EmailAuth extension
 * @phpcs-require-sorted-array
 */
return [
	'EmailAuth.AuthenticationLogger' => static function ( MediaWikiServices $services ): LoggerInterface {
		return LoggerFactory::getInstance( 'authentication' );
	},
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
