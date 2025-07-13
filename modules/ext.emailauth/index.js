// eslint-disable-next-line no-jquery/no-global-selector
$( '#mw-emailauth-verification-code' ).on( 'paste', function ( jqe ) {
	const e = jqe.originalEvent,
		originalCode = e.clipboardData.getData( 'text' ),
		cleanedCode = originalCode.replace( /\D/g, '' );
	this.setRangeText( cleanedCode, this.selectionStart, this.selectionEnd, 'end' );
	e.preventDefault();
} );
