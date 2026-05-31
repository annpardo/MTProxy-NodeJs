'use strict'

module.exports = {
	// The platform port is usually supplied by PORT or SERVER_PORT.
	PORT: 443,

	// name -> 32 hex chars
	USERS: {
		tg: '0123456789abcdef0123456789abcdef',
	},

	MODES: {
		classic: false,
		secure: false,
		tls: true,
	},

	// Used only when MODES.tls is true. The full ee-secret is generated from it.
	TLS_DOMAIN: 'www.cloudflare.com',

	// 16-byte ad tag from @MTProxybot. Leave empty/zeroed if you do not use ads.
	AD_TAG: '00000000000000000000000000000000',

	// Optional. Leave commented/undefined for automatic behavior:
	// no AD_TAG -> direct Telegram DC, valid AD_TAG -> middle proxy.
	// USE_MIDDLE_PROXY: false,

	NUM_CPUS: 1,
	POOL_SIZE: 4,
	FAST_MODE: true,
	// Direct mode defaults to IPv6 when the server has public IPv6.
	// Middle proxy mode defaults to IPv4 unless you set this to true.
	PREFER_IPV6: undefined,

	// Show periodic stats like: tg: 51 connects (0 current), 0.16 MB, 206 msgs
	SHOW_STATS: true,

	// Show live bytes/messages for active clients on /clients. Disable for lowest CPU/IPC overhead.
	LIVE_STATS: true,
	LIVE_STATS_INTERVAL_SEC: 15,

	// Limit how many active client rows /clients renders.
	CLIENTS_PAGE_LIMIT: 200,

	// Restart workers every day at AUTO_RESTART_TIME. Keeps the master process alive.
	AUTO_RESTART: true,
	AUTO_RESTART_TIME: '00:03',

	// Set true only when you need detailed per-client connection logs.
	LOG_CLIENTS: false,
}
