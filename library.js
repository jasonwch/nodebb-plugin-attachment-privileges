'use strict';

const path = require('path');

const plugin = module.exports;

const posts = nodebb.require('./src/posts');
const privileges = nodebb.require('./src/privileges');
const meta = nodebb.require('./src/meta');
const winston = nodebb.require('winston');
const routeHelpers = nodebb.require('./src/routes/helpers');

const PLUGIN_HASH = 'attachment-privileges';
const PRIVILEGE = 'topics:read';
const ROUTE_PREFIX = '/assets/uploads/files/';

const DENY = { allowed: false, status: 403 };
const DENY_SERVER_ERROR = { allowed: false, status: 500 };
const ALLOW = { allowed: true, status: 0 };

const ALLOW_CC = 'private, no-cache';
const DENY_CC = 'private, no-store';
const VARY_COOKIE = 'Cookie';

const stats = { allow: 0, deny: 0 };

async function isEnabled() {
	try {
		const settings = await meta.settings.get(PLUGIN_HASH);
		return !settings || settings.enabled !== 'off';
	} catch (e) {
		return true;
	}
}

async function checkAccess(filePath, uid) {
	let usages;
	try {
		usages = await posts.uploads.getUsage([{ path: filePath }]);
	} catch (e) {
		winston.error('[attachment-privileges] getUsage failed for ' + filePath + ': ' + e.message);
		return DENY_SERVER_ERROR;
	}

	const pids = usages && usages[0];
	if (!pids || !pids.length) {
		return ALLOW;
	}

	let cids;
	try {
		const rawCids = await posts.getCidsByPids(pids);
		cids = Array.from(new Set(rawCids.filter(Boolean)));
	} catch (e) {
		winston.error('[attachment-privileges] getCidsByPids failed: ' + e.message);
		return DENY_SERVER_ERROR;
	}

	if (!cids.length) {
		return ALLOW;
	}

	try {
		const accessible = await privileges.categories.filterCids(PRIVILEGE, cids, uid);
		return accessible && accessible.length > 0 ? ALLOW : DENY;
	} catch (e) {
		winston.error('[attachment-privileges] filterCids failed for cids=' + cids.join(',') + ' uid=' + uid + ': ' + e.message);
		return DENY_SERVER_ERROR;
	}
}

plugin.init = async function (params) {
	const { router } = params;

	await meta.settings.setOnEmpty(PLUGIN_HASH, { enabled: 'on' });

	router.get('/assets/uploads/files/*', async function guard(req, res, next) {
		try {
			const enabled = await isEnabled();
			if (!enabled) {
				return next();
			}

			const rawPath = req.path;
			if (!rawPath || !rawPath.startsWith(ROUTE_PREFIX)) {
				return res.status(403).json('not-allowed');
			}

			let filename;
			try {
				filename = decodeURIComponent(rawPath.slice(ROUTE_PREFIX.length));
			} catch (e) {
				return res.status(400).json('bad-request');
			}

			filename = path.basename(filename);
			if (!filename) {
				return res.status(403).json('not-allowed');
			}

			const filePath = 'files/' + filename;
			const uid = req.uid || 0;

			const result = await checkAccess(filePath, uid);

			if (result.allowed) {
				stats.allow++;
				res.setHeader('Cache-Control', ALLOW_CC);
				res.vary(VARY_COOKIE);

				const _setHeader = res.setHeader.bind(res);
				res.setHeader = function (name, value) {
					if (name.toLowerCase() === 'cache-control' && res.getHeader('cache-control')) {
						return res;
					}
					return _setHeader(name, value);
				};

				return next();
			}

			stats.deny++;
			res.setHeader('Cache-Control', DENY_CC);
			res.vary(VARY_COOKIE);
			return res.status(result.status).json('not-allowed');
		} catch (e) {
			winston.error('[attachment-privileges] guard error: ' + e.message);
			stats.deny++;
			res.setHeader('Cache-Control', DENY_CC);
			res.vary(VARY_COOKIE);
			return res.status(500).json('server-error');
		}
	});

	routeHelpers.setupAdminPageRoute(router, '/admin/plugins/attachment-privileges', renderAdmin);

	const SocketAdmin = nodebb.require('./src/socket.io/admin');
	SocketAdmin.plugins.getAttachmentPrivilegesStats = async function () {
		return { allow: stats.allow, deny: stats.deny };
	};
};

async function renderAdmin(req, res) {
	res.render('admin/plugins/attachment-privileges', {
		title: 'attachment-privileges:plugin-name',
	});
}

plugin.addAdminNavigation = async function (header) {
	header.plugins.push({
		route: '/plugins/attachment-privileges',
		icon: 'fa-lock',
		name: 'attachment-privileges:plugin-name',
	});
	return header;
};