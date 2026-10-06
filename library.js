'use strict';

const path = require('path');
const crypto = require('crypto');

const plugin = module.exports;

const posts = nodebb.require('./src/posts');
const privileges = nodebb.require('./src/privileges');
const meta = nodebb.require('./src/meta');
const winston = nodebb.require('winston');
const routeHelpers = nodebb.require('./src/routes/helpers');
const db = nodebb.require('./src/database');
const messaging = nodebb.require('./src/messaging');
const groups = nodebb.require('./src/groups');
const user = nodebb.require('./src/user');
const file = nodebb.require('./src/file');
const nconf = nodebb.require('nconf');
const cron = nodebb.require('./src/cron');

const PLUGIN_HASH = 'attachment-privileges';
const PRIVILEGE = 'topics:read';
const ROUTE_PREFIX = '/assets/uploads/files/';
// Matches both the canonical (/assets/uploads/files/...) and legacy (/uploads/files/...) URL forms.
// '@', '?' and '#' are excluded (aligned with current core master): stored filenames are
// slugified and can never contain them, and a query string/fragment glued onto a URL
// would otherwise corrupt the parsed filename and silently skip the association.
const UPLOADS_IN_TEXT_REGEX = /(?:\/assets)?\/uploads(\/files\/[^\s")@?#]+\.?[\w]*)/;
// Plugin-side per-message association record; survives message purge (unlike message:<mid> itself)
const MESSAGE_ASSOC_KEY = 'attachment-privileges:message:';
// Plugin-side chat-usage sets, kept in the plugin's own key namespace so they can
// never collide with core's upload:<md5> object or upload:<md5>:pids sorted set
const UPLOAD_ASSOC_KEY = 'attachment-privileges:upload:';
const ASSOC_MIDS_SUFFIX = ':mids';
const ASSOC_ROOMS_SUFFIX = ':rooms';
// Durability: mids whose association write failed (for retry), and a high-water
// mark of processed chat messages (for the boot-time catch-up that covers the
// fire-and-forget window between core persisting a message and the association write)
const RETRY_KEY = 'attachment-privileges:retry';
const LAST_PROCESSED_KEY = 'attachment-privileges:lastProcessed';
const CATCHUP_OVERLAP_MS = 60 * 1000; // re-scan margin for out-of-order timestamps
const CATCHUP_MAX_LOOKBACK_MS = 48 * 60 * 60 * 1000; // bounded catch-up window
const RETRY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // poison-entry retention
const RETRY_DELAYS = [5 * 1000, 60 * 1000, 5 * 60 * 1000]; // in-process backoff schedule

const DENY = { allowed: false, status: 403 };
const DENY_SERVER_ERROR = { allowed: false, status: 500 };
const ALLOW_PUBLIC = { allowed: true, status: 0, worldReadable: true };
const ALLOW_RESTRICTED = { allowed: true, status: 0, worldReadable: false };

// Allowed files: browser reuses its local copy within the TTL (no server contact,
// no proxy involvement), then must revalidate — including on reload — so the
// guard re-checks access. must-revalidate also forbids serving the stale copy
// while the origin is unreachable; revocation lag is therefore bounded by max-age.
const PUBLIC_CC = 'public, must-revalidate, no-transform, max-age=900, s-maxage=60';
const RESTRICTED_ALLOW_CC = 'private, must-revalidate, no-transform, max-age=900';
// Denials and errors must never be negatively cached: a user granted access
// after a denial is re-checked on the very next request.
const RESTRICTED_CC = 'private, no-cache';
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

const md5 = text => crypto.createHash('md5').update(text).digest('hex');

// Mirrors core's derivation (posts.uploads.getUsage / user.associateUpload):
// '/files/<name>' with '-resized' stripped
function uploadMd5(filePath) {
	const normalized = `/${String(filePath).split(path.sep).join(path.posix.sep)}`;
	return md5(normalized.replace('-resized', ''));
}

// Core's read-only upload metadata key (holds the uploader's uid)
function coreUploadKey(filePath) {
	return `upload:${uploadMd5(filePath)}`;
}

// Plugin-side association set keys
function assocMidsKey(filePath) {
	return `${UPLOAD_ASSOC_KEY}${uploadMd5(filePath)}${ASSOC_MIDS_SUFFIX}`;
}

function assocRoomsKey(filePath) {
	return `${UPLOAD_ASSOC_KEY}${uploadMd5(filePath)}${ASSOC_ROOMS_SUFFIX}`;
}

function parseUploadsFromContent(content) {
	const uploads = new Set();
	const regex = new RegExp(UPLOADS_IN_TEXT_REGEX.source, 'g');
	let match;
	while ((match = regex.exec(String(content || ''))) !== null) {
		const name = path.posix.basename(match[1].replace('-resized', ''));
		if (name && name !== '.' && name !== '..') {
			uploads.add(`files/${name}`);
		}
	}
	return Array.from(uploads);
}

async function filterExistingUploads(filePaths) {
	const uploadPath = nconf.get('upload_path');
	return (await Promise.all(filePaths.map(async (filePath) => {
		const fullPath = path.join(uploadPath, filePath);
		const valid = file.isPathInside(uploadPath, fullPath) && await file.exists(fullPath);
		return valid ? filePath : null;
	}))).filter(Boolean);
}

// Ownership check: the uploader of a file never loses fetch access to their
// own upload, mirroring core's upload ownership model (uploads panel, User.deleteUpload)
async function isFileUploader(filePath, uid) {
	if (!uid || uid <= 0) {
		return false;
	}
	try {
		const uploaderUid = await db.getObjectField(coreUploadKey(filePath), 'uid');
		return !!uploaderUid && String(uploaderUid) === String(uid);
	} catch (e) {
		return false;
	}
}

// Decides whether `uid` may bind `filePath` to a chat room (message save/edit):
// - admins and the file's uploader always may;
// - a file with no usage anywhere (no posts, no chat rooms) may only be
//   introduced by its uploader or an admin, since "unassociated => public"
//   is a default, not an authorization — otherwise any user could restrict
//   (brick) someone else's abandoned upload by pasting its URL into a room;
// - otherwise the introducer must already have access to the file
//   (category access, or membership of a room the file is already bound to)
// Lookup errors intentionally propagate: the caller records a retry so that a
// transient failure does not silently leave the attachment unassociated (fail-open)
async function canIntroduce(filePath, uid) {
	if (!uid || uid <= 0) {
		return false;
	}
	if (await user.isAdministrator(uid)) {
		return true;
	}
	if (await isFileUploader(filePath, uid)) {
		return true;
	}
	const usages = await posts.uploads.getUsage([{ path: filePath }]);
	const pids = usages && usages[0];
	const roomIds = await db.getSortedSetRange(assocRoomsKey(filePath), 0, -1);
	if ((!pids || !pids.length) && (!roomIds || !roomIds.length)) {
		return false; // unassociated: uploader/admin only
	}
	const result = await checkAccess(filePath, uid);
	// Structural check (not object identity): a future refactor of checkAccess
	// returning a fresh {allowed:false, status:500} literal must still be
	// treated as "unavailable" here, otherwise a transient failure would be
	// indistinguishable from a legitimate gate rejection (fail-open)
	if (!result || result.status === DENY_SERVER_ERROR.status) {
		throw new Error('access check unavailable for ' + filePath);
	}
	return !!result.allowed;
}

async function removeRoomIfUnused(filePath, roomId) {
	const mids = await db.getSortedSetRange(assocMidsKey(filePath), 0, -1);
	if (!mids || !mids.length) {
		await db.sortedSetRemove(assocRoomsKey(filePath), roomId);
		return;
	}
	const messageRooms = await db.getObjectsFields(mids.map(mid => `message:${mid}`), ['roomId']);
	const stillUsed = messageRooms.some(room => room && String(room.roomId) === String(roomId));
	if (!stillUsed) {
		await db.sortedSetRemove(assocRoomsKey(filePath), roomId);
	}
}

// Brings the plugin's records for a message in line with its current content.
// Single primitive used by message saves, message edits, and retry/catch-up
// healing (all idempotent).
async function reconcileMessageAssociations(message) {
	const mid = String(message.mid);
	const stored = await db.getObject(`${MESSAGE_ASSOC_KEY}${mid}`);
	const roomId = String((message && message.roomId) || (stored && stored.roomId) || '');
	if (!roomId) {
		return;
	}
	let previous = [];
	try {
		previous = JSON.parse((stored && stored.uploads) || '[]');
	} catch (e) {
		previous = [];
	}
	const parsed = await filterExistingUploads(parseUploadsFromContent(message.content));
	const current = [];
	for (const filePath of parsed) {
		// Previously associated files keep their association (point-in-time grants);
		// only newly added references pass the introducer gate
		if (previous.includes(filePath) || await canIntroduce(filePath, message.fromuid)) {
			current.push(filePath);
		}
	}
	const removed = previous.filter(filePath => !current.includes(filePath));
	const now = Date.now();

	if (!current.length && !previous.length) {
		return;
	}
	await db.setObject(`${MESSAGE_ASSOC_KEY}${mid}`, { roomId: roomId, uploads: JSON.stringify(current) });
	// Upsert ALL current files (not just newly added ones) so that partial
	// writes from an earlier failed attempt are healed as well
	if (current.length) {
		await Promise.all([
			db.sortedSetAddBulk(current.map(filePath => [assocMidsKey(filePath), now, mid])),
			db.sortedSetAddBulk(current.map(filePath => [assocRoomsKey(filePath), now, roomId])),
		]);
	}
	for (const filePath of removed) {
		await db.sortedSetRemove(assocMidsKey(filePath), mid);
		await removeRoomIfUnused(filePath, roomId);
	}
}

async function dissociateMessage(message) {
	const mid = String(message.mid);
	const stored = await db.getObject(`${MESSAGE_ASSOC_KEY}${mid}`);
	if (!stored) {
		return;
	}
	const roomId = String(stored.roomId || message.roomId || '');
	let uploads = [];
	try {
		uploads = JSON.parse(stored.uploads || '[]');
	} catch (e) {
		uploads = [];
	}
	await Promise.all([
		db.delete(`${MESSAGE_ASSOC_KEY}${mid}`),
		...uploads.map(filePath => db.sortedSetRemove(assocMidsKey(filePath), mid)),
	]);
	for (const filePath of uploads) {
		await removeRoomIfUnused(filePath, roomId);
	}
}

// Returns null when the file has no chat-room associations — i.e. unassociated;
// otherwise true/false for allowed/denied. Mirrors core messaging loadRoom() semantics;
// chat usage is never world-readable (chats are login-gated).
async function checkChatAccess(filePath, uid) {
	const roomIds = await db.getSortedSetRange(assocRoomsKey(filePath), 0, -1);
	if (!roomIds || !roomIds.length) {
		return null; // unassociated
	}
	const rooms = await messaging.getRoomsData(roomIds);
	const validRooms = [];
	rooms.forEach((room, index) => {
		if (room) {
			validRooms.push({ roomId: String(roomIds[index]), room: room });
		}
	});
	if (!validRooms.length) {
		// Associations exist but every referenced room has been deleted:
		// fail closed — returning null here would make the file world-readable
		return false;
	}
	if (!uid || uid <= 0) {
		return false; // guests never (chats are login-gated)
	}
	// Mirrors core loadRoom: loading any room (public or private) requires chat privileges
	const canChat = await privileges.global.can(['chat', 'chat:privileged'], uid);
	if (!canChat || !canChat.includes(true)) {
		return false;
	}

	const publicRooms = validRooms.filter(({ room }) => room.public);
	const privateRooms = validRooms.filter(({ room }) => !room.public);

	if (publicRooms.length) {
		// unrestricted public room: any logged-in user with chat privileges
		if (publicRooms.some(({ room }) => !(Array.isArray(room.groups) && room.groups.length))) {
			return true;
		}
		// group-restricted public room: admins or members of the allowed groups (mirrors core loadRoom)
		const isAdmin = await user.isAdministrator(uid);
		if (isAdmin) {
			return true;
		}
		for (const { room } of publicRooms) {
			if (Array.isArray(room.groups) && room.groups.length && await groups.isMemberOfAny(uid, room.groups)) {
				return true;
			}
		}
	}

	if (privateRooms.length) {
		const isMember = await messaging.isRoomMember(uid, privateRooms.map(({ roomId }) => roomId));
		if (isMember && isMember.some(Boolean)) {
			return true;
		}
	}
	return false;
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
		// No post usage: PM/chat attachment, or an abandoned upload
		try {
			const chatResult = await checkChatAccess(filePath, uid);
			// null ⇒ not associated with any chat room ⇒ unassociated ⇒ public (intended policy)
			if (chatResult === null) {
				return ALLOW_PUBLIC;
			}
			if (chatResult) {
				return ALLOW_RESTRICTED;
			}
			// Ownership: the uploader keeps access to their own upload even when
			// it is only referenced from rooms they cannot read
			if (await isFileUploader(filePath, uid)) {
				return ALLOW_RESTRICTED;
			}
			return DENY;
		} catch (e) {
			winston.error('[attachment-privileges] chat lookup failed for ' + filePath + ': ' + e.message);
			return DENY_SERVER_ERROR;
		}
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
		return ALLOW_PUBLIC;
	}

	try {
		const accessible = await privileges.categories.filterCids(PRIVILEGE, cids, uid);
		if (accessible && accessible.length > 0) {
			const guestAccessible = uid === 0
				? accessible
				: await privileges.categories.filterCids(PRIVILEGE, cids, 0);
			return guestAccessible && guestAccessible.length > 0 ? ALLOW_PUBLIC : ALLOW_RESTRICTED;
		}
		// No category access — fall back to chat-room usage
		// (file may additionally be shared in a room this uid belongs to)
		const chatAllowed = await checkChatAccess(filePath, uid);
		if (chatAllowed === true) {
			return ALLOW_RESTRICTED;
		}
		// Ownership: the uploader keeps access to their own upload even when it
		// has been posted in categories they cannot read
		if (await isFileUploader(filePath, uid)) {
			return ALLOW_RESTRICTED;
		}
		return DENY;
	} catch (e) {
		winston.error('[attachment-privileges] access check failed for cids=' + cids.join(',') + ' uid=' + uid + ': ' + e.message);
		return DENY_SERVER_ERROR;
	}
}

// ---------------------------------------------------------------- durability
// The write path must not fail open: if an association write cannot complete
// (DB error mid-send, or the process dying in the fire-and-forget window before
// the hook runs), the file would be left unassociated => world-readable. Failed
// mids are queued for retry, and a boot-time catch-up re-scans messages saved
// since the last processed high-water mark.

async function advanceLastProcessed(timestamp) {
	if (!timestamp) {
		return;
	}
	try {
		const current = parseInt(await db.get(LAST_PROCESSED_KEY), 10) || 0;
		if (timestamp > current) {
			await db.set(LAST_PROCESSED_KEY, String(timestamp));
		}
	} catch (e) {
		// non-fatal: the catch-up window simply grows
	}
}

const pendingRetries = new Map(); // mid -> in-process timer

async function healMessage(mid) {
	const message = await db.getObject(`message:${mid}`);
	if (!message || message.system || !message.mid || !message.roomId) {
		return; // purged or system message: nothing to associate
	}
	await reconcileMessageAssociations(message);
}

function scheduleRetry(mid, attempt) {
	if (pendingRetries.has(mid)) {
		return;
	}
	const delay = RETRY_DELAYS[Math.min(attempt, RETRY_DELAYS.length - 1)];
	const timer = setTimeout(async () => {
		pendingRetries.delete(mid);
		try {
			await healMessage(mid);
			await db.sortedSetRemove(RETRY_KEY, String(mid));
		} catch (e) {
			winston.error('[attachment-privileges] retry failed for mid ' + mid + ': ' + (e && e.message));
			if (attempt + 1 < RETRY_DELAYS.length) {
				scheduleRetry(mid, attempt + 1);
			}
			// else: stays in the retry set for the next drain (boot catch-up / hourly cron)
		}
	}, delay);
	if (timer.unref) {
		timer.unref();
	}
	pendingRetries.set(mid, timer);
}

async function recordFailure(mid) {
	try {
		await db.sortedSetAdd(RETRY_KEY, Date.now(), String(mid));
	} catch (e) {
		winston.error('[attachment-privileges] could not queue retry for mid ' + mid + ': ' + (e && e.message));
	}
	scheduleRetry(String(mid), 0);
}

async function drainRetrySet() {
	const now = Date.now();
	// drop entries that have been failing for too long (poison protection)
	const expired = await db.getSortedSetRangeByScore(RETRY_KEY, 0, -1, 0, now - RETRY_MAX_AGE_MS);
	if (expired && expired.length) {
		await db.sortedSetRemove(RETRY_KEY, expired.map(mid => String(mid)));
	}
	const mids = await db.getSortedSetRange(RETRY_KEY, 0, -1);
	for (const mid of mids) {
		try {
			await healMessage(mid);
			await db.sortedSetRemove(RETRY_KEY, String(mid));
		} catch (e) {
			winston.error('[attachment-privileges] catch-up retry failed for mid ' + mid + ': ' + (e && e.message));
		}
	}
}

async function runCatchUp() {
	// 1) retry association writes that failed at runtime
	await drainRetrySet();
	// 2) re-scan messages saved since the high-water mark: covers the
	//    fire-and-forget window where the process died before the hook ran
	const now = Date.now();
	const stored = await db.get(LAST_PROCESSED_KEY);
	if (stored === null || stored === undefined || isNaN(parseInt(stored, 10))) {
		// first run: no backfill — only messages saved from now on are tracked.
		// compare-and-max: never write below a mark a concurrent save may have created
		await advanceLastProcessed(now);
		return;
	}
	const since = parseInt(stored, 10);
	const from = Math.max(since - CATCHUP_OVERLAP_MS, now - CATCHUP_MAX_LOOKBACK_MS);
	if (now - since > CATCHUP_MAX_LOOKBACK_MS) {
		winston.warn('[attachment-privileges] catch-up window capped at ' + (CATCHUP_MAX_LOOKBACK_MS / 3600000) + 'h');
	}
	const mids = await db.getSortedSetRangeByScore('messages:mid', 0, -1, from, now);
	for (const mid of mids) {
		try {
			await healMessage(mid);
		} catch (e) {
			winston.error('[attachment-privileges] catch-up failed for mid ' + mid + ': ' + (e && e.message));
			try {
				await db.sortedSetAdd(RETRY_KEY, Date.now(), String(mid));
			} catch (e2) {
				// retried by the next drain
			}
		}
	}
	// compare-and-max with the post-scan time (not the scan-start value): a live
	// save that advanced the mark while the scan was running must never be
	// overwritten backwards
	await advanceLastProcessed(Date.now());
}

// internal: exposed for tests and operational drain
plugin._runCatchUp = runCatchUp;

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
				res.setHeader('Cache-Control', result.worldReadable ? PUBLIC_CC : RESTRICTED_ALLOW_CC);
				if (!result.worldReadable) {
					res.vary(VARY_COOKIE);
				}

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
			res.setHeader('Cache-Control', RESTRICTED_CC);
			res.vary(VARY_COOKIE);
			return res.status(result.status).json('not-allowed');
		} catch (e) {
			winston.error('[attachment-privileges] guard error: ' + e.message);
			stats.deny++;
			res.setHeader('Cache-Control', RESTRICTED_CC);
			res.vary(VARY_COOKIE);
			return res.status(500).json('server-error');
		}
	});

	routeHelpers.setupAdminPageRoute(router, '/admin/plugins/attachment-privileges', renderAdmin);

	const SocketAdmin = nodebb.require('./src/socket.io/admin');
	SocketAdmin.plugins.getAttachmentPrivilegesStats = async function () {
		return { allow: stats.allow, deny: stats.deny };
	};

	// Durability: heal failed association writes (DB errors mid-send) and the
	// fire-and-forget crash window (process death between message save and hook)
	if (nconf.get('runJobs')) {
		setImmediate(() => {
			runCatchUp().catch(e => winston.error('[attachment-privileges] catch-up failed: ' + (e && e.message)));
		});
		try {
			if (!cron.hasJob('attachment-privileges:drainRetry')) {
				await cron.addJob({
					name: 'attachment-privileges:drainRetry',
					cronTime: '0 * * * *', // hourly
					onTick: async () => {
						await drainRetrySet();
					},
				});
			}
		} catch (e) {
			winston.error('[attachment-privileges] could not register retry drain job: ' + (e && e.message));
		}
	}
};

plugin.onMessageSaved = async function (payload) {
	const message = payload && payload.message;
	if (!message || !message.mid || !message.roomId || message.system) {
		return;
	}
	try {
		await reconcileMessageAssociations(message);
		await advanceLastProcessed(message.timestamp);
	} catch (e) {
		winston.error('[attachment-privileges] chat associate failed: ' + (e && e.message));
		await recordFailure(String(message.mid));
	}
};

plugin.onMessageEdited = async function (payload) {
	const message = payload && payload.message;
	if (!message || !message.mid || message.system) {
		return;
	}
	try {
		await reconcileMessageAssociations(message);
	} catch (e) {
		winston.error('[attachment-privileges] chat sync failed: ' + (e && e.message));
		await recordFailure(String(message.mid));
	}
};

plugin.onMessageDeleted = async function (payload) {
	try {
		const message = payload && payload.message;
		if (!message || !message.mid) {
			return;
		}
		// purgeMessage() removes the message object before firing this hook; soft delete keeps it.
		// Soft-deleted messages keep their associations (fail-safe: dissociating would flip the file to public).
		if (await db.exists('message:' + String(message.mid))) {
			return;
		}
		await dissociateMessage(message);
	} catch (e) {
		winston.error('[attachment-privileges] chat dissociate failed: ' + (e && e.message));
	}
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
