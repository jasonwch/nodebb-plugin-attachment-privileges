'use strict';

define('admin/plugins/attachment-privileges', ['settings', 'alerts'], function (Settings, alerts) {
	var ACP = {};

	ACP.init = function () {
		Settings.load('attachment-privileges', $('.attachment-privileges-settings'));

		$('#save').on('click', function () {
			var newEnabledState = $('#ap-enabled').is(':checked');
			Settings.save('attachment-privileges', $('.attachment-privileges-settings'), function () {
				alerts.alert({
					type: 'success',
					alert_id: 'attachment-privileges-saved',
				title: 'admin/admin:changes-saved',
				message: newEnabledState ? 'attachment-privileges:saved-on' : 'attachment-privileges:saved-off',
					timeout: 2500,
				});
			});
		});

		function refreshStats() {
			socket.emit('admin.plugins.getAttachmentPrivilegesStats', {}, function (err, data) {
				if (err) {
					return;
				}
				$('#ap-stats-allow').text(String((data && data.allow) || 0));
				$('#ap-stats-deny').text(String((data && data.deny) || 0));
			});
		}

		refreshStats();

		$('#ap-refresh-stats').on('click', refreshStats);
	};

	return ACP;
});