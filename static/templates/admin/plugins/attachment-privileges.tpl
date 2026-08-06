<div class="acp-page-container">
	<!-- IMPORT admin/partials/settings/header.tpl -->

	<div class="row m-0">
		<div id="spy-container" class="col-12 px-2 mb-4" tabindex="0">
			<p class="text-muted">{{tx("attachment-privileges:description")}}</p>

			<form role="form" class="attachment-privileges-settings">
				<div class="mb-4">
					<h5 class="fw-bold tracking-tight settings-header">{{tx("attachment-privileges:settings.title")}}</h5>
					<div class="mb-3">
						<div class="form-check form-switch">
							<input class="form-check-input" type="checkbox" role="switch" id="ap-enabled" name="enabled" data-key="enabled">
							<label class="form-check-label" for="ap-enabled">{{tx("attachment-privileges:settings.enabled")}}</label>
						</div>
						<p class="form-text">{{tx("attachment-privileges:settings.enabled-hint")}}</p>
					</div>
				</div>
			</form>

			<div class="mb-4">
				<h5 class="fw-bold tracking-tight settings-header">{{tx("attachment-privileges:stats.title")}}</h5>
				<div class="row mb-3">
					<div class="col-md-3 col-6 mb-2">
						<div class="card text-center">
							<div class="card-body">
								<h3 id="ap-stats-allow" class="mb-0">0</h3>
								<p class="form-text mb-0">{{tx("attachment-privileges:stats.allow")}}</p>
							</div>
						</div>
					</div>
					<div class="col-md-3 col-6 mb-2">
						<div class="card text-center">
							<div class="card-body">
								<h3 id="ap-stats-deny" class="mb-0 text-danger">0</h3>
								<p class="form-text mb-0">{{tx("attachment-privileges:stats.deny")}}</p>
							</div>
						</div>
					</div>
				</div>
				<button type="button" class="btn btn-outline-secondary btn-sm" id="ap-refresh-stats">
					<i class="fa fa-refresh"></i> {{tx("attachment-privileges:stats.refresh")}}
				</button>
				<p class="form-text mt-2">
					<em class="text-muted">{{tx("attachment-privileges:stats.reset-note")}}</em>
				</p>
			</div>
		</div>
	</div>
</div>