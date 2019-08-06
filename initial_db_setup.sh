# Creates a db user to be used by the app
#!/bin/bash
set -e;

if [ -n "${MONGO_SERVICE_USER_USERNAME:-}" ] && [ -n "${MONGO_SERVICE_USER_PASSWORD:-}" ]; then
	"${mongo[@]}" "$MONGO_SERVICE_DATABASE" <<-EOJS
		db.createUser({
			user: $(_js_escape "$MONGO_SERVICE_USER_USERNAME"),
			pwd: $(_js_escape "$MONGO_SERVICE_USER_PASSWORD"),
			roles: [ { role: $(_js_escape "readWrite"), db: $(_js_escape "$MONGO_SERVICE_DATABASE") } ]
			})
	EOJS
fi
