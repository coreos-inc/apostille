#!/usr/bin/env sh

# When run in the docker containers, the working directory
# is the root of the repo.

iter=0

case $SERVICE_NAME in
	apostille)
		MIGRATIONS_PATH=${MIGRATIONS_PATH:-migrations/mysql}
		DB_URL=${DB_URL:-mysql://server@tcp(mysql:3306)/apostille}
		# have to poll for DB to come up
		until migrate -path=$MIGRATIONS_PATH -url=$DB_URL version > /dev/null
		do
			iter=$(( iter+1 ))
			if [[ $iter -gt 30 ]]; then
				echo "apostille database failed to come up within 30 seconds"
				exit 1;
			fi
			echo "waiting for $DB_URL to come up."
			sleep 1
		done
		pre=$(migrate -path=$MIGRATIONS_PATH -url="${DB_URL}" version)
		if migrate -path=$MIGRATIONS_PATH -url="${DB_URL}" up ; then
			post=$(migrate -path=$MIGRATIONS_PATH -url="${DB_URL}" version)
			if [ "$pre" != "$post" ]; then
				echo "apostille database migrated to latest version"
			else
				echo "apostille database already at latest version"
			fi
		else
			echo "apostille database migration failed"
			exit 1
		fi
esac
