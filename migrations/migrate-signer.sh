#!/usr/bin/env sh

# When run in the docker containers, the working directory
# is the root of the repo.
export DATABASE=$DB_URL
iter=0
MIGRATIONS_PATH=${MIGRATIONS_PATH:-migrations/mysql}
# have to poll for DB to come up
until migrate -path=$MIGRATIONS_PATH -database=$DATABASE up
do
	iter=$(( iter+1 ))
	if [[ $iter -gt 30 ]]; then
		echo "signer database failed to come up within 30 seconds"
		exit 1;
	fi
	echo "waiting for $DATABASE to come up."
	sleep 1
done
pre=$(migrate -path=$MIGRATIONS_PATH -database="${DATABASE}" version)
if migrate -path=$MIGRATIONS_PATH -database="${DATABASE}" up ; then
	post=$(migrate -path=$MIGRATIONS_PATH -database="${DATABASE}" version)
	if [ "$pre" != "$post" ]; then
		echo "signer database ($DATABASE) migrated to latest version"
	else
		echo "signer database ($DATABASE)) already at latest version"
	fi
else
	echo "signer database ($DATABASE)) migration failed"
	exit 1
fi
