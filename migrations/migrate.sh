#!/usr/bin/env sh

# When run in the docker containers, the working directory
# is the root of the repo.
for DATABASE in ${DB_URL:-mysql://server@tcp(mysql:3306)/apostille} ${ROOT_DB_URL:-mysql://server_root@tcp(mysql:3306)/apostille_root}
do
		iter=0
		MIGRATIONS_PATH=${MIGRATIONS_PATH:-migrations/mysql}
		# have to poll for DB to come up
		until migrate -path=$MIGRATIONS_PATH -url=$DATABASE version
		do
			iter=$(( iter+1 ))
			if [[ $iter -gt 30 ]]; then
				echo "apostille database failed to come up within 30 seconds"
				exit 1;
			fi
			echo "waiting for $DATABASE to come up."
			sleep 1
		done
		pre=$(migrate -path=$MIGRATIONS_PATH -url="${DATABASE}" version)
		if migrate -path=$MIGRATIONS_PATH -url="${DATABASE}" up ; then
			post=$(migrate -path=$MIGRATIONS_PATH -url="${DATABASE}" version)
			if [ "$pre" != "$post" ]; then
				echo "apostille database ($DATABASE) migrated to latest version"
			else
				echo "apostille database ($DATABASE)) already at latest version"
			fi
		else
			echo "apostille database ($DATABASE)) migration failed"
			exit 1
		fi
done
