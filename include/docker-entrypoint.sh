#!/bin/sh
# vim:sw=4:ts=4:et

set -e

entrypoint_log() {
    if [ -z "${NGINX_ENTRYPOINT_QUIET_LOGS:-}" ]; then
        echo "$@"
    fi
}

if [ "$1" = "nginx" ] || [ "$1" = "nginx-debug" ]; then
    if /usr/bin/find "/docker-entrypoint.d/" -mindepth 1 -maxdepth 1 -type f -print -quit 2>/dev/null | read v; then
        entrypoint_log "$0: /docker-entrypoint.d/ is not empty, will attempt to perform configuration"

        entrypoint_log "$0: Looking for shell scripts in /docker-entrypoint.d/"
        find "/docker-entrypoint.d/" -follow -type f -print | sort -V | while read -r f; do
            case "$f" in
                *.envsh)
                    if [ -x "$f" ]; then
                        entrypoint_log "$0: Sourcing $f";
                        . "$f"
                    else
                        # warn on shell scripts without exec bit
                        entrypoint_log "$0: Ignoring $f, not executable";
                    fi
                    ;;
                *.sh)
                    if [ -x "$f" ]; then
                        entrypoint_log "$0: Launching $f";
                        "$f"
                    else
                        # warn on shell scripts without exec bit
                        entrypoint_log "$0: Ignoring $f, not executable";
                    fi
                    ;;
                *) entrypoint_log "$0: Ignoring $f";;
            esac
        done

        entrypoint_log "$0: Configuration complete; ready for start up"
    else
        entrypoint_log "$0: No files found in /docker-entrypoint.d/, skipping configuration"
    fi
fi

envsubst < /opt/pairing/index.html.template > /opt/pairing/index.html
envsubst < /opt/pairing/pairing.js.template > /opt/pairing/pairing.js

./opt/cert-manager/bin -deploy

set +e

ec=1

term_cm() {
  if pid="$(cat "$PID_FILE_PATH" 2> /dev/null)"; then
    if [ "$pid" != "" ]; then
        kill -SIGTERM $pid 2> /dev/null
      fi
  fi
}

term_nginx() {
  if pid="$(cat /var/run/nginx.pid 2> /dev/null)"; then
    if [ "$pid" != "" ]; then
      kill -SIGQUIT $pid 2> /dev/null
    fi
  fi
}

term_handler() {
  entrypoint_log "$0: Stopping cert-manager ..."
  term_cm
  entrypoint_log "$0: Stopping nginx ..."
  term_nginx
  ec=0
}

trap "term_handler" QUIT

run_cm() {
  ./opt/cert-manager/bin
  c="$?"
  sleep 2
  term_nginx
  exit $c
}

run_nginx() {
  nginx -g "daemon off;"
  c="$?"
  sleep 2
  term_cm
  exit $c
}

run_cm &
sleep 2
run_nginx &

wait

sleep 6

exit $ec
