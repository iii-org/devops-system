#!/usr/bin/env bash

# shellcheck disable=SC1090
# shellcheck disable=SC1091

set -euo pipefail
# set -o xtrace # Uncomment this line for debugging purposes

usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [options]...

Update Redmine SMTP values.

Options:
  -H, --host HOST           SMTP server host.
  -P, --port PORT           SMTP server port.
  -U, --user USER           SMTP account user.
  -p, --password PASSWORD   SMTP account password.
      --protocol PROTOCOL   SMTP protocol to use. Allowed values: tls, ssl. No default value.
      --auth AUTH           SMTP authentication method. Allowed values: login, plain, cram_md5. Default: login
      --kubeconfig PATH     Path to the kubeconfig file to use for CLI requests. Default: /root/.kube/config
      --kube-context NAME   Name of the kubeconfig context to use. Default: system
      --namespace NAME      Namespace where the chart is installed. Default: iiidevops

Miscellaneous:
  -h, --help                Print this help and exit
  -v, --verbose             Print script debug info
      --no-color            Disable color output
  -f, --force               Force overwrite existing values
EOF
  exit 0
}

msg() {
  echo >&2 -e "${1-}"
}

die() {
  local msg=$1
  local code=${2-1} # default exit status 1
  msg "[ERROR] $msg"
  exit "$code"
}

k8s_command() {
  kubectl --kubeconfig="${k8s_config}" --context="${k8s_context}" "${@}"
}

helm_command() {
  helm --kubeconfig="${k8s_config}" --kube-context="${k8s_context}" "${@}"
}

parse_params() {
  local code=0

  error() {
    msg "[ERROR] ${1}"
    code=1
  }

  check_valid_port() {
    local port="${!1}"

    if ! [[ "${port}" =~ ^[0-9]+$ ]]; then
      error "The port must be a number"
      return
    fi
    if [[ "${port}" -lt 1 || "${port}" -gt 65535 ]]; then
      error "The port must be in the range 1-65535"
      return
    fi
  }

  check_multi() {
    if [[ " ${2} " != *" ${!1} "* ]]; then
      error "The allowed values for ${1} are: ${2}"
    fi
  }

  # Default values
  k8s_config="/root/.kube/config" # kubeconfig path
  k8s_context="system"            # kubectl context
  NAMESPACE="iiidevops"           # Namespace where the chart is installed

  SMTP_HOST=""      # Leave blank to disable SMTP, server host
  SMTP_PORT=""      # Leave blank to disable SMTP, server port
  SMTP_USER=""      # Leave blank to disable SMTP, account user
  SMTP_PASSWORD=""  # Leave blank to disable SMTP, account password
  SMTP_PROTOCOL=""  # If specified, SMTP protocol to use. Allowed values: tls, ssl. No default.
  SMTP_AUTH="login" # SMTP authentication method. Allowed values: login, plain, cram_md5. Default: login.

  while [[ "$#" -gt 0 ]]; do
    case "${1-}" in
    -h | --help) usage ;;
    -v | --verbose) set -x ;;

    -H | --host)
      SMTP_HOST="${2-}"
      shift
      ;;
    -P | --port)
      SMTP_PORT="${2-}"
      shift
      ;;
    -U | --user)
      SMTP_USER="${2-}"
      shift
      ;;
    -p | --password)
      SMTP_PASSWORD="${2-}"
      shift
      ;;
    --protocol)
      SMTP_PROTOCOL="${2-}"
      shift
      ;;
    --auth)
      SMTP_AUTH="${2-}"
      shift
      ;;

    --kubeconfig)
      k8s_config="${2-}"
      shift
      ;;
    --kube-context)
      k8s_context="${2-}"
      shift
      ;;
    --namespace)
      NAMESPACE="${2-}"
      shift
      ;;

    -?*) die "Unknown option: $1" ;;
    *) break ;;
    esac
    shift
  done

  # Validation
  [[ -z "${SMTP_HOST}" ]] && error "The SMTP_HOST variable is empty or not set."
  for empty_env_var in "SMTP_USER" "SMTP_PASSWORD"; do
    [[ -z "${!empty_env_var}" ]] && error "The ${empty_env_var} variable is empty or not set."
  done
  [[ -z "${SMTP_PORT}" ]] && error "The SMTP_PORT variable is empty or not set."
  [[ -n "${SMTP_PORT}" ]] && check_valid_port "SMTP_PORT"
  check_multi "SMTP_AUTH" "plain login cram_md5"
  [[ -n "${SMTP_PROTOCOL}" ]] && check_multi "SMTP_PROTOCOL" "tls ssl"

  [[ ! -f ${k8s_config} ]] && error "The kubeconfig file does not exist."

  return ${code}
}

main() {
  local redmine_pod

  # Check NAMESPACE exists
  if ! k8s_command get ns "${NAMESPACE}" >/dev/null 2>&1; then
    die "The namespace ${NAMESPACE} does not exist."
  fi

  redmine_pod="$(k8s_command get pods -n "${NAMESPACE}" -l "app.kubernetes.io/name=redmine,app.kubernetes.io/instance=redmine" -o jsonpath="{.items[0].metadata.name}" || die "No Redmine pod found")"

  # Remove /bitnami/redmine/.user_scripts_initialized to force re-run of init scripts
  k8s_command exec -it -n "${NAMESPACE}" "${redmine_pod}" -- rm -f /bitnami/redmine/.user_scripts_initialized

  # make temp dir
  temp_dir="$(mktemp -d)"
  yaml_file="${temp_dir}/values.yaml"

  cat <<EOF >"${yaml_file}"
extraEnvVars:
 - name: REDMINE_SMTP_AUTH
   value: ${SMTP_AUTH:-login}

smtpHost: "${SMTP_HOST}"
smtpPort: "${SMTP_PORT}"
smtpUser: "${SMTP_USER}"
smtpPassword: "${SMTP_PASSWORD}"
smtpProtocol: "${SMTP_PROTOCOL}"
EOF

  cat <<'EOF' >>"${yaml_file}"
customPostInitScripts:
  smtp.sh: |
    #!/bin/bash

    # shellcheck disable=SC1091

    set -o errexit
    set -o nounset
    set -o pipefail
    # set -o xtrace # Uncomment this line for debugging purposes

    # Load Redmine environment
    . /opt/bitnami/scripts/redmine-env.sh

    # Load generic libraries
    . /opt/bitnami/scripts/libredmine.sh
    . /opt/bitnami/scripts/libfs.sh
    . /opt/bitnami/scripts/libos.sh
    . /opt/bitnami/scripts/libnet.sh
    . /opt/bitnami/scripts/libvalidations.sh
    . /opt/bitnami/scripts/libpersistence.sh
    . /opt/bitnami/scripts/libservice.sh

    info "Configuring Redmine SMTP credentials"

    # Copy from /opt/bitnami/scripts/libredmine.sh
    if ! is_empty_value "$REDMINE_SMTP_HOST"; then
        info "Configuring SMTP credentials"
        redmine_conf_set "default.email_delivery.delivery_method" ":smtp"
        redmine_conf_set "default.email_delivery.smtp_settings.address" "$REDMINE_SMTP_HOST"
        redmine_conf_set "default.email_delivery.smtp_settings.port" "$REDMINE_SMTP_PORT_NUMBER"
        redmine_conf_set "default.email_delivery.smtp_settings.authentication" "$REDMINE_SMTP_AUTH"
        redmine_conf_set "default.email_delivery.smtp_settings.user_name" "$REDMINE_SMTP_USER"
        redmine_conf_set "default.email_delivery.smtp_settings.password" "$REDMINE_SMTP_PASSWORD"
        # Remove 'USER@' part from e-mail address and use as domain
        redmine_conf_set "default.email_delivery.smtp_settings.domain" "${REDMINE_SMTP_USER//*@/}"
        redmine_conf_set "default.email_delivery.smtp_settings.openssl_verify_mode" "$REDMINE_SMTP_OPENSSL_VERIFY_MODE"
        redmine_conf_set "default.email_delivery.smtp_settings.ca_file" "$REDMINE_SMTP_CA_FILE"
        if [[ "$REDMINE_SMTP_PROTOCOL" = "tls" ]]; then
            redmine_conf_set "default.email_delivery.smtp_settings.enable_starttls_auto" "true" "bool"
        else
            redmine_conf_set "default.email_delivery.smtp_settings.enable_starttls_auto" "false" "bool"
        fi
    fi
EOF

  # Update SMTP values
  helm_command upgrade -n "${NAMESPACE}" redmine bitnami/redmine --reuse-values -f "${yaml_file}"

  # Remove temp dir
  rm -rf "${temp_dir}"
}

parse_params "$@"
main