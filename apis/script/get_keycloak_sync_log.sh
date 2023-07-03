#!/usr/bin/env bash

set -euo pipefail
# set -o xtrace # Uncomment this line for debugging purposes

usage() {
  cat <<EOF
Usage: $(basename "${BASH_SOURCE[0]}") [options]...

Get Keycloak service logs for sync LDAP users. If no logs found, exit the script.

Options:
  -n, --name NAME           Keycloak deployment name. Default: iiidevops-keycloak-0

Common options:
  -h, --help                Print this help and exit
  -v, --verbose             Print script debug info
      --kubeconfig PATH     Path to the kubeconfig file to use for CLI requests. Default: /root/.kube/config
      --kube-context NAME   Name of the kubeconfig context to use. Default: system
      --namespace NAME      Namespace where the chart is installed. Default: iiidevops
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

parse_params() {
  local code=0

  error() {
    msg "[ERROR] ${1}"
    code=1
  }

  # Default values
  k8s_config="/root/.kube/config"                 # kubeconfig path
  k8s_context="system"                            # kubectl context
  NAMESPACE="iiidevops"                           # Namespace where the chart is installed
  KEYCLOAK_DEPLOYMENT_NAME="iiidevops-keycloak-0" # Default Keycloak deployment name

  while [[ "$#" -gt 0 ]]; do
    case "${1-}" in
    -h | --help) usage ;;
    -v | --verbose) set -x ;;

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

    # Below is custom variables
    -n | --name)
      KEYCLOAK_DEPLOYMENT_NAME="${2-}"
      shift
      ;;

    -?*) die "Unknown option: $1" ;;
    *) break ;;
    esac
    shift
  done

  # Validation
  [[ -z "${KEYCLOAK_DEPLOYMENT_NAME}" ]] && error "The KEYCLOAK_DEPLOYMENT_NAME variable is empty or not set."

  [[ ! -f ${k8s_config} ]] && error "The kubeconfig file does not exist."

  return ${code}
}

main() {
  local log_messages
  local execute_tag

  # Check NAMESPACE exists
  if ! k8s_command get ns "${NAMESPACE}" >/dev/null 2>&1; then
    die "The namespace ${NAMESPACE} does not exist."
  fi

  log_messages="$(kubectl logs -n "${NAMESPACE}" "${KEYCLOAK_DEPLOYMENT_NAME}" | grep -F "[org.keycloak.storage.ldap.LDAPStorageProviderFactory]")"

  # If the log_messages is empty, exit the script
  if [[ -z "${log_messages}" ]]; then
    echo "No logs found."
    exit 0
  fi

  # It has a lot of lines, and we need to find out the last line containing "Sync all users from LDAP to local store: realm:"
  execute_tag=$(echo "${log_messages}" | grep -F "Sync all users from LDAP to local store: realm:" | tail -n 1 | grep -o "executor-thread-[0-9]*")

  # Filter the log_messages by the execute_tag
  log_messages=$(echo "${log_messages}" | grep -F "${execute_tag}")

  # For all logs, we only need messages after column 6, and remove the first 5 columns
  log_messages=$(echo "${log_messages}" | awk '{for(i=6;i<=NF;i++) printf $i" "; print ""}')

  echo "${log_messages}"
}

parse_params "$@"
main
