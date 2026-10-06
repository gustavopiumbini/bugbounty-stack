#!/usr/bin/env bash
set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin_dir="${root_dir}/tools/bin"
lock_file="${root_dir}/tools/versions.lock.json"
mkdir -p "${bin_dir}"

for required in curl jq unzip sha256sum; do
  command -v "${required}" >/dev/null || {
    echo "missing dependency: ${required}" >&2
    exit 1
  }
done

tmp_dir="$(mktemp -d)"
trap 'rm -rf -- "${tmp_dir}"' EXIT

install_pd_tool() {
  local tool="$1"
  local version version_number archive checksum_file base_url expected
  version="$(jq -er --arg tool "${tool}" '.[$tool]' "${lock_file}")"
  version_number="${version#v}"
  archive="${tool}_${version_number}_linux_amd64.zip"
  checksum_file="${tool}_${version_number}_checksums.txt"
  if [[ "${tool}" == "katana" ]]; then
    checksum_file="katana-${version_number}-checksums.txt"
  fi
  base_url="https://github.com/projectdiscovery/${tool}/releases/download/${version}"

  echo "installing ${tool} ${version}"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
    --output "${tmp_dir}/${archive}" "${base_url}/${archive}"
  curl --fail --location --retry 3 --proto '=https' --tlsv1.2 \
    --output "${tmp_dir}/${checksum_file}" "${base_url}/${checksum_file}"

  expected="$(awk -v file="${archive}" '$2 == file {print $1}' "${tmp_dir}/${checksum_file}")"
  [[ "${expected}" =~ ^[0-9a-fA-F]{64}$ ]] || {
    echo "checksum not found for ${archive}" >&2
    exit 1
  }
  printf '%s  %s\n' "${expected}" "${tmp_dir}/${archive}" | sha256sum --check --status
  unzip -oq "${tmp_dir}/${archive}" "${tool}" -d "${tmp_dir}/${tool}"
  install -m 0755 "${tmp_dir}/${tool}/${tool}" "${bin_dir}/${tool}"
}

if [[ "$#" -eq 0 ]]; then
  set -- subfinder httpx katana nuclei dnsx
fi

for tool in "$@"; do
  jq -e --arg tool "${tool}" 'has($tool)' "${lock_file}" >/dev/null || {
    echo "unknown or unpinned tool: ${tool}" >&2
    exit 1
  }
  install_pd_tool "${tool}"
done

echo "installed in ${bin_dir}"

