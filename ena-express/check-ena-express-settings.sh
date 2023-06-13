#!/usr/bin/env bash
#
# This script checks the instance configuration for optimal
# ENA Express performance and suggests the recommended configuration.
#
# Usage: ./check-ena-express-settings.sh <interface>
# Example: ./check-ena-express-settings.sh eth0
#
# Description of checks and whether they are required/recommended.
# 1. MTU <= 8900 (required)
# 2. tcp_limit_output_bytes >= 1MB (required)
# 3. BQL to be disabled (required)
# 4. TX queue size >= 1024 (recommended)
# 5. RX queue size >= 8192 (recommended)

# Recommended configuration
MTU_RECOMMENDED_MAX=8900
MTU_RECOMMENDED_MIN=8800
TCP_LIMIT_BYTES_RECOMMENDED=1048576
TX_QUEUE_SIZE_RECOMMENDED=1024
RX_QUEUE_SIZE_RECOMMENDED=8192

set -euo pipefail

ethtool="/usr/sbin/ethtool"
sysctl="/usr/sbin/sysctl"
required_fail=0
recommended_fail=0

echo_success() {
  local str=$1
  echo -e "\033[1;32m${str}\033[0m"
}

echo_error() {
  local str=$1
  echo -e "\033[1;31mERROR: ${str}\033[0m"
}

echo_warn() {
  local str=$1
  echo -e "\033[1;33mWARN: ${str}\033[0m"
}

check_eth_mtu() {
  local interface=${1}
  local mtu=$(ip link show ${interface} | awk '{print $5}')
  if [ ${mtu} -gt ${MTU_RECOMMENDED_MAX} ]; then
    ((required_fail += 1))
    echo_error "MTU should be <= ${MTU_RECOMMENDED_MAX} for ENA Express, currently set to ${mtu}"
    echo "To fix run: sudo ip link set ${interface} mtu ${MTU_RECOMMENDED_MAX}"
  elif [ ${mtu} -lt ${MTU_RECOMMENDED_MIN} ]; then
    echo_warn "MTU lower than recommended and not optimal for bandwidth performance, currently set to ${mtu}"
    echo "To fix run: sudo ip link set ${interface} mtu ${MTU_RECOMMENDED_MAX}"
  else
    echo_success "${interface} MTU value is $mtu (good)"
  fi
}

check_tcp_limit_output_bytes() {
  local limit_bytes=$(cat /proc/sys/net/ipv4/tcp_limit_output_bytes)
  if [ ${limit_bytes} -lt ${TCP_LIMIT_BYTES_RECOMMENDED} ]; then
    ((required_fail += 1))
    echo_error "tcp_limit_output_bytes should be >= ${TCP_LIMIT_BYTES_RECOMMENDED} for ENA Express, currently set to ${limit_bytes}"
    echo "To fix run: sudo sh -c 'echo ${TCP_LIMIT_BYTES_RECOMMENDED} > /proc/sys/net/ipv4/tcp_limit_output_bytes'"
  else
    echo_success "IPv4 tcp_limit_output_bytes value is ${limit_bytes} (good)"
  fi
}

check_eth_rx_queue_size() {
  local interface=${1}
  local rx_queue_size=$(${ethtool} -g ${interface} | grep "RX:" | tail -n1 | awk '{print $2}')
  if [ ${rx_queue_size} -lt ${RX_QUEUE_SIZE_RECOMMENDED} ]; then
    ((recommended_fail += 1))
    echo_warn "$interface RX queue size should be >= ${RX_QUEUE_SIZE_RECOMMENDED} for ENA Express, currently set to ${rx_queue_size}"
    echo "To fix run: sudo ${ethtool} -G ${interface} rx ${RX_QUEUE_SIZE_RECOMMENDED}"
  else
    echo_success "${interface} RX queue size is ${rx_queue_size} (good)"
  fi
}

check_eth_tx_queue_size() {
  local interface=${1}
  local tx_queue_size=$(${ethtool} -g ${interface} | grep "TX:" | tail -n1 | awk '{print $2}')
  if [ ${tx_queue_size} -lt ${TX_QUEUE_SIZE_RECOMMENDED} ]; then
    ((recommended_fail += 1))
    echo_warn "$interface TX queue size should be >= ${TX_QUEUE_SIZE_RECOMMENDED} for ENA Express, currently set to ${tx_queue_size}"
    echo "To fix run: sudo ${ethtool} -G ${interface} tx ${TX_QUEUE_SIZE_RECOMMENDED}"
  else
    echo_success "${interface} TX queue size is ${tx_queue_size} (good)"
  fi
}

check_bql_enable() {
  local interface=${1}
  local enable_bql=0
  if [ -e "/sys/module/ena/parameters/enable_bql" ]; then
    enable_bql=$(cat /sys/module/ena/parameters/enable_bql)
  else
    for txq in /sys/class/net/"${interface}"/queues/tx-*; do
      local limit_min=$(cat ${txq}/byte_queue_limits/limit_min)
      if [ ${limit_min} == 0 ]; then
        enable_bql=1
        break
      fi
    done
  fi

  if [ ${enable_bql} == 1 ]; then
    echo_error "BQL is enabled on $interface which is not optimal for ENA Express"
    echo "To fix run: sudo sh -c 'for txq in /sys/class/net/${interface}/queues/tx-*; do echo max > \${txq}/byte_queue_limits/limit_min; done'"
    ((required_fail += 1))
  else
    echo_success "BQL is disabled on ${interface} (good)"
  fi
}

check_network_misc() {
  local interface=${1}

  # driver version
  echo "========= ena driver version ==========================="
  ${ethtool} -i ${interface} | grep "^version:"

  echo "========= ena_srd stats ================================"
  local ena_srd_stats=$(${ethtool} -S ${interface} | { grep "ena_srd" || true; })
  if [ -z "${ena_srd_stats}" ]; then
    echo "ena srd stats not available, please upgrade ena driver"
  else
    echo "${ena_srd_stats}"
  fi

  # interrupt moderation
  echo "========= interrupt moderation settings ================"
  ${ethtool} -c ${interface} | grep -E 'Adaptive|usecs|frames'

  # eth queues
  echo "========= ethtool -l ==================================="
  ${ethtool} -l ${interface}

  # rmem/wmem
  echo "========= rmem/wmem ===================================="
  ${sysctl} net.core.rmem_default
  ${sysctl} net.core.rmem_max
  ${sysctl} net.core.wmem_default
  ${sysctl} net.core.wmem_max

  # busy_poll
  echo "========= busy_poll ===================================="
  ${sysctl} net.core.busy_poll
  ${sysctl} net.core.busy_read
}

print_results() {
  if [ ${required_fail} -gt 0 ] || [ ${recommended_fail} -gt 0 ]; then
    if [ ${required_fail} -gt 0 ]; then
      echo_error "${required_fail} required configuration failed"
    fi
    if [ ${recommended_fail} -gt 0 ]; then
      echo_warn "${recommended_fail} recommended configuration failed"
    fi
    echo "See suggestions to fix above"
  else
    echo_success "All checks passed"
  fi
}

check_ena_express_settings() {
  local interface=${1}
  if [ -e "/sys/class/net/${interface}/device" ]; then
    echo "Checking interface ${interface}"
  else
    echo_error "interface ${interface} does not exist"
    exit 255
  fi
  if [ ! -e ${ethtool} ]; then
    echo_error "${ethtool} not found"
    exit 255
  fi
  if [ ! -e ${sysctl} ]; then
    echo_error "${sysctl} not found"
    exit 255
  fi
  echo "============= Checking MTU ============================="
  check_eth_mtu ${interface}
  echo "============= Checking TCP settings ===================="
  check_tcp_limit_output_bytes
  echo "============= Checking BQL settings ===================="
  check_bql_enable ${interface}
  echo "============= Checking TX Queue size ==================="
  check_eth_tx_queue_size ${interface}
  echo "============= Checking RX Queue size ==================="
  check_eth_rx_queue_size ${interface}
  echo "============= Misc network configuration ==============="
  check_network_misc ${interface}
  echo "============= Results =================================="
  print_results
}

if [ $# -ne 1 ]; then
  echo_error "Interface argument is required"
  echo "Usage: ${0} <interface>"
  exit 255
fi

check_ena_express_settings ${1}
exit ${required_fail}
