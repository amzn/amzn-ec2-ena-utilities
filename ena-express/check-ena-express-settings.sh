#!/usr/bin/env bash
#
# This script checks the instance configuration for optimal
# ENA Express performance and suggests the recommended configuration.
#
# Usage: ./check-ena-express-settings.sh -i|--interface <interface> [--low-rtt]
# Options:
#  -i, --interface            Target network interface.
#  --low-rtt                  Skip checks for high latency environment (high RTT checks are enabled by default).
#
# Example: ./check-ena-express-settings.sh --interface eth0 --low-rtt
#
# Description of checks and whether they are required/recommended.
# 1. MTU <= 8900 (required)
# 2. tcp_limit_output_bytes >= 1MB / 4MB (required. 4MB for high RTT environments)
# 3. BQL to be disabled (required)
# 4. tcp_autocorking = 0 (recommended)
# 5. TX queue size >= min(1024, pre-set maximum) (recommended)
# 6. RX queue size >= min(8192, pre-set maximum) (recommended)
# 7. Large LLQ explicitly disabled via module param (recommended when large LLQ is supported)
# 8. net.ipv4.tcp_rmem, net.ipv4.tcp_wmem tuples - set maximum window value to 8MB at least (required for high RTT environments)
# 9. net.core.[rw]mem_default >= 4MB, net.core.[rw]mem_max >= 8MB (required for high RTT environments)
# 10. net.ipv4.tcp_congestion_control=cubic, tcp_cubic.parameters.hystart_detect = 0 (required for high RTT environments)

### Recommended Configuration
MTU_RECOMMENDED_MAX=8900
MTU_RECOMMENDED_MIN=8800
TCP_LIMIT_BYTES_RECOMMENDED=1048576
TCP_LIMIT_BYTES_RECOMMENDED_HIGH_RTT=4194304
TCP_MEM_RECOMMENDED_HIGH_RTT_MAX=8388608
NET_SOCKET_BUFFER_SIZE_RECOMMENDED_DEFAULT_HIGH_RTT=4194304
NET_SOCKET_BUFFER_SIZE_RECOMMENDED_MAXIMUM_HIGH_RTT=8388608
TX_QUEUE_SIZE_RECOMMENDED=1024
RX_QUEUE_SIZE_RECOMMENDED=8192

set -euo pipefail

ethtool="/usr/sbin/ethtool"
sysctl="/usr/sbin/sysctl"
ip="/usr/sbin/ip"
required_fail=0
recommended_fail=0

### Utilities
echo_success() { echo -e "\033[1;32m${1}\033[0m"; }
echo_error() { echo -e "\033[1;31mERROR: ${1}\033[0m" 1>&2; }
echo_warn() { echo -e "\033[1;33mWARN: ${1}\033[0m"; }
echo_fix() { echo -e "\033[1mTo fix, run:\033[0m\n  ${1}"; }
min() { echo $(( $1 < $2 ? $1 : $2 )); }

setting_evaluator() {
  local setting_name=${1}
  local recommended=${2}
  local setting_location="/proc/sys/${setting_name//\.//}"
  local current_value="undefined"
  local change_required=true

  if [ -f ${setting_location} ]; then
    current_value=$(cat ${setting_location})
    change_required=$([[ ${current_value} -lt ${recommended} ]] && echo true || echo false)
  fi
  if [ ${change_required} = true ]; then
    ((required_fail += 1))
    echo_error "${setting_name} should be >= ${recommended} for ENA Express, currently set to ${current_value}"
    echo_fix "sudo sh -c 'echo ${recommended} > ${setting_location}'"
  else
    echo_success "${setting_name} value is ${current_value} (good)"
  fi
}

### Tests
check_eth_mtu() {
  local interface=${1}
  local mtu=$(${ip} link show ${interface} | awk '{print $5}')
  if [ ${mtu} -gt ${MTU_RECOMMENDED_MAX} ]; then
    ((required_fail += 1))
    echo_error "MTU should be <= ${MTU_RECOMMENDED_MAX} for ENA Express, currently set to ${mtu}"
    echo_fix "sudo ip link set ${interface} mtu ${MTU_RECOMMENDED_MAX}"
  elif [ ${mtu} -lt ${MTU_RECOMMENDED_MIN} ]; then
    echo_warn "MTU lower than recommended and not optimal for bandwidth performance, currently set to ${mtu}"
    echo_fix "sudo ip link set ${interface} mtu ${MTU_RECOMMENDED_MAX}"
  else
    echo_success "${interface} MTU value is $mtu (good)"
  fi
}

check_tcp_limit_output_bytes() {
  [[ $HIGH_RTT = true ]] && recommended="${TCP_LIMIT_BYTES_RECOMMENDED_HIGH_RTT}" || recommended="${TCP_LIMIT_BYTES_RECOMMENDED}"
  setting_evaluator "net.ipv4.tcp_limit_output_bytes" ${recommended}
}

check_tcp_socket_buffer_size() {
  echo "========= rmem/wmem ===================================="
  read -r min_size default_size max_size <<< "$(${sysctl} -n net.ipv4.tcp_rmem)"
  if [ ${max_size} -lt ${TCP_MEM_RECOMMENDED_HIGH_RTT_MAX} ]; then
    ((recommended_fail += 1))
    echo_warn "net.ipv4.tcp_rmem max size should be >= ${TCP_MEM_RECOMMENDED_HIGH_RTT_MAX} for ENA Express in high RTT environment, currently set to ${max_size}"
    echo_fix "sudo ${sysctl} -w net.ipv4.tcp_rmem=\"${min_size} ${default_size} ${TCP_MEM_RECOMMENDED_HIGH_RTT_MAX}\""
  else
    echo_success "net.ipv4.tcp_rmem max size is ${max_size} (good)"
  fi

  read -r min_size default_size max_size <<< "$(${sysctl} -n net.ipv4.tcp_wmem)"
  if [ ${max_size} -lt ${TCP_MEM_RECOMMENDED_HIGH_RTT_MAX} ]; then
    ((recommended_fail += 1))
    echo_warn "net.ipv4.tcp_wmem max size should be >= ${TCP_MEM_RECOMMENDED_HIGH_RTT_MAX} for ENA Express in high RTT environment, currently set to ${max_size}"
    echo_fix "sudo ${sysctl} -w net.ipv4.tcp_wmem=\"${min_size} ${default_size} ${TCP_MEM_RECOMMENDED_HIGH_RTT_MAX}\""
  else
    echo_success "net.ipv4.tcp_wmem max size is ${max_size} (good)"
  fi
}

check_tcp_cubic_hybrid_start() {
  echo "========= tcp cubic hybrid start ============================="
  local algo=$(cat /proc/sys/net/ipv4/tcp_congestion_control)
  if [[ "${algo}" != "cubic" ]]; then
    ((required_fail += 1))
    echo_error "net.ipv4.tcp_congestion_control should be set to cubic, currently set to ${algo}"
    echo_fix "${sysctl} -w net.ipv4.tcp_congestion_control=cubic"
  fi
  local current_value=$(cat /sys/module/tcp_cubic/parameters/hystart_detect)
  if ((current_value != 0)); then
    ((required_fail += 1))
    echo_error "module.tcp_cubic.parameters.hystart_detect should be equal to 0 for ENA Express, currently set to ${current_value}"
    echo_fix "sudo sh -c 'echo 0 > /sys/module/tcp_cubic/parameters/hystart_detect'"
  else
    echo_success "sys.module.tcp_cubic.parameters.hystart_detect value is ${current_value} (good)"
  fi
}

check_tcp_settings() {
  check_tcp_limit_output_bytes
  check_tcp_autocorking
  if [[ ${HIGH_RTT} = true ]]; then
    check_tcp_socket_buffer_size
    check_tcp_cubic_hybrid_start
  fi
}

check_net_socket_buffer_size() {
  echo "========= rmem/wmem ===================================="
  if [[ ${HIGH_RTT} = true ]]; then
    setting_evaluator "net.core.rmem_default" ${NET_SOCKET_BUFFER_SIZE_RECOMMENDED_DEFAULT_HIGH_RTT}
    setting_evaluator "net.core.rmem_max" ${NET_SOCKET_BUFFER_SIZE_RECOMMENDED_MAXIMUM_HIGH_RTT}
    setting_evaluator "net.core.wmem_default" ${NET_SOCKET_BUFFER_SIZE_RECOMMENDED_DEFAULT_HIGH_RTT}
    setting_evaluator "net.core.wmem_max" ${NET_SOCKET_BUFFER_SIZE_RECOMMENDED_MAXIMUM_HIGH_RTT}
  else
    ${sysctl} net.core.rmem_default
    ${sysctl} net.core.rmem_max
    ${sysctl} net.core.wmem_default
    ${sysctl} net.core.wmem_max
  fi
}

check_tcp_autocorking() {
  local autocorking=$(cat /proc/sys/net/ipv4/tcp_autocorking)
  if [ ${autocorking} -ne 0 ]; then
    ((recommended_fail += 1))
    echo_warn "tcp_autocorking is currently set to ${autocorking}, it is recommended to set it to 0 for ENA Express"
    echo_fix "sudo sh -c 'echo 0 > /proc/sys/net/ipv4/tcp_autocorking'"
  else
    echo_success "net.ipv4.tcp_autocorking is disabled (good)"
  fi
}

check_eth_rx_queue_size() {
  local interface=${1}
  # rx_q_size_values[0] holds the preconfigured maximum, rx_q_size_values[1] holds the current setting
  local rx_q_size_values=($(${ethtool} -g ${interface} | grep "RX:" | awk '{print $2}'))
  local recommended_rx_q_size_value=$(min "${rx_q_size_values[0]}" "${RX_QUEUE_SIZE_RECOMMENDED}")

  if [ "${rx_q_size_values[1]}" -lt "${recommended_rx_q_size_value}" ]; then
    ((recommended_fail += 1))
    echo_warn "$interface RX queue size should be >= ${recommended_rx_q_size_value} for ENA Express, currently set to ${rx_q_size_values[1]}"
    echo_fix "sudo ${ethtool} -G ${interface} rx ${recommended_rx_q_size_value}"
  else
    echo_success "${interface} RX queue size is ${rx_q_size_values[1]} (good)"
  fi
}

check_eth_tx_queue_size_large_llq() {
  local interface=${1}
  # tx_q_size_values[0] holds the preconfigured maximum, tx_q_size_values[1] holds the current setting
  local tx_q_size_values=($(${ethtool} -g ${interface} | grep "TX:" | awk '{print $2}'))
  local recommended_tx_q_size_value=$(min "${tx_q_size_values[0]}" "${TX_QUEUE_SIZE_RECOMMENDED}")
  local large_llq_param_path="/sys/module/ena/parameters/force_large_llq_header"

  if [  "${tx_q_size_values[1]}" -ge "${recommended_tx_q_size_value}" ]; then
    echo_success "${interface} TX queue size is ${tx_q_size_values[1]} (good)"
    return
  fi

  if test -f "${large_llq_param_path}"; then
    case "$(< "${large_llq_param_path}")" in
      0)
        echo_success "Large LLQ is explicitly disabled via module param (good)"
        ;;
      *)
        echo_warn "Large LLQ is not explicitly disabled via module parameter"
        ((recommended_fail += 1))
        echo "Consider disabling large LLQ for optimal ENA Express performance"
        echo_fix "sudo sh -c 'rmmod ena && modprobe ena force_large_llq_header=0'"
        echo
        echo "More details about large LLQ are available here:"
        echo " https://github.com/amzn/amzn-drivers/blob/master/kernel/linux/ena/ENA_Linux_Best_Practices.rst"
        echo
        return
        ;;
    esac
  fi

  ((recommended_fail += 1))
  echo_warn "$interface TX queue size is not at maximum of ${recommended_tx_q_size_value}, currently set to ${tx_q_size_values[1]}"
  echo_fix "sudo ${ethtool} -G ${interface} tx ${recommended_tx_q_size_value}"
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
    echo_fix "sudo sh -c 'for txq in /sys/class/net/${interface}/queues/tx-*; do echo max > \${txq}/byte_queue_limits/limit_min; done'"
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
    echo "Checking interface ${interface} high RTT mode=${HIGH_RTT}"
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
  echo
  echo "============= Checking TCP settings ===================="
  check_tcp_settings
  echo "============= Checking Network socket settings ========="
  check_net_socket_buffer_size
  echo
  echo "============= Checking BQL settings ===================="
  check_bql_enable ${interface}
  echo
  echo "============= Checking TX Queue size and Large LLQ ====="
  check_eth_tx_queue_size_large_llq ${interface}
  echo
  echo "============= Checking RX Queue size ==================="
  check_eth_rx_queue_size ${interface}
  echo
  echo "============= Misc network configuration ==============="
  check_network_misc ${interface}
  echo
  echo "============= Results =================================="
  print_results
}

usage() {
  echo
  echo "Check network and ENA driver settings for ENA Express optimal performance"
  echo
  echo "Usage: ${0} -i|--interface <interface> [--low-rtt]"
  echo
  echo "Options:"
  echo "-i, --interface            Target network interface."
  echo "--low-rtt                  Skip checks for high latency environment (high RTT checks are enabled by default)."
  echo "-h, --help                 Print this help message and exit."
}

### Entrypoint

HIGH_RTT=true

while [ "$#" -gt 0 ]; do
  case "$1" in
    -i | --interface)
      shift
      if [ "$#" -eq 0 ]; then
        echo_error "Non-empty interface id is required"
        usage
        exit 255
      fi
      interface="${1}"
      ;;
    --low-rtt)
      HIGH_RTT=false
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      echo_error "Unexpected argument: $1"
      usage
      exit 255
      ;;
  esac
  shift
done

if [ -z "${interface+x}" ]; then
  echo_error "Interface argument is required"
  usage
  exit 255
fi

if [ ! -d "/sys/class/net/${interface}" ]; then
  echo_error "Interface ${interface} does not exist"
  exit 1
fi

if [ ! -d "/sys/class/net/${interface}/device/driver/module" ] || [ "$(basename "$(realpath "/sys/class/net/${interface}/device/driver/module")")" != "ena" ]; then
  echo_error "Interface ${interface} does not bind the ENA driver"
  exit 1
fi

check_ena_express_settings ${interface}
exit ${required_fail}
