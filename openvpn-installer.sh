#!/usr/bin/env bash

# Author: Lukas Kuntze
# Website: https://www.kuntze-it.de
# Copyright (c) 2021 LK Webmedia & IT-Dienstleistungen.
# Released under the MIT License.

############################################################
# +------------------------------------------------------+ #
# |                     Configuration                    | #
# +------------------------------------------------------+ #
############################################################

# ==================== Application Configuration ==================== #

application_prefix="[OpenVPN]"
application_version="v.1.0.0"
application_url="https://github.com/lkuntze/openvpn-installer"

# Application Directories

application_directory="/opt/openvpn-server/"
application_profile_directory="/opt/openvpn-server/profiles/"

# ==================== OpenVPN Configuration ==================== #

cipher="AES-256-GCM"

easy_rsa_url='https://github.com/OpenVPN/easy-rsa/releases/download/v3.0.8/EasyRSA-3.0.8.tgz'

protocol=
port=1194
dns_server=1

# OpenVPN Directories

openvpn_directory="/etc/openvpn/"
openvpn_server_directory="/etc/openvpn/server/"
openvpn_server_easyrsa_directory="/etc/openvpn/server/easy-rsa/"

# ==================== Network Configuration ==================== #

ipv4_address="0.0.0.0"
ipv6_address="::"

subnet4_address="10.125.1.0"
subnet_netmask="255.255.255.0"

subnet6_address="fddd:1194:1194:1194::"

# ==================== User/Group Configuration ==================== #

user_name="nobody"
group_name="nogroup"

client=""

# ==================== Installation/Dependencies ==================== #

# Check dependencies, requirements and create directories
function _check_dependencies() {
  if [[ $(uname -r | cut -d "." -f 1) -eq 2 ]]; then
    echo "$application_prefix The system is running an old kernel, which is incompatible with this installer."
    exit
  fi

  if grep -qs "ubuntu" /etc/os-release; then
    os="ubuntu"
    os_version=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2 | tr -d '.')

    if [[ "$os" == "ubuntu" && "$os_version" -lt 1804 ]]; then
      echo "$application_prefix Ubuntu 18.04 or higher is required to use this installer."
      exit
    fi
  elif [[ -e /etc/debian_version ]]; then
    os="debian"
    os_version=$(grep -oE '[0-9]+' /etc/debian_version | head -1)

    if [[ "$os" == "debian" && "$os_version" -lt 9 ]]; then
      echo "$application_prefix Debian 9 or higher is required to use this installer."
      exit
    fi
  else
    echo "$application_prefix This installer seems to be running on an unsupported distribution."
    exit
  fi

  if [[ ! -e /dev/net/tun ]] || ! (exec 7<>/dev/net/tun) 2>/dev/null; then
    echo "$application_prefix The system does not have the TUN device available."
    exit
  fi

  if systemd-detect-virt -cq; then
    mkdir /etc/systemd/system/openvpn-server@server.service.d/ 2>/dev/null
    echo "[Service]
    LimitNPROC=infinity" >/etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
  fi

  read -N 999999 -r -t 0.001

  _create_directories
}

# Check if the kernel extension SELinux is available
function _check_for_extended_kernel() {
  if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
    semanage port -a -t openvpn_port_t -p "$protocol" "$port"
  fi
}

# Update Packages, remove unnecessary packages and install dependencies
function _install_dependencies() {
  apt update && apt dist-upgrade -y && apt autoremove -y && apt autoclean -y
  apt install -y ca-certificates iptables openvpn openssl wget
}

# Creates the application and openvpn directories
function _create_directories() {
  mkdir -p $application_directory
  mkdir -p $application_profile_directory

  mkdir -p $openvpn_directory
  mkdir -p $openvpn_server_directory
  mkdir -p $openvpn_server_easyrsa_directory
}

# Detects the ipv4 address from the network configuration
function _detect_public_ipv4_address() {
  if [[ $(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}') -eq 1 ]]; then
    ipv4_address=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}')
  else
    amount_ipv4=$(ip -4 addr | grep inet | grep -vEc '127(\.[0-9]{1,3}){3}')

    echo -e "\nWhich IPv4 address should be used?"
    ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | nl -s ') '

    read -p "IPv4 address [1]: " ip_number
    until [[ -z "$ip_number" || "$ip_number" =~ ^[0-9]+$ && "$ip_number" -le "$amount_ipv4" ]]; do
      echo "The address $ip_number is invalid."
      read -p "IPv4 address [1]: " ip_number
    done

    [[ -z "$ip_number" ]] && ip_number="1"
    ipv4_address=$(ip -4 addr | grep inet | grep -vE '127(\.[0-9]{1,3}){3}' | cut -d '/' -f 1 | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | sed -n "$ip_number"p)
  fi
}

# Detects the ipv6 address from the network configuration
function _detect_public_ipv6_address() {
  if [[ $(ip -6 addr | grep -c 'inet6 [23]') -eq 1 ]]; then
    ipv6_address=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}')
  elif [[ $(ip -6 addr | grep -c 'inet6 [23]') -gt 1 ]]; then
    amount_ipv6=$(ip -6 addr | grep -c 'inet6 [23]')

    echo -e "\nWhich IPv6 address should be used?"
    ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | nl -s ') '

    read -p "IPv6 address [1]: " ip6_number
    until [[ -z "$ip6_number" || "$ip6_number" =~ ^[0-9]+$ && "$ip6_number" -le "$amount_ipv6" ]]; do
      echo "The address $ip6_number is invalid."
      read -p "IPv6 address [1]: " ip6_number
    done

    [[ -z "$ip6_number" ]] && ip6_number="1"
    ipv6_address=$(ip -6 addr | grep 'inet6 [23]' | cut -d '/' -f 1 | grep -oE '([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}' | sed -n "$ip6_number"p)
  fi
}

# Detects the protocol for openvpn configuration
function _detect_protocol() {
  echo -e "\nWhich protocol should OpenVPN use?"
  echo -e "   1) UDP (recommended)"
  echo -e "   2) TCP"

  read -p "Protocol [1]: " protocol
  until [[ -z "$protocol" || "$protocol" =~ ^[12]$ ]]; do
    echo "The protocol $protocol is invalid."
    read -p "Protocol [1]: " protocol
  done

  case "$protocol" in
  1 | "")
    protocol=udp
    ;;
  2)
    protocol=tcp
    ;;
  esac
}

# Detects which port openvpn should listen
function _detect_port() {
  echo -e "\nWhich port should OpenVPN listen to?"

  read -p "Port [1194]: " port
  until [[ -z "$port" || "$port" =~ ^[0-9]+$ && "$port" -le 65535 ]]; do
    echo "The port $port is invalid."
    read -p "Port [1194]: " port
  done

  [[ -z "$port" ]] && port="1194"
}

# Detect the nameserver for all clients
function _detect_dns_server() {
  echo -e "\nSelect a DNS-Server for the clients:"
  echo "   1) Current nameserver"
  echo "   2) Cloudflare"
  echo "   3) Google"

  read -p "DNS-Server [1]: " dns_server
  until [[ -z "$dns_server" || "$dns_server" =~ ^[1-3]$ ]]; do
    echo "The dns-server $dns_server is invalid."
    read -p "DNS-Server [1]: " dns_server
  done
}

# Define easyrsa settings
function _configure_easy_rsa() {
  { wget -qO- "$easy_rsa_url" 2>/dev/null || curl -sL "$easy_rsa_url"; } | tar xz -C $openvpn_server_easyrsa_directory --strip-components 1

  chown -R root:root $openvpn_server_easyrsa_directory
  cd $openvpn_server_easyrsa_directory

  # Public-Key-Infrastructure
  ./easyrsa init-pki
  ./easyrsa --batch build-ca nopass

  _set_client_name 1

  EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-server-full server nopass
  EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client"
  EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

  cp pki/ca.crt pki/private/ca.key pki/issued/server.crt pki/private/server.key pki/crl.pem $openvpn_server_directory
  chown "$user_name:$group_name" "/etc/openvpn/server/crl.pem"
  chmod o+x "$openvpn_server_directory"

  openvpn --genkey --secret $openvpn_server_directory"tc.key"

  echo '-----BEGIN DH PARAMETERS-----
MIICCAKCAgEA8PDyxzu/QM1iBx90CShIAF0RYqu73UsN7SiJx+C60+yoMWy2XcrK
SXM1ldoQa6l+CAkQScHklIr82xdg3Z4lFV900VSB5RnI/VTyYVTCY31zao2YSEjD
NobFUfCRY/hUcEHJ1Lc19kdTrFeVkI9FrJM78UPPCKHVkkrvqdtyf/ApeTkGXYb9
5fEfe4hgHALwQP5J/vCsnqKZdIRRlvvhaWm0k1z7u2H+jYUI7hFgdqmm9MZJQYLI
CS/Dtu7Nuj2FugH4aHSUp3dg2Nq1DnArGrTWJ1JOSeo6WjO+oeMLNdgOQAmkR64C
sLiZysJ3Eaeuam6webqjDqILzHSU76jnk+qa0OWZ+SuO0zunPueoiz4GRgFLbdmr
dLJqWXPByYq7VWBhFR9sOcKX0R8S7gitLKRCUE4FtxNdI8NM4rwj/s9QUxrbc37G
2K6lW2UqBK4uyg0y7tnuHsQH+pyqjP9nUs89ML4eW/maUfc6MHz8bgYHwiOV9Wec
KJuLyVrvjHasQJf5nUyYpo5iQwDdvt/7TurJaLN1L6F81m8Wi32i31ACoqsYQgUS
AV3dBtmLDqROUuGzm+OmMEuVUPtJ0bLbIjdV28NKkYSPfojySbcgXDqhGUDSvs2F
kROu/0fJGm9BAEEecqf7H41xurDr/W9pQ9FEdtam3zN4AGkZJlbZB+MCAQI=
-----END DH PARAMETERS-----' >$openvpn_server_directory"dh.pem"
}

# Create and fill the openvpn server.conf
function _configure_server_config() {
  echo "local $ipv4_address
port $port
proto $protocol
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA512
tls-crypt tc.key
topology subnet
server $subnet4_address $subnet_netmask" >$openvpn_server_directory"server.conf"

  server_configuration=$openvpn_server_directory"server.conf"

  if [[ -z "$ipv6_address" ]]; then
    echo 'push "redirect-gateway def1 bypass-dhcp"' >>$server_configuration
  else
    echo 'server-ipv6 '$subnet6_address'/64' >>$server_configuration
    echo 'push "redirect-gateway def1 ipv6 bypass-dhcp"' >>$server_configuration
  fi

  echo 'ifconfig-pool-persist ipp.txt' >>$server_configuration

  case "$dns_server" in
  1 | "")
    if grep -q '^nameserver 127.0.0.53' "/etc/resolv.conf"; then
      resolv_conf="/run/systemd/resolve/resolv.conf"
    else
      resolv_conf="/etc/resolv.conf"
    fi

    grep -v '^#\|^;' "$resolv_conf" | grep '^nameserver' | grep -oE '[0-9]{1,3}(\.[0-9]{1,3}){3}' | while read line; do
      echo "push \"dhcp-option DNS $line\"" >>$server_configuration
    done
    ;;
  2)
    echo 'push "dhcp-option DNS 1.1.1.1"' >>$server_configuration
    echo 'push "dhcp-option DNS 1.0.0.1"' >>$server_configuration
    ;;
  3)
    echo 'push "dhcp-option DNS 8.8.8.8"' >>$server_configuration
    echo 'push "dhcp-option DNS 8.8.4.4"' >>$server_configuration
    ;;
  esac

  echo "keepalive 10 120
cipher $cipher
user $user_name
group $group_name
persist-key
persist-tun
verb 3
crl-verify crl.pem" >>$server_configuration

  if [[ "$protocol" == "udp" ]]; then
    echo "explicit-exit-notify" >>$server_configuration
  fi

  echo 'net.ipv4.ip_forward=1' >/etc/sysctl.d/30-openvpn-forward.conf
  echo 1 >/proc/sys/net/ipv4/ip_forward

  if [[ -n "$ipv6_address" ]]; then
    echo "net.ipv6.conf.all.forwarding=1" >>/etc/sysctl.d/30-openvpn-forward.conf
    echo 1 >/proc/sys/net/ipv6/conf/all/forwarding
  fi
}

# Define firewall rules for openvpn
function _configure_iptables() {
  iptables_path=$(command -v iptables)
  ip6tables_path=$(command -v ip6tables)

  if [[ $(systemd-detect-virt) == "openvz" ]] && readlink -f "$(command -v iptables)" | grep -q "nft" && hash iptables-legacy 2>/dev/null; then
    iptables_path=$(command -v iptables-legacy)
    ip6tables_path=$(command -v ip6tables-legacy)
  fi

  echo "[Unit]
Before=network.target
[Service]
Type=oneshot
ExecStart=$iptables_path -t nat -A POSTROUTING -s $subnet4_address/24 ! -d $subnet4_address/24 -j SNAT --to $ipv4_address
ExecStart=$iptables_path -I INPUT -p $protocol --dport $port -j ACCEPT
ExecStart=$iptables_path -I FORWARD -s $subnet4_address/24 -j ACCEPT
ExecStart=$iptables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ExecStop=$iptables_path -t nat -D POSTROUTING -s $subnet4_address/24 ! -d $subnet4_address/24 -j SNAT --to $ipv4_address
ExecStop=$iptables_path -D INPUT -p $protocol --dport $port -j ACCEPT
ExecStop=$iptables_path -D FORWARD -s $subnet4_address/24 -j ACCEPT
ExecStop=$iptables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >/etc/systemd/system/openvpn-iptables.service

  if [[ -n "$ipv6_address" ]]; then
    echo "ExecStart=$ip6tables_path -t nat -A POSTROUTING -s $subnet6_address/64 ! -d $subnet6_address/64 -j SNAT --to $ipv6_address
  ExecStart=$ip6tables_path -I FORWARD -s $subnet6_address/64 -j ACCEPT
  ExecStart=$ip6tables_path -I FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
  ExecStop=$ip6tables_path -t nat -D POSTROUTING -s $subnet6_address/64 ! -d $subnet6_address/64 -j SNAT --to $ipv6_address
  ExecStop=$ip6tables_path -D FORWARD -s $subnet6_address/64 -j ACCEPT
  ExecStop=$ip6tables_path -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT" >>/etc/systemd/system/openvpn-iptables.service
  fi

  echo "RemainAfterExit=yes
  [Install]
  WantedBy=multi-user.target" >>/etc/systemd/system/openvpn-iptables.service

  systemctl enable --now openvpn-iptables.service
}

# Creates the openvpn common client config
function _configure_client_config() {
  echo "client
dev tun
proto $protocol
remote $ipv4_address $port
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
auth SHA512
cipher $cipher
ignore-unknown-option block-outside-dns
block-outside-dns
verb 3" >$openvpn_server_directory"client-common.txt"
}

# ==================== Uninstall/Restore ==================== #

# Uninstall the openvpn package, remove unnecessary packages/configs and restore settings
function _uninstall_dependencies() {
  _remove_directories

  apt remove --purge -y openvpn && apt autoremove -y && apt autoclean -y
  _remove_configuration

  if sestatus 2>/dev/null | grep "Current mode" | grep -q "enforcing" && [[ "$port" != 1194 ]]; then
    semanage port -d -t openvpn_port_t -p "$protocol" "$port"
  fi
}

# Deletes the application and openvpn directories
function _remove_directories() {
  rm -rf $application_directory
  rm -rf $openvpn_directory
}

# Deletes the OpenVPN configuration files
function _remove_configuration() {
  rm -f /etc/systemd/system/openvpn-server@server.service.d/disable-limitnproc.conf
  rm -f /etc/sysctl.d/30-openvpn-forward.conf
}

# Reset the openvpn iptables rules
function _reset_iptables() {
  if systemctl is-active --quiet firewalld.service; then
    ipv4_address=$(firewall-cmd --direct --get-rules ipv4 nat POSTROUTING | grep "\-s $subnet4_address/24 ""'"'!'"'"" -d $subnet4_address/24" | grep -oE '[^ ]+$')

    firewall-cmd --remove-port="$port"/"$protocol"
    firewall-cmd --zone=trusted --remove-source=$subnet4_address/24
    firewall-cmd --permanent --remove-port="$port"/"$protocol"
    firewall-cmd --permanent --zone=trusted --remove-source=$subnet4_address/24
    firewall-cmd --direct --remove-rule ipv4 nat POSTROUTING 0 -s $subnet4_address/24 ! -d $subnet4_address/24 -j SNAT --to "$ipv4_address"
    firewall-cmd --permanent --direct --remove-rule ipv4 nat POSTROUTING 0 -s $subnet4_address/24 ! -d $subnet4_address/24 -j SNAT --to "$ipv4_address"

    if grep -qs "server-ipv6" /etc/openvpn/server/server.conf; then
      ipv6_address=$(firewall-cmd --direct --get-rules ipv6 nat POSTROUTING | grep '\-s '$subnet6_address'/64 '"'"'!'"'"' -d '$subnet6_address'/64' | grep -oE '[^ ]+$')

      firewall-cmd --zone=trusted --remove-source="$subnet6_address"/64
      firewall-cmd --permanent --zone=trusted --remove-source="$subnet6_address"/64
      firewall-cmd --direct --remove-rule ipv6 nat POSTROUTING 0 -s "$subnet6_address"/64 ! -d "$subnet6_address"/64 -j SNAT --to "$ipv6_address"
      firewall-cmd --permanent --direct --remove-rule ipv6 nat POSTROUTING 0 -s "$subnet6_address"/64 ! -d "$subnet6_address"/64 -j SNAT --to "$ipv6_address"
    fi
  else
    systemctl disable --now openvpn-iptables.service
    rm -f /etc/systemd/system/openvpn-iptables.service
  fi
}

# ==================== Utilities ==================== #

# Check if the executing user is root
function _is_root_account() {
  if [ "$EUID" -ne 0 ]; then
    return 1
  fi
}

# Clears the command line
function _clear_terminal() {
  clear
}

# Defines the name for the openvpn profile
function _set_client_name() {
  if [ "$1" == 1 ]; then
    echo -e "\nChoose a name for the first client:"

    read -p "Name [Client]: " client_name
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<<"$client_name")
    [[ -z "$client" ]] && client="client"
  else
    echo -e "\nChoose a name for the client:"

    read -p "Name: " client_name
    client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<<"$client_name")

    while [[ -z "$client" || -e /etc/openvpn/server/easy-rsa/pki/issued/"$client".crt ]]; do
      echo "$client: invalid name."
      read -p "Name: " client_name
      client=$(sed 's/[^0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-]/_/g' <<<"$client_name")
    done
  fi
}

# Creates a new client.ovpn file
function _create_new_client() {
  {
    cat $openvpn_server_directory"client-common.txt"
    echo "<ca>"
    cat $openvpn_server_easyrsa_directory"pki/ca.crt"
    echo "</ca>"

    echo "<cert>"
    sed -ne '/BEGIN CERTIFICATE/,$ p' $openvpn_server_easyrsa_directory"pki/issued/$client.crt"
    echo "</cert>"

    echo "<key>"
    cat $openvpn_server_easyrsa_directory"pki/private/$client.key"
    echo "</key>"

    echo "<tls-crypt>"
    sed -ne '/BEGIN OpenVPN Static key/,$ p' $openvpn_server_directory"tc.key"
    echo "</tls-crypt>"
  } >$application_profile_directory"$client".ovpn
}

# ==================== Application ==================== #

function _application_header_text() {
  if [ "$1" == 1 ]; then
    _clear_terminal
    echo -e "############################################################"
    echo -e "# +------------------------------------------------------+ #"
    echo -e "# |              OpenVPN Server (Installer)              | #"
    echo -e "# |                   Version: $application_version                   | #"
    echo -e "# |                                                      | #"
    echo -e "# | Copyright (c) 2021 LK Webmedia & IT-Dienstleistungen | #"
    echo -e "# +------------------------------------------------------+ #"
    echo -e "############################################################"
  else
    _clear_terminal
    echo -e "############################################################"
    echo -e "# +------------------------------------------------------+ #"
    echo -e "# |            OpenVPN Server (Configuration)            | #"
    echo -e "# |                 Version: $application_version                     | #"
    echo -e "# |                                                      | #"
    echo -e "# | Copyright (c) 2021 LK Webmedia & IT-Dienstleistungen | #"
    echo -e "# +------------------------------------------------------+ #"
    echo -e "############################################################"
  fi
}

function _application_installation() {
  echo -e "\nWelcome to the OpenVPN installer script."
  echo -e "In the following, some information must be given for the OpenVPN settings."

  _detect_public_ipv4_address
  _detect_public_ipv6_address
  _detect_protocol
  _detect_port
  _detect_dns_server

  echo -e "\nOpenVPN installation is ready to start."
  read -n1 -r -p "Press any key to start the installation..."
  _install_dependencies

  _configure_easy_rsa
  _configure_server_config
  _configure_iptables
  _configure_client_config

  _check_for_extended_kernel
  systemctl enable --now openvpn-server@server.service

  _create_new_client

  _application_header_text 1
  echo -e "\nThe OpenVPN installation was successful."
  echo -e "Please restart the script to get into the configuration."
  echo -e "\nYour OpenVPN-Profile ($client.ovpn) was stored in a $application_profile_directory.\n"
}

# Add a new client configuration
function _application_client_add() {
  _set_client_name 2

  cd $openvpn_server_easyrsa_directory

  EASYRSA_CERT_EXPIRE=3650 ./easyrsa build-client-full "$client"
  _create_new_client

  _application_header_text 2
  echo -e "\nThe Client $client was successfully added."
  echo -e "Configuration available in:" $application_profile_directory"$client.ovpn"

  exit
}

# Deletes an existing client configuration
function _application_client_delete() {
  client_amount=$(tail -n +2 $openvpn_server_easyrsa_directory"pki/index.txt" | grep -c "^V")

  if [[ "$client_amount" == 0 ]]; then
    echo -e "\nThere are no existing clients!"
    exit
  fi

  echo -e "\nSelect a client to revoke:"
  tail -n +2 $openvpn_server_easyrsa_directory"pki/index.txt" | grep "^V" | cut -d '=' -f 2 | nl -s ') '

  read -p "Client: " client_number
  until [[ "$client_number" =~ ^[0-9]+$ && "$client_number" -le "$client_amount" ]]; do
    echo "The client $client_number is invalid."
    read -p "Client: " client_number
  done

  client=$(tail -n +2 $openvpn_server_easyrsa_directory"pki/index.txt" | grep "^V" | cut -d '=' -f 2 | sed -n "$client_number"p)
  echo -e ""

  read -p "Confirm $client revocation? [y/N]: " revoke
  until [[ "$revoke" =~ ^[yYnN]*$ ]]; do
    echo "The answer $revoke is invalid."
    read -p "Confirm $client revocation? [y/N]: " revoke
  done

  if [[ "$revoke" =~ ^[yY]$ ]]; then
    cd $openvpn_server_easyrsa_directory

    ./easyrsa --batch revoke "$client"
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl

    rm -f $openvpn_server_directory"crl.pem"

    cp $openvpn_server_easyrsa_directory"pki/crl.pem" $openvpn_server_directory"crl.pem"
    chown "$user_name:$group_name" $openvpn_server_directory"crl.pem"

    _application_header_text 1
    echo -e "\nThe  Client $client was successfully revoked."
  else
    echo -e "\n Revocation for client $client aborted."
  fi

  exit
}

# Displays information and update-url for the script
function _application_update() {
  _application_header_text 2

  echo -e "\nAuthor: Lukas Kuntze"
  echo -e "Website: https://www.kuntze-it.de"

  echo -e "\nOpenVPN Server (Installer Script)"
  echo -e "Current version: $application_version"
  echo -e "Update url: $application_url\n"
}

# Uninstall OpenVPN, reset settings/iptables and disable services
function _application_uninstall() {
  echo -e "\nYou are about to uninstall OpenVPN."

  read -p "Are you sure? [y/N]: " remove
  until [[ "$remove" =~ ^[yYnN]*$ ]]; do
    echo "The selection $remove is invalid."
    read -p "Are you sure? [y/N]: " remove
  done

  if [[ "$remove" =~ ^[yY]$ ]]; then
    port=$(grep '^port ' $openvpn_server_directory"server.conf" | cut -d " " -f 2)
    protocol=$(grep '^proto ' $openvpn_server_directory"server.conf" | cut -d " " -f 2)

    systemctl disable --now openvpn-server@server.service

    _reset_iptables
    _uninstall_dependencies

    _application_header_text 2
    echo -e "\nOpenVPN has been successfully uninstalled."
    echo -e "If you want to reinstall OpenVPN you can run the script again."
  else
    echo -e "\nUninstall aborted!"
  fi
  exit 130
}

# Displays the application menu
function _application_menu() {
  echo -e "\nWhat do you want to do?"
  echo -e "   1) Add a new client configuration"
  echo -e "   2) Delete an existing client configuration"
  echo -e "   3) Check for new script versions"
  echo -e "   4) Uninstall OpenVPN"
  echo -e "   5) Exit\n"

  read -p "Select an option [1-5]: " option
  until [[ "$option" =~ ^[1-5]$ ]]; do
    echo "The selection '$option' is invalid."
    read -p "Select an option [1-5]: " option
  done

  case $option in
  1)
    _application_client_add
    ;;
  2)
    _application_client_delete
    ;;
  3)
    _application_update
    ;;
  4)
    _application_uninstall
    ;;
  5)
    exit
    ;;
  esac
}

# Main function
function _main() {
  if [[ ! -e $openvpn_server_directory"server.conf" ]]; then
    _check_dependencies
    _clear_terminal

    _application_header_text 1
    _application_installation
  else
    _application_header_text 2
    _application_menu
  fi
}

############################################################
# +------------------------------------------------------+ #
# |              OpenVPN Installer (Script)              | #
# +------------------------------------------------------+ #
############################################################

if ! _is_root_account; then
  echo -e "$application_prefix You need to run this Script as root"
  exit 2
else
  echo "$application_prefix Installer is starting..."
  _main
fi
