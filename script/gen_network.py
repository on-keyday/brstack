#!/usr/bin/env python3
import json
import yaml
import ipaddress
import sys
import argparse

# サブネット自動割り当てのための設定
BASE_NETWORK_ADDRESS = '10.0.0.0/8'
SUBNET_PREFIX_LENGTH = 24 # /24

def generate_subnets(num_subnets, base_network_cidr):
    """Generates a list of sequential subnets from a base network."""
    try:
        base_net = ipaddress.ip_network(base_network_cidr, strict=False)
        if base_net.prefixlen > SUBNET_PREFIX_LENGTH:
            raise ValueError(f"Base network prefix length ({base_net.prefixlen}) must be <= {SUBNET_PREFIX_LENGTH}")
        subnet_iterator = base_net.subnets(new_prefix=SUBNET_PREFIX_LENGTH)
        subnet_list = []
        for _ in range(num_subnets):
            try:
                current_subnet_obj = next(subnet_iterator)
                subnet_list.append(str(current_subnet_obj))
            except StopIteration:
                raise ValueError(f"Ran out of assignable subnets within the base network {base_network_cidr}. Needed {num_subnets}, but could only generate {len(subnet_list)}.")
        return subnet_list
    except ValueError as e:
        print(f"Error generating subnets: {e}", file=sys.stderr)
        sys.exit(1)

def get_network_prefix(subnet_cidr):
    """Gets the network prefix (e.g., '192.168.30') from a CIDR."""
    network = ipaddress.IPv4Network(subnet_cidr, strict=False)
    return str(network.network_address).rsplit('.', 1)[0]

# --- ヘルパー関数: ホストのデフォルトゲートウェイIPを見つける ---
def find_default_gateway_ip_for_host(node_name, node, node_configs_map, node_ips, network_subnets):
    """Finds the default gateway IP for a client or server node."""
    connected_networks = list(node.get('connections', []))
    if not connected_networks:
        print(f"Warning: Node '{node_name}' has no connections defined. Cannot determine default gateway.", file=sys.stderr)
        return None

    primary_connected_network_name = connected_networks[0]['network']
    primary_subnet = network_subnets.get(primary_connected_network_name)
    if not primary_subnet:
        print(f"Internal Error: Primary network '{primary_connected_network_name}' for node '{node_name}' not in subnet map.", file=sys.stderr)
        return None


    explicit_gw_router_name = node.get('default_gateway_router')
    if explicit_gw_router_name:
        gw_router_node = node_configs_map.get(explicit_gw_router_name)
        if not gw_router_node or (gw_router_node.get('role') != 'router' and gw_router_node.get('role') != 'nat_router'):
            print(f"Warning: Node '{node_name}' specifies non-existent or non-router default_gateway_router '{explicit_gw_router_name}'. Falling back to auto-detection.", file=sys.stderr)
        else:
            gw_router_connected_nets = [conn['network'] for conn in gw_router_node.get('connections', [])]
            if primary_connected_network_name not in gw_router_connected_nets:
                print(f"Warning: Specified default_gateway_router '{explicit_gw_router_name}' for node '{node_name}' is not connected to its primary network '{primary_connected_network_name}'. Falling back to auto-detection.", file=sys.stderr)
            else:
                gw_router_ip_on_net = node_ips.get(explicit_gw_router_name, {}).get(primary_connected_network_name)
                if gw_router_ip_on_net:
                    return gw_router_ip_on_net
                else:
                    print(f"Internal Error: IP for specified default_gateway_router '{explicit_gw_router_name}' on network '{primary_connected_network_name}' not found.", file=sys.stderr)


    router_ip_on_net = None
    for other_node_name, other_node in node_configs_map.items():
        if other_node.get('role') == 'router' or other_node.get('role') == 'nat_router':
            if primary_connected_network_name in node_ips.get(other_node_name, {}):
                router_ip_on_net = node_ips[other_node_name][primary_connected_network_name]
                return router_ip_on_net

    print(f"Warning: No router found on primary network '{primary_connected_network_name}' for node '{node_name}'. Default route will be missing.", file=sys.stderr)
    return None


# --- ROUTING 環境変数生成ロジック ---
def generate_routing_info(node_name, node, node_configs_map, network_subnets, node_ips):
    """Generates the ROUTING environment variable string for a given node."""
    role = node.get('role')
    if not role:
        return ""

    routing_entries = []
    
    # static_routes にデフォルトルートが明示的に設定されているかチェック
    has_explicit_default_route = False
    for static_route in node.get('static_routes', []):
        target_network_name = static_route.get('target_network')
        if target_network_name in ["default", "0.0.0.0/0"]:
            has_explicit_default_route = True
            break

    # Add Direct Routes (<subnet> 0.0.0.0) for ALL roles
    for net_name in node_ips.get(node_name, {}):
        subnet = network_subnets.get(net_name)
        if subnet:
            routing_entries.append(f"{subnet} 0.0.0.0")

    # Add Default Route (0.0.0.0/0 <router_ip_on_local_net>) for Client/Server
    # ただし、static_routesで明示的にデフォルトルートが設定されている場合は追加しない
    if (role.endswith('client') or role.endswith('server')) and not has_explicit_default_route:
        default_gw_ip = find_default_gateway_ip_for_host(node_name, node, node_configs_map, node_ips, network_subnets)
        if default_gw_ip:
            routing_entries.append(f"0.0.0.0/0 {default_gw_ip}")

    # Add static routes for ALL roles (including client/server)
    for static_route in node.get('static_routes', []):
        target_network_name = static_route.get('target_network')
        next_hop_node_name = static_route.get('next_hop_node') 

        if not target_network_name or not next_hop_node_name:
            print(f"Warning: Node '{node_name}' has incomplete static_route entry (missing target_network or next_hop_node).", file=sys.stderr)
            continue

        # --- ターゲットの決定: "default", "0.0.0.0/0", またはネットワーク名 ---
        is_default_route = False
        if target_network_name == "default" or target_network_name == "0.0.0.0/0":
            target_subnet_cidr = "0.0.0.0/0" # デフォルトルート
            is_default_route = True
        else:
            target_subnet_cidr = network_subnets.get(target_network_name)

        if not target_subnet_cidr:
            if not is_default_route: # デフォルトルート以外でsubnetが見つからない場合はエラー
                print(f"Warning: Node '{node_name}' static route specifies non-existent target_network '{target_network_name}'.", file=sys.stderr)
            continue
            # デフォルトルートの場合は target_subnet_cidr が "0.0.0.0/0" になっている


        next_hop_node = node_configs_map.get(next_hop_node_name)
        if not next_hop_node:
            print(f"Warning: Node '{node_name}' static route to '{target_network_name}' specifies invalid next_hop_node '{next_hop_node_name}' (not found).", file=sys.stderr)
            continue

        # Find the shared network between the current node and the next hop node
        shared_network_name = None
        current_node_nets = node.get('connections', [])
        next_hop_node_nets = next_hop_node.get('connections', [])

        for net_curr_conn in current_node_nets:
            for net_next_conn in next_hop_node_nets:
                if net_curr_conn['network'] == net_next_conn['network']:
                    shared_network_name = net_curr_conn['network']
                    break
            if shared_network_name:
                break

        if not shared_network_name:
            print(f"Warning: Could not find a shared network between node '{node_name}' and next_hop_node '{next_hop_node_name}' for static route to '{target_network_name}'. Cannot determine next hop IP.", file=sys.stderr)
            continue

        # Get the next hop node's IP on the shared network
        next_hop_ip = node_ips.get(next_hop_node_name, {}).get(shared_network_name)

        if not next_hop_ip:
            print(f"Internal Error: Could not find IP for next_hop_node '{next_hop_node_name}' on shared network '{shared_network_name}' for route to '{target_network_name}'.", file=sys.stderr)
            continue

        # Add the static route entry: <target_subnet> <next_hop_ip>
        routing_entries.append(f"{target_subnet_cidr} {next_hop_ip}")

    return " ".join(routing_entries) if routing_entries else ""


def generate_client_dest_ip(node_name, node, node_configs_map, node_ips):
    """Generates the DEST IP address for a client node."""
    role = node.get('role')
    if role is None or not role.endswith('client'):
        return None

    dest_server_name = node.get('dest_server')
    if not dest_server_name:
        print(f"Warning: Client node '{node_name}' is missing 'dest_server'. DEST will not be set.", file=sys.stderr)
        return None

    target_server_node = node_configs_map.get(dest_server_name)
    if not target_server_node:
        return dest_server_name


    server_connections = list(target_server_node.get('connections', []))
    if not server_connections:
        print(f"Warning: Target server '{dest_server_name}' has no connections defined. DEST for client '{node_name}' will not be set.", file=sys.stderr)
        return None

    server_target_net = server_connections[0]['network'] # Assume first connection is primary
    server_target_ip = node_ips.get(dest_server_name, {}).get(server_target_net)

    if not server_target_ip:
        all_server_ips = list(node_ips.get(dest_server_name, {}).values())
        if all_server_ips:
            print(f"Warning: Could not find server '{dest_server_name}' IP on its first connected network '{server_target_net}'. Using the first found IP: {all_server_ips[0]} for client '{node_name}' DEST.", file=sys.stderr)
            server_target_ip = all_server_ips[0]

    if not server_target_ip:
        print(f"Warning: Could not determine target IP for server '{dest_server_name}' (target for client '{node_name}'). Server has no assigned IPs. DEST will not be set.", file=sys.stderr)
        return None

    return server_target_ip


def generate_docker_compose(config, network_subnets, node_ips, node_configs_map, service_routing_info, client_dest_info):
    """Generates Docker Compose data structure."""
    docker_compose_data = {
        'services': {},
        'networks': {}
    }

    docker_compose_data['services']['brstack_app'] = {
        'image': 'brstack_app:latest',
        'build': {
            'context': '.',
            'dockerfile': 'Dockerfile',
            'tags': ['brstack_app:latest']
        },
        'profiles': ['build_only']
    }

    # config.get('networks', [])はネットワーク名のリストではなく、ネットワーク定義のリストであることに注意
    network_definitions_from_config = {net['name']: net for net in config.get('networks', [])}

    network_name_prefix= "brstk"
    index = 1

    all_names = [f"{network_name_prefix}{i}" for i in range(1, len(network_subnets)+1)]

    for net_name, subnet in network_subnets.items():
        bridge_name = f"{network_name_prefix}{index}"
        index += 1
        network_definition = {
            'ipam': {
                'config': [
                    {'subnet': subnet}
                ]
            },
            'driver_opts': {
                "com.docker.network.bridge.enable_ip_masquerade": 0,
                "com.docker.network.bridge.name": bridge_name,
                # from https://github.com/moby/moby/blob/ada61040e00f25ab7c326561159cf59090d7d2a3/daemon/libnetwork/drivers/bridge/labels.go#L29
                # from https://github.com/moby/moby/blob/ada61040e00f25ab7c326561159cf59090d7d2a3/daemon/libnetwork/drivers/bridge/bridge_linux.go#L369
                "com.docker.network.bridge.trusted_host_interfaces": ':'.join(all_names)
            }
        }
        
        # JSON設定からMTUを読み込む
        config_net = network_definitions_from_config.get(net_name)
        if config_net and 'mtu' in config_net:
            mtu_value = config_net['mtu']
            if isinstance(mtu_value, int) and mtu_value > 0:
                network_definition['driver_opts']['com.docker.network.driver.mtu'] = str(mtu_value)
            else:
                print(f"Warning: Invalid MTU value '{mtu_value}' for network '{net_name}'. MTU must be a positive integer. Skipping MTU setting for this network.", file=sys.stderr)


        docker_compose_data['networks'][net_name] = network_definition

    for node_name, node in node_configs_map.items():
        role = node.get('role')
        if role == "external_host":
            continue  # 外部ホストはサービスとして生成しない
        service_definition = {
            'image': 'brstack_app:latest',
            'cap_add': ['NET_ADMIN', 'NET_RAW'],
            "sysctls": {
                "net.bridge.bridge-nf-call-iptables": "0",
            },
            'environment': {'ROLE': role},
            'networks': {}
        }

        if not node.get('connections'):
            print(f"Warning: Node '{node_name}' has no connections defined.", file=sys.stderr)

        for conn in node.get('connections', []):
            net_name = conn['network']
            assigned_ip = node_ips.get(node_name, {}).get(net_name)
            if not assigned_ip:
                raise ValueError(f"Internal Error: IP not found for node '{node_name}' on network '{net_name}'.")

            service_definition['networks'][net_name] = {
                'ipv4_address': assigned_ip
            }

        routing_string = service_routing_info.get(node_name, "")
        service_definition['environment']['ROUTING'] = routing_string

        if role.endswith('client'):
            dest_ip = client_dest_info.get(node_name)
            if dest_ip:
                service_definition['environment']['DST'] = dest_ip


        docker_compose_data['services'][node_name] = service_definition

    return docker_compose_data

# --- Graphviz DOT 生成関数 (ROUTING情報とDST情報を含む) ---
def generate_dot(config, network_subnets, node_ips, node_configs_map, service_routing_info, client_dest_info):
    """Generates Graphviz DOT format output including routing info and DST in node labels."""
    dot_output = ['digraph network_topology {']
    dot_output.append('  rankdir=LR;')
    dot_output.append('  node [shape=box];')

    # Define Network nodes
    dot_output.append('\n  // Networks')
    for net_name, subnet in network_subnets.items():
        safe_net_name = net_name.replace('-', '_')
        dot_output.append(f'  {safe_net_name} [shape=ellipse, label="{net_name}\\n({subnet})"];')

    # Define Service nodes
    dot_output.append('\n  // Services')
    for node_name, node in node_configs_map.items():
        role = node.get('role', 'unknown')
        shape = 'box'
        color = 'lightblue'
        if role == 'nat_router':
            shape = 'diamond'
            color = 'pink'
        elif role == 'external_host':
            shape = 'box3d'
            color = 'lightgrey' 
        elif role == 'router':
            shape = 'diamond'
            color = 'orange'
        elif role == 'server':
            shape = 'cylinder'
            color = 'lightgreen'
        elif role == 'client':
            shape = 'ellipse'
            color = 'yellow'
        elif role == 'stun_client':
            shape = 'ellipse'
            color = 'violet'
        elif role == 'ntp_client':
            shape = 'ellipse'
            color = 'cyan'

        safe_node_name = node_name.replace('-', '_')

        # --- ラベル内容の構築 ---
        label_lines = [f"{node_name}\\n({role})"]

        # Add DEST info for clients
        if role.endswith('client'):
            dest_ip = client_dest_info.get(node_name)
            if dest_ip:
                label_lines.append(f"Dest: {dest_ip}")


        # Add a separator line if DEST was added OR if there's routing info
        routing_string = service_routing_info.get(node_name, "")
        has_dest_info = client_dest_info.get(node_name) is not None
        has_routing_entries = bool(routing_string)
        if has_dest_info or has_routing_entries:
            label_lines.append("")


        # Add ROUTING info
        label_lines.append("Routes:")
        if routing_string:
            routes_list = routing_string.split()
            if len(routes_list) % 2 == 0:
                for i in range(0, len(routes_list), 2):
                    subnet_str = routes_list[i]
                    gateway_str = routes_list[i+1]
                    if gateway_str == "0.0.0.0":
                        label_lines.append(f"{subnet_str} (connected)")
                    else:
                        label_lines.append(f"{subnet_str} via {gateway_str}")
            else:
                label_lines.append("Invalid ROUTING format")
                label_lines.append(f"Raw: {routing_string}")
        else:
            label_lines.append("(None)")

        # Join label lines with DOT newline character
        safe_label_content = "\\n".join(label_lines)


        # DOTラベルはダブルクォートで囲む
        dot_output.append(f'  {safe_node_name} [shape={shape}, style=filled, fillcolor={color}, label="{safe_label_content}"];')


    # Define Connections (Edges)
    dot_output.append('\n  // Connections')
    for node_name, node in node_configs_map.items():
        safe_node_name = node_name.replace('-', '_')
        for conn in node.get('connections', []):
            net_name = conn['network']
            safe_net_name = net_name.replace('-', '_')
            assigned_ip = node_ips.get(node_name, {}).get(net_name, 'N/A')

            # Create edge from service to network with IP as label
            dot_output.append(f'  {safe_node_name} -> {safe_net_name} [label="{assigned_ip}"];')

    dot_output.append('}')

    return "\n".join(dot_output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate Docker Compose YAML or Graphviz DOT from JSON config.")
    parser.add_argument("config_json_file", help="Path to the JSON configuration file.")
    parser.add_argument(
        "--format",
        choices=['yaml', 'dot'],
        default='yaml',
        help="Output format: 'yaml' for Docker Compose, 'dot' for Graphviz DOT."
    )

    args = parser.parse_args()

    try:
        with open(args.config_json_file, 'r') as f:
            config = json.load(f)

        # --- 共通の前処理 ---
        # ネットワーク名をリストではなく、設定オブジェクトから取得
        # MTUなどの追加情報を含むため
        network_configs = config.get('networks', [])
        network_names = [net['name'] for net in network_configs]

        num_required_subnets = len(network_names)

        assigned_subnet_cidrs = generate_subnets(num_required_subnets, BASE_NETWORK_ADDRESS)
        network_subnets = dict(zip(network_names, assigned_subnet_cidrs))

        assigned_ips = {net_name: 10 for net_name in network_subnets}
        node_ips = {} 
        node_configs_map = {node['name']: node for node in config.get('nodes', [])}

        for node_name, node in node_configs_map.items():
            node_ips[node_name] = {}
            for conn in node.get('connections', []):
                net_name = conn['network']
                if net_name not in network_subnets:
                    raise ValueError(f"Internal Error: Network '{net_name}' for node '{node_name}' was not assigned a subnet.")

                subnet = network_subnets[net_name]
                prefix = get_network_prefix(subnet)
                net_obj = ipaddress.ip_network(subnet)

                assigned_ip = None
                current_suffix_start = assigned_ips[net_name]
                found = False

                role = node.get('role')
                if role == 'external_host':
                    current_suffix_start = 1  # 外部ホストはサブネットの最初のIPを使用(Dockerの外部接続用)
                    potential_ip_str = f"{prefix}.{current_suffix_start}"
                    ip_obj = ipaddress.ip_address(potential_ip_str)
                    if ip_obj in net_obj and ip_obj != net_obj.network_address and ip_obj != net_obj.broadcast_address:
                        assigned_ip = potential_ip_str
                        assigned_ips[net_name] = current_suffix_start + 1
                        found = True
                    else:
                        raise ValueError(f"Cannot assign IP {potential_ip_str} to external_host '{node_name}' on network '{net_name}'.")
                else:
                    for suffix in range(current_suffix_start, 255):
                        potential_ip_str = f"{prefix}.{suffix}"
                        try:
                            ip_obj = ipaddress.ip_address(potential_ip_str)
                            if ip_obj in net_obj and ip_obj != net_obj.network_address and ip_obj != net_obj.broadcast_address:
                                assigned_ip = potential_ip_str
                                assigned_ips[net_name] = suffix + 1
                                found = True
                                break
                        except ValueError:
                            pass

                    if not found:
                        raise ValueError(f"Ran out of assignable IPs in subnet {subnet} for network {net_name} starting from suffix {current_suffix_start}.")

                node_ips[node_name][net_name] = assigned_ip

        # --- ROUTING および DEST 情報の生成 ---
        service_routing_info = {}
        client_dest_info = {}

        for node_name, node in node_configs_map.items():
            # ROUTING情報を生成
            service_routing_info[node_name] = generate_routing_info(node_name, node, node_configs_map, network_subnets, node_ips)

            # クライアントの場合はDEST情報も生成
            if node.get('role').endswith('client'):
                dest_ip = generate_client_dest_ip(node_name, node, node_configs_map, node_ips)
                if dest_ip:
                    client_dest_info[node_name] = dest_ip


        # --- 選択されたフォーマットに応じて出力を生成 ---
        if args.format == 'yaml':
            # generate_docker_composeにconfig全体を渡すように変更
            docker_compose_data = generate_docker_compose(config, network_subnets, node_ips, node_configs_map, service_routing_info, client_dest_info)
            print(yaml.dump(docker_compose_data, default_flow_style=False, sort_keys=False))
        elif args.format == 'dot':
            dot_output = generate_dot(config, network_subnets, node_ips, node_configs_map, service_routing_info, client_dest_info)
            print(dot_output)

    except FileNotFoundError:
        print(f"Error: Config file '{args.config_json_file}' not found.", file=sys.stderr)
        sys.exit(1)
    except json.JSONDecodeError:
        print(f"Error: Could not parse JSON from '{args.config_json_file}'.", file=sys.stderr)
        sys.exit(1)
    except ValueError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred: {e}", file=sys.stderr)
        sys.exit(1)