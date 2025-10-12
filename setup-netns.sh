#!/bin/bash

# Exit on error
set -e

NETNS_NAME="sdns"
VETH_HOST="veth0"
VETH_NS="veth1"
HOST_IP="192.168.100.1"
NS_IP="192.168.100.2"
SUBNET="192.168.100.0/24"
PHYSICAL_IF="en0"

echo "Creating network namespace: $NETNS_NAME"
sudo ip netns add $NETNS_NAME

echo "Creating veth pair: $VETH_HOST <-> $VETH_NS"
sudo ip link add $VETH_HOST type veth peer name $VETH_NS

echo "Moving $VETH_NS into namespace"
sudo ip link set $VETH_NS netns $NETNS_NAME

echo "Configuring host side ($VETH_HOST)"
sudo ip addr add $HOST_IP/24 dev $VETH_HOST
sudo ip link set $VETH_HOST up

echo "Configuring namespace side ($VETH_NS)"
sudo ip netns exec $NETNS_NAME ip addr add $NS_IP/24 dev $VETH_NS
sudo ip netns exec $NETNS_NAME ip link set $VETH_NS up
sudo ip netns exec $NETNS_NAME ip link set lo up
sudo ip netns exec $NETNS_NAME ip route add default via $HOST_IP

echo "Enabling IP forwarding"
sudo sysctl -w net.ipv4.ip_forward=1

echo "Setting up NAT"
sudo iptables -t nat -A POSTROUTING -s $SUBNET -o $PHYSICAL_IF -j MASQUERADE

echo "Done! Network namespace '$NETNS_NAME' is ready."
echo ""
echo "To run your app in the namespace:"
echo "  sudo ip netns exec $NETNS_NAME ./your_app"
echo ""
echo "To capture traffic:"
echo "  sudo tshark -i $VETH_HOST -w app.pcap"
