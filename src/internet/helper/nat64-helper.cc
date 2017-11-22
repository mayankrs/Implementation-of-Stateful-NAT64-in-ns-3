/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */

#include "nat64-helper.h"

#include "ns3/log.h"
#include "ns3/assert.h"
#include "ns3/ptr.h"
#include "ns3/node.h"
#include "ns3/nat64.h"

#include <stdint.h>
#include <limits.h>
#include <sys/socket.h>
#include "ns3/ptr.h"
#include "ns3/net-device.h"
#include "ns3/packet.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv6-header.h"
#include "ns3/object.h"
#include "ns3/ipv4-netfilter.h"
#include "ns3/ipv4-netfilter-hook.h"
#include "ns3/netfilter-callback-chain.h"

#include "ns3/netfilter-tuple-hash.h"
#include "ns3/netfilter-conntrack-tuple.h"
#include "ns3/netfilter-conntrack-l3-protocol.h"
#include "ns3/netfilter-conntrack-l4-protocol.h"
#include "ns3/ip-conntrack-info.h"
#include "ns3/ipv4.h"
#include "ns3/ipv6.h"
NS_LOG_COMPONENT_DEFINE ("Nat64Helper");

namespace ns3 {

Nat64Helper::Nat64Helper ()
{}

Nat64Helper::Nat64Helper (const Nat64Helper &o)
{}

Ptr<Nat64>
Nat64Helper::Install (Ptr<Node> node) const
{
  Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
  NS_ASSERT_MSG (ipv4, "No IPv4 object found");
  Ptr<Ipv6> ipv6 = node->GetObject<Ipv6> ();
  NS_ASSERT_MSG (ipv6, "No IPv6 object found");
  Ptr<Nat64> nat = CreateObject<Nat64> ();
  node->AggregateObject (nat);
  return nat;
}

} 
