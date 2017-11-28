/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
 * Copyright (c) 2017 Amitkumar Patel, Mayank Sitapara and Tejas Rafaliya.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors: Amitkumar Patel   <amitpatel111297@gmail.com>
 *          Mayank Sitapara   <mayank.sitapara@gmail.com>
 *          Tejas Rafaliya    <trafaliya@gmail.com>
 */

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
