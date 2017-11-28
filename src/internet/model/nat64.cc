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

#include "ns3/log.h"
#include "ns3/uinteger.h"
#include "ns3/ipv4-netfilter.h"

#include "ns3/ip-conntrack-info.h"
#include "ns3/ipv4-conntrack-l3-protocol.h"
#include "ns3/tcp-conntrack-l4-protocol.h"
#include "ns3/udp-conntrack-l4-protocol.h"
#include "ns3/icmpv4-conntrack-l4-protocol.h"

#include "ns3/tcp-header.h"
#include "ns3/udp-header.h"
#include "ns3/ipv4-header.h"
#include "ns3/ipv6-header.h"
#include "ns3/node.h"
#include "ns3/net-device.h"
#include "ns3/output-stream-wrapper.h"
#include "nat64.h"
#include "ns3/ipv6.h"

#include <iomanip>

NS_LOG_COMPONENT_DEFINE ("Nat64");

namespace ns3 {

Ipv4NetfilterHook natCallback1;
Ipv4NetfilterHook natCallback2;

NS_OBJECT_ENSURE_REGISTERED (Nat64);

TypeId
Nat64::GetTypeId (void)
{
  static TypeId tId = TypeId ("ns3::Nat64").SetParent<Object> ();

  return tId;
}

Nat64::Nat64 ()
  : m_insideInterface (-1),
    m_outsideInterface (-1)
{
  NS_LOG_FUNCTION (this);

  NetfilterHookCallback doNatPreRouting = MakeCallback (&Nat64::DoNatPreRouting, this);
  //NetfilterHookCallback doNatPostRouting = MakeCallback (&Nat64::DoNatPostRouting, this);

  //natCallback1 = Ipv4NetfilterHook (1, NF_INET_POST_ROUTING, NF_IP_PRI_NAT_SRC, doNatPostRouting);
  natCallback2 = Ipv4NetfilterHook (1, NF_INET_PRE_ROUTING, NF_IP_PRI_NAT_DST, doNatPreRouting);

}

void
Nat64::NotifyNewAggregate ()
{
  NS_LOG_FUNCTION (this);
  if (m_ipv4 != 0 && m_ipv6 != 0)
    {
      return;
    }
  Ptr<Node> node = this->GetObject<Node> ();
  if (node != 0)
    {
      Ptr<Ipv4> ipv4 = node->GetObject<Ipv4> ();
      if (ipv4 != 0)
        {
          Ptr<Ipv4Netfilter> netfilter = ipv4->GetNetfilter ();
          if (ipv4 != 0)
            {
              m_ipv4 = ipv4;
              // Set callbacks on netfilter pointer

              netfilter->RegisterHook (natCallback1);
              netfilter->RegisterHook (natCallback2);

            }
        }
      Ptr<Ipv6> ipv6 = node->GetObject<Ipv6> ();
      if (ipv6 != 0)
        {
          //Ptr<Ipv6Netfilter> netfilter = ipv6->GetNetfilter ();
          if (ipv6 != 0)
            {
              m_ipv6 = ipv6;
              // Set callbacks on netfilter pointer

              //netfilter->RegisterHook (natCallback1);
              //netfilter->RegisterHook (natCallback2);

            }
        }
    }
  Object::NotifyNewAggregate ();
}

uint32_t
Nat64::GetNSessions (void) const
{
  NS_LOG_FUNCTION (this);
  return m_sessiontable.size ();
}

Session
Nat64::GetSession (uint32_t index) const
{
  NS_LOG_FUNCTION (this << index);
  uint32_t tmp = 0;
  for (SessionTable::const_iterator i = m_sessiontable.begin ();
       i != m_sessiontable.end ();
       i++)
    {
      if (tmp == index)
        {
          return *i;
        }
      tmp++;
    }
  NS_ASSERT (false);

  return Session();// Session (Ipv6Address (), 0, Ipv6Address (), 0, );
}

BIB
Nat64::GetDynamicTuple (uint32_t index) const
{
  NS_LOG_FUNCTION (this << index);
  uint32_t tmp = 0;
  for (BIBTable::const_iterator i = m_dynamicBIBtable.begin ();
       i != m_dynamicBIBtable.end ();
       i++)
    {
      if (tmp == index)
        {
          return *i;
        }
      tmp++;
    }
  NS_ASSERT (false);

  return;
}

uint32_t
Nat64::GetNDynamicBIBTuples (void) const
{
  NS_LOG_FUNCTION (this);
  return m_dynamicBIBtable.size ();
}

void
Nat64::RemoveSession (uint32_t index)
{

  NS_LOG_FUNCTION (this << index);
  NS_ASSERT (index < m_sessiontable.size ());
  uint32_t tmp = 0;
  for (SessionTable::iterator i = m_sessiontable.begin ();
       i != m_sessiontable.end (); i++, tmp++)
    {
      if (tmp == index)
        {
          m_sessiontable.erase (i);
          return;
        }
    }
  NS_ASSERT_MSG (false, "Rule Not Found");
}

void
Nat64::PrintTable (Ptr<OutputStreamWrapper> stream) const

{
  NS_LOG_FUNCTION (this);
  std::ostream* os = stream->GetStream ();
  if (GetNSessions () > 0)
    {
      *os << "       Session Table" << std::endl;
      *os << "ClientIpv6     Clientport     Prefix+Ipv4    Serverport    NATIpv4    AssignedPort    ServerIpv4    Serverport    Lifetime" << std::endl;
      for (uint32_t i = 0; i < GetNSessions (); i++)
        {
          std::ostringstream cl6ip, nat6ip, cl6prt, ser4prt, nat4ip, ser4ip, assgnprt, life;
          Session rule = GetSession (i);

          cl6ip << rule.Getv6ip ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << cl6ip.str ();

          cl6prt << rule.Getv6ip ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << cl6prt.str ();

          nat6ip << rule.Getnatv6ip ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << nat6ip.str ();

          ser4prt << rule.Getv4prt ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << ser4prt.str ();

          nat4ip << rule.Getnatv4ip ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << nat4ip.str ();

          assgnprt << rule.Getassgnprt ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << assgnprt.str ();

          ser4ip << rule.Getv4ip ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << ser4ip.str ();

          ser4prt << rule.Getv4prt ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << ser4prt.str ();

          life << rule.Getlifetime ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << life.str ();

          *os << std::endl;

        }
    }

  if (GetNDynamicBIBTuples () > 0)
    {
      *os << std::endl;
      *os << "       Binding Information Base" << std::endl;
      *os << "ClientIpv6             Clientport           NATIpv4          AssignmentPort" << std::endl;
      for (uint32_t i = 0; i < GetNDynamicBIBTuples (); i++)
        {
          std::ostringstream cl6ip, cl6prt, nat4ip, assgnprt;
          BIB rule = GetDynamicTuple (i);

          cl6ip << rule.Getv6Address ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << cl6ip.str ();

          cl6prt << rule.Getv6Port ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << cl6prt.str ();

          nat4ip << rule.Getnatv4Address ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << nat4ip.str ();

          assgnprt << rule.Getnatv4Port ();
          *os << std::setiosflags (std::ios::left) << std::setw (16) << assgnprt.str ();

          *os << std::endl;
        }

      *os << std::endl;
    }
}

uint32_t
Nat64:: DoNatPreRouting(Hooks_t hookNumber, Ptr<Packet> p, Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb)
{
  NS_LOG_FUNCTION (this << p << hookNumber << in << out);

  if (m_ipv6 == 0 || m_ipv4 == 0)
  {
    return 0;
  }
  uint16_t port;
  Ipv4Header ip4Header; //v4 header container

  Ipv6Header ip6Header; //v6 header container

  NS_LOG_DEBUG ("Input device " << m_ipv4->GetInterfaceForDevice (in) << " inside interface " << m_insideInterface);
  NS_LOG_DEBUG ("Output device " << m_ipv4->GetInterfaceForDevice (out) << " outside interface " << m_outsideInterface);

  p->RemoveHeader (ip6Header); // remove ipv6 header from packet

  NS_LOG_DEBUG ("evaluating packet with src " << ip6Header.GetSourceAddress () << " dst " << ip6Header.GetDestinationAddress ());
  //Ipv6Address destAddress = ip6Header.GetDestination ();

  int BIB_flag = 0;
  int session_flag = 0;

  //Checking for Static NAT Rules
  for (BIBTable::const_iterator i = m_dynamicBIBtable.begin (); // iterating through the BIB table entries
        i != m_dynamicBIBtable.end (); i++)
  {
    if( (*i).Getv6Address() == ip6Header.GetSourceAddress () && ip6Header.GetNextHeader() == IPPROTO_TCP)
    {
        TcpHeader tcpHeader;
        p->RemoveHeader (tcpHeader);
        port=tcpHeader.GetDestinationPort();
        if (tcpHeader.GetDestinationPort () == (*i).Getnatv4Port () && tcpHeader.GetSourcePort() == (*i).Getv6Port())
        {
          p->AddHeader(tcpHeader);
          BIB_flag = 1;
        }
      }
      else if ( (*i).Getv6Address() == ip6Header.GetSourceAddress () && ip6Header.GetNextHeader() == IPPROTO_UDP)
      {
          UdpHeader udpHeader;
          p->RemoveHeader (udpHeader);
          port=udpHeader.GetDestinationPort();
          if (udpHeader.GetDestinationPort () == (*i).Getnatv4Port () && udpHeader.GetSourcePort() == (*i).Getv6Port())
          {
            p->AddHeader(udpHeader);
            BIB_flag = 1;
          }
      }
  }

  if(! BIB_flag) // if BIB entry does not exist
  {
    //Add BIB entry
    if (ip6Header.GetNextHeader() == IPPROTO_TCP)
    {
      TcpHeader header;
    }
    else if (ip6Header.GetNextHeader() == IPPROTO_UDP)
    {
      UdpHeader header;
    }

    p->RemoveHeader(header);
    BIB b( ip6Header.GetSourceAddress(), header.GetSourcePort(), m_natv4ip, GetNewOutsidePort()); // creating new BIB entry
    port=GetCurrentPort();
    p->AddHeader(header);
  }

  for (SessionTable::iterator i = m_sessiontable.begin (); // iterating through the session table entries
      i != m_sessiontable.end (); i++)
  {
    if((*i).Getv6ip() == ip6Header.GetSourceAddress() && (*i).Getnatv6ip() == ip6Header.GetDestinationAddress() && ip6Header.GetNextHeader() == IPPROTO_TCP)
    {
      TcpHeader tcpHeader;
      p->RemoveHeader (tcpHeader);

      if (tcpHeader.GetDestinationPort () == (*i).Getv4prt () && tcpHeader.GetSourcePort() == (*i).Getv6prt())
      {
        (*i).Setlifetime(30); // if session exists, renew lifetime of 30 seconds
        session_flag = 1;
      }
    }
    else if((*i).Getv6ip() == ip6Header.GetSourceAddress() && (*i).Getnatv6ip() == ip6Header.GetDestinationAddress() && ip6Header.GetNextHeader() == IPPROTO_UDP)
    {
      UdpHeader udpHeader;
      p->RemoveHeader (udpHeader);

      if (udpHeader.GetDestinationPort () == (*i).Getv4prt () && udpHeader.GetSourcePort() == (*i).Getv6prt())
      {
        (*i).Setlifetime(30); // if session exists, renew lifetime of 30 seconds
        session_flag = 1;
      }
    }
  }

  if(! session_flag) // if session table entry does not exist
  {
    if (ip6Header.GetNextHeader() == IPPROTO_TCP)
    {
      TcpHeader header;
    }
    else if (ip6Header.GetNextHeader() == IPPROTO_UDP)
    {
      UdpHeader header;
    }
    p->RemoveHeader(header);
    Session s( ip6Header.GetSourceAddress(), header.GetSourcePort(), ip6Header.GetDestinationAddress(), header.GetDestinationPort(), GetNatv4Address(), 
          port, ip6Header.GetDestinationAddress().GetIpv4MappedAddress(),port, 30);
    p->AddHeader(header);
  }

  Ipv4Header newv4header = Convertv6tov4(ip6Header);
  p->AddHeader(newv4header);

  return 0;
}

void
Nat64::AddAddressPool (Ipv4Address globalip, Ipv4Mask globalmask)
{
  NS_LOG_FUNCTION (this << globalip << globalmask);
  m_natv4ip = globalip;
  m_natv4mask = globalmask;
}

Ipv4Address
Nat64::GetNatv4Address () const
{
  return m_natv4ip;
}

Ipv4Mask
Nat64::GetNatv4Mask () const
{
  return m_natv4mask;
}

void
Nat64::AddPortPool (uint16_t strtprt, uint16_t endprt)         //port range
{
  NS_LOG_FUNCTION (this << strtprt << endprt);
  m_startport = strtprt;
  m_endport = endprt;
  m_currentPort = strtprt - 1;
}

uint16_t
Nat64::GetStartPort () const
{
  return m_startport;
}

uint16_t
Nat64::GetEndPort () const
{
  return m_endport;
}

uint16_t
Nat64::GetCurrentPort () const
{
  return m_currentPort;
}

uint16_t
Nat64::GetNewOutsidePort ()
{
  for (int i = m_startport - 1; i <= m_endport; i++)
    {
      if ( m_currentPort == i)
        {
          m_currentPort++;
          return m_currentPort;

        }
    }
  return 0;
}

void
Nat64::SetInside (int32_t interfaceIndex)
{
  NS_LOG_FUNCTION (this << interfaceIndex);
  m_insideInterface = interfaceIndex;

}

void
Nat64::SetOutside (int32_t interfaceIndex)
{

  NS_LOG_FUNCTION (this << interfaceIndex);
  m_outsideInterface = interfaceIndex;
}

void
Nat64::AddSessionEntry (const Session& rule)
{
  NS_LOG_FUNCTION (this);
  m_sessiontable.push_front (rule);
}

void
Nat64::AddBIBentry (const BIB& rule)
{
  NS_LOG_FUNCTION (this);
  m_dynamicBIBtable.push_front (rule);
}

Session::Session()
{}

BIB::BIB()
{}

Session::Session (Ipv6Address v6ip, uint16_t v6prt,Ipv6Address natv6ip, uint16_t v4prt, Ipv4Address natv4ip, uint16_t assgnprt,
   Ipv4Address v4ip, uint16_t v4prt1, uint16_t lifetime)
{
  NS_LOG_FUNCTION (this << v6ip << v6prt << natv6ip << v4prt << natv4ip << assgnprt << v4ip << v4prt << lifetime);
  m_v6addr = v6ip;
  m_v4addr = v4ip;
  m_v6port = v6prt;
  m_v4port = v4prt;
  m_natv6addr = natv6ip;
  m_natv4addr = natv4ip;
  m_assignedport = assgnprt;
  m_lifetime = lifetime;

}

Ipv6Address
Session::Getv6ip () const
{
  return m_v6addr;
}

Ipv4Address
Session::Getv4ip () const
{
  return m_v4addr;
}

Ipv6Address
Session::Getnatv6ip () const
{
  return m_natv6addr;
}

Ipv4Address
Session::Getnatv4ip () const
{
  return m_natv4addr;
}

uint16_t
Session::Getv6prt () const
{
  return m_v6port;
}

uint16_t
Session::Getv4prt () const
{
  return m_v4port;
}

uint16_t
Session::Getassgnprt () const
{
  return m_assignedport;
}

uint16_t
Session::Getlifetime () const
{
  return m_lifetime;
}

void
Session::Setlifetime(uint16_t newlifetime)
{
  m_lifetime = newlifetime;
}

BIB::BIB (Ipv6Address v6ip, uint16_t v6port, Ipv4Address natv4ip, uint16_t natv4port)
{
  NS_LOG_FUNCTION (this << v6ip << v6port << natv4ip << natv4port);
  m_v6ip = v6ip;
  m_natv4ip = natv4ip;
  m_v6port = v6port;
  m_natv4port = natv4port;
}

Ipv6Address
BIB::Getv6Address () const
{
  return m_v6ip;
}

Ipv4Address
BIB::Getnatv4Address () const
{
  return m_natv4ip;
}

uint16_t
BIB::Getv6Port () const
{
  return m_v6port;
}

uint16_t
BIB::Getnatv4Port () const
{
  return m_natv4port;
}

Ipv6Address
Nat64::GetNatv6Address () const
{
  return m_natv6ip;
}

Ipv4Header
Nat64::Convertv6tov4(Ipv6Header v6header)
{
  Ipv4Header newv4header;

  // VERSION = 4
  // INTERNET HEADER LENGTH = 5

  newv4header.SetTos(v6header.GetTrafficClass()); // DCSP + ECN

  // TOTAL LENGTH = IPv6 PAYLOAD LENGTH + IPv4 HEADER LENGTH

  newv4header.SetPayloadSize (v6header.GetPayloadLength());

  newv4header.SetIdentification(0);

  newv4header.SetMoreFragments(); // Set more fragments to 0

  newv4header.SetDontFragment(); // Need to set DF to 1

  newv4header.SetFragmentOffset(0); // All zeros

  newv4header.SetTtl(v6header.GetHopLimit()-1); // NAT64 device is considered as a hop, deduct 1

  newv4header.SetProtocol(v6header.GetNextHeader()); // Upper layer protocol, derived from NextHeader of IPv6 packet

  Ipv6Address sourcev6 = v6header.GetSourceAddress();

  Ipv6Address destv6 = v6header.GetDestinationAddress(); // IPv6 packet's destination contains WKP + IPv4 Address

  Ipv4Address extractedv4 = destv6.GetIpv4MappedAddress(); // Needs clarification, line 136 of ipv6-address.h

  newv4header.SetSource(GetNatv4Address());

  newv4header.SetDestination(extractedv4);

  newv4header.EnableChecksum();
  // Header Checksum = Compute once IPv4 Header is created

  return newv4header;
}

Ipv6Header
Nat64::Convertv4tov6(Ipv4Header v4header)
{

  // VERSION = 6

  Ipv6Header newv6header;

  newv6header.SetTrafficClass(v4header.GetTos());

  newv6header.SetFlowLabel(0);

  newv6header.SetPayloadLength(v4header.GetPayloadSize());

  newv6header.SetNextHeader(v4header.GetProtocol());

  newv6header.SetHopLimit(v4header.GetTtl()-1);

  newv6header.SetSourceAddress(GetNatv6Address());

  newv6header.SetDestinationAddress(Ipv6Address ("3001:1::")); // requires searching BIB; port number and ipv4 destination

  return newv6header;
}

}
