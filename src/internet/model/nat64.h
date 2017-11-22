/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef __NAT64_H__
#define __NAT64_H__

#endif /* __NAT64_H__ */

#ifndef IPV4_NAT_H
#define IPV4_NAT_H

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


namespace ns3 {

class Packet;
class NetDevice;
class OutputStreamWrapper;

class Session
{
public:
  Session();
  Session (Ipv6Address v6ip, uint16_t v6prt,Ipv6Address natv6ip, uint16_t v4prt, Ipv4Address natv4ip, uint16_t assgnprt, Ipv4Address v4ip, uint16_t v4prt1, uint16_t lifetime);

  Ipv6Address Getv6ip() const;

  Ipv4Address Getv4ip () const;

  Ipv4Address Getnatv4ip () const;

  Ipv6Address Getnatv6ip () const;

  uint16_t Getassgnprt () const;

  uint16_t Getv6prt () const;

  uint16_t Getv4prt () const;

  uint16_t Getlifetime () const;

  void Setlifetime(uint16_t);

private:
  Ipv6Address m_v6addr;
  Ipv4Address m_v4addr;
  uint16_t m_v6port;
  uint16_t m_v4port;
  Ipv6Address m_natv6addr;
  Ipv4Address m_natv4addr;
  uint16_t m_assignedport;
  uint16_t m_lifetime;

  // private data member
};


class BIB
{
public:

  BIB ();
  BIB (Ipv6Address v6ip, uint16_t v6port, Ipv4Address natv4ip, uint16_t natv4port);

  Ipv6Address Getv6Address () const;

  Ipv4Address Getnatv4Address () const;

  uint16_t Getnatv4Port () const;

  uint16_t Getv6Port () const;

private:
  Ipv6Address m_v6ip;
  Ipv4Address m_natv4ip;
  uint16_t m_v6port;
  uint16_t m_natv4port;
};


class Nat64 : public Object
{
public:
  static TypeId GetTypeId (void);

  Nat64 ();

  void AddSessionEntry (const Session& rule);

  void AddBIBentry (const BIB& rule);

  Ipv4Header Convertv6tov4 (Ipv6Header);

  Ipv6Header Convertv4tov6 (Ipv4Header);

  uint32_t GetNSessions (void) const;

  BIB GetDynamicTuple (uint32_t index) const;

  uint32_t GetNDynamicBIBTuples (void) const;

  Session GetSession (uint32_t index) const;

  BIB GetDynamicBIBtuple (uint32_t index) const;

  void RemoveSession (uint32_t index);

  void RemoveBIBtuple (uint32_t index);

  void PrintTable (Ptr<OutputStreamWrapper> stream) const;

  void AddAddressPool (Ipv4Address, Ipv4Mask);

  void AddPortPool (uint16_t, uint16_t); //port range

  void SetInside (int32_t interfaceIndex);

  void SetOutside (int32_t interfaceIndex);

  typedef std::list<Session> SessionTable;

  typedef std::list<BIB> BIBTable;

protected:
  // from Object base class
  virtual void NotifyNewAggregate (void);

private:
  //bool m_isConnected;

  Ptr<Ipv4> m_ipv4;
  Ptr<Ipv6> m_ipv6;

  uint32_t DoNatPreRouting (Hooks_t hookNumber, Ptr<Packet> p,
                            Ptr<NetDevice> in, Ptr<NetDevice> out, ContinueCallback& ccb);

  Ipv4Address GetNatv4Address () const;

  Ipv6Address GetNatv6Address () const;

  Ipv4Mask GetNatv4Mask () const;

  uint16_t GetStartPort () const;

  uint16_t GetEndPort () const;

  uint16_t GetCurrentPort () const;

  uint16_t GetNewOutsidePort ();

  SessionTable m_sessiontable;
  BIBTable m_dynamicBIBtable;
  int32_t m_insideInterface;
  int32_t m_outsideInterface;
  Ipv4Address m_natv4ip;
  Ipv6Address m_natv6ip;
  Ipv4Mask m_natv4mask;
  uint16_t m_startport;
  uint16_t m_endport;
  uint16_t m_currentPort;

};

}
#endif

