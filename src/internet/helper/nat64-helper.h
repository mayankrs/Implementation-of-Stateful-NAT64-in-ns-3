/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
#ifndef __Nat64_HELPER_H__
#define __Nat64_HELPER_H__

#include "ns3/ptr.h"
#include "ns3/nat64.h"
namespace ns3 {
//class Nat64;
class Node;

class Nat64Helper
{
public:
  Nat64Helper ();

  Nat64Helper (const Nat64Helper &);

  virtual Ptr<Nat64> Install (Ptr<Node> node) const;

private:

  Nat64Helper &operator = (const Nat64Helper &o);
};

}

#endif /* __NAT64_HELPER_H__ */
