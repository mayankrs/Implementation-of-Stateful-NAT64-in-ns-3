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
