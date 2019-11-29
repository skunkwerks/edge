defmodule EdgeTest do
  use ExUnit.Case, async: true

  import Bytesize
  import BGP4.Protocol

  @keepalive <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0013_04::bytes(19)>>

  test "keepalive" do
    assert :keepalive = BGP4.Protocol.parse(@keepalive)
    # open packet
    # marker        fffffffffffffffffffffffffffffff
    # length        0039
    # type          01 (OPEN)
    # version       04
    # my_AS         fde8
    # hold_time     00f0
    # bgp_id        0a634787
    # options       1c
    # capabilities  02
    # length      1a
    # opt_MPEC    01
    # length    04
    # AFI       0001 (IPv4)
    # reserved  00
    # SAFI      01  (unicast)
    # 0200400600000001010041040000fde8
    # erfc        4600
    # llgr        4700
  end
end
