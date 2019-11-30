defmodule EdgeTest do
  use ExUnit.Case, async: true

  import Bytesize
  import BGP4.Protocol

  # sample messages
  @empty <<>>
  @keepalive <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0013_04::bytes(19)>>
  @shutdown <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0015_0306_02::bytes(21)>>
  @open <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_003F_0104_FFFA_005A_934B_2440_2202_0601_0400_0100_0102_0280_0002_0202_0002_0440_0240_7802_0641_0400_00FF_FA02_0247_00::bytes(
            63
          )>>

  test "open" do
    assert {:bgp_open, _} = BGP4.Protocol.parse(@open)
  end

  test "keepalive" do
    assert {:bgp_keepalive, @empty} = BGP4.Protocol.parse(@keepalive)
  end

  test "shutdown" do
    assert {:bgp_shutdown, @empty} = BGP4.Protocol.parse(@shutdown)
  end
end
