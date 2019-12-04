defmodule EdgeTest do
  use ExUnit.Case, async: true

  import Bytesize
  import BGP4.Protocol

  # sample messages
  @keepalive <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0013_04::bytes(19)>>
  @shutdown <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0015_0306_02::bytes(21)>>
  @open1 <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_003F_0104_FFFA_005A_934B_2440_2202_0601_0400_0100_0102_0280_0002_0202_0002_0440_0240_7802_0641_0400_00FF_FA02_0247_00::bytes(
             63
           )>>

  @open2 <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_003F_0104_FFFA_005A_934B_CC23_2202_0601_0400_0100_0102_0280_0002_0202_0002_0440_0240_7802_0641_0400_00FF_FA02_0247_00FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00_1304::bytes(
             82
           )>>
  @update <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0030_0200_0000_1440_0101_0040_0206_0201_0000_FDE8_4003_040A_6347_8720_934B_C214::bytes(
              48
            )>>

  test "keepalive" do
    assert [bgp_keepalive: nil] = BGP4.Protocol.parse(@keepalive)
  end

  test "shutdown" do
    assert [bgp_shutdown: nil] = BGP4.Protocol.parse(@shutdown)
  end

  test "open" do
    assert [bgp_open: _] = BGP4.Protocol.parse(@open1)
  end

  test "packets with multiple frames are parsed in correct order" do
    assert [bgp_open: _, bgp_keepalive: nil] = BGP4.Protocol.parse(@open2)
  end

  test "update" do
    assert [bgp_update: _] = BGP4.Protocol.parse(@update)
  end
end
