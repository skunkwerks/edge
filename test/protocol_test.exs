defmodule ProtocolTest do
  use ExUnit.Case, async: true

  import Bytesize
  import BGP4.Protocol

  # sample messages
  @keepalive <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0013_04::bytes(19)>>
  @shutdown <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0015_0306_02::bytes(21)>>
  @open <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_003F_0104_FFFA_005A_934B_2440_2202_0601_0400_0100_0102_0280_0002_0202_0002_0440_0240_7802_0641_0400_00FF_FA02_0247_00::bytes(
             63
           )>>

  @stacked <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_003F_0104_FFFA_005A_934B_CC23_2202_0601_0400_0100_0102_0280_0002_0202_0002_0440_0240_7802_0641_0400_00FF_FA02_0247_00FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00_1304::bytes(
             82
           )>>
  @update <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0030_0200_0000_1440_0101_0040_0206_0201_0000_FDE8_4003_040A_6347_8720_934B_C214::bytes(
              48
            )>>

  @expired <<0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_0015_0304_00::bytes(21)>>

  test "keepalive" do
    assert [bgp_keepalive: nil] = parse(@keepalive)
  end

  test "notifications" do
    assert [bgp_shutdown: :cease] = parse(@shutdown)
    assert [bgp_shutdown: :expired] = parse(@expired)
  end

  test "open" do
    assert [bgp_open: _] = parse(@open)
  end

  test "message ordering is preserved" do
    assert [bgp_open: _, bgp_keepalive: nil] = parse(@stacked)
  end

  test "update" do
    assert [bgp_update: _] = parse(@update)
  end
end
