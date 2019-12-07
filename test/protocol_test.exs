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

  @expired <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0015_0304_00::bytes(21)>>

  test "keepalive" do
    assert [bgp_keepalive: nil] = unpack(@keepalive)
  end

  test "notifications" do
    assert [bgp_shutdown: :cease] = unpack(@shutdown)
    assert [bgp_shutdown: :expired] = unpack(@expired)
  end

  test "open" do
    assert [bgp_open: _] = unpack(@open)
  end

  test "message ordering is preserved" do
    assert [bgp_open: _, bgp_keepalive: nil] = unpack(@stacked)
  end

  test "update" do
    assert [bgp_update: _] = unpack(@update)
  end

  test "pack path origin (IGP)" do
    assert <<0x4001_0100::bytes(4)>> = pack_path_origin_igp()
  end

  test "pack AS path" do
    assert <<0x40020602010000FDE8::bytes(9)>> = pack_AS_path(<<0xFDE8::bytes(2)>>)
  end

  test "pack next hop" do
    assert <<0x40_0304_0A50_4581::bytes(7)>> = pack_path_next_hop(<<0x0A504581::bytes(4)>>)
  end

  test "pack NLRI" do
    assert <<0x20_934B_C214::bytes(5)>> = pack_nlri(32, <<0x934BC214::bytes(4)>>)
  end

  test "wrapped path attributes have valid header" do
    assert <<0x0014::bytes(2), rest::binary>> = wrapped_path_attributes(<<0::16>>, <<0::32>>)
  end

  test "update message is exact match" do
    assert <<0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003002000000144001010040020602010000FDE84003040A50458120934BC214::bytes(
               48
             )>> = pack_update(<<0xFDE8::16>>, <<0x0A504581::32>>, <<0x934BC214::32>>, 32, [])
  end
end
