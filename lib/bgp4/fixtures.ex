defmodule BGP4.Fixtures do
  import BGP4.Protocol
  import Bytesize

  # message fragments
  def version(), do: <<0x04>>
  def preamble(), do: <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF::bytes(16)>>
  def keepalive(), do: <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0013_04::bytes(19)>>
  def shutdown(), do: <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0015_0306_02::bytes(21)>>
  def open(), do: [open1(), open2()]

  def open1(),
    do:
      <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_003F_0104_FFFA_005A_934B_2440_2202_0601_0400_0100_0102_0280_0002_0202_0002_0440_0240_7802_0641_0400_00FF_FA02_0247_00::bytes(
          63
        )>>

  def open2(),
    do:
      <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_003F_0104_FFFA_005A_934B_CC23_2202_0601_0400_0100_0102_0280_0002_0202_0002_0440_0240_7802_0641_0400_00FF_FA02_0247_00FF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FF00_1304::bytes(
          82
        )>>

  def update(),
    do:
      <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0030_0200_0000_1440_0101_0040_0206_0201_0000_FDE8_4003_040A_6347_8720_934B_C214::bytes(
          48
        )>>
end
