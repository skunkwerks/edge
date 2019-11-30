defmodule BGP4.Protocol do
  @moduledoc """
  Elixir Parser, Generator, and Definitions for BGPv4 Protocol

  See https://tools.ietf.org/html/rfc4271 for BGPv4
  and https://tools.ietf.org/html/rfc4760 for Multiprotocol Extensions
  """
  import Bytesize

  @empty <<>>
  # immutable tags and options in typical packet order
  @bgp_marker <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF::bytes(32)>>
  # packet_length                     << ... :: byte() >>
  @bgp_version <<0x04::byte()>>
  @msg_open <<0x01::byte()>>
  @msg_notification <<0x03::byte()>>
  @msg_keepalive <<0x04::byte()>>
  @bgp_hold_time <<0x00F0::bytes(2)>>
  # notifications
  @cease_admin_shutdown <<0x0602::bytes(2)>>
  # optional capabilities
  @cap_multi_proto_extn <<0x0104_0001_0001::bytes(6)>>
  #  followed by AS
  @cap_4_octet_asn <<0x4104::bytes(2)>>
  @cap_graceful_restart <<0x4006_0000_0001_0100::bytes(8)>>
  @cap_no_route_refresh <<0x0200::bytes(2)>>
  @cap_no_enhanced_route_refresh <<0x4600::bytes(2)>>
  @cap_no_longlived_graceful_restart <<0x4700::bytes(2)>>

  # sample AS taken from private AS range
  # 0xfde8
  @as_local <<65000::bytes(2)>>
  # 0xfe00
  @upstream <<65024::bytes(2)>>
  @local_ip <<0x0A634783::bytes(4)>>

  @doc """
  Validate and strip off standard preamble and length
  """
  def parse(@bgp_marker <> <<length::bytes(2)>> <> rest = msg)
      when length == byte_size(msg),
      do: parse(rest)

  def parse(@msg_open <> rest = msg), do: {:bgp_open, @empty}

  def parse(@msg_keepalive = msg), do: {:bgp_keepalive, @empty}

  def parse(@msg_notification <> @cease_admin_shutdown = msg), do: {:bgp_shutdown, @empty}

  @doc """
  Prepend BGP preamble , then total packet length, and tack on the message
  """
  def generate(msg) when is_binary(msg) do
    # add 2 bytes for length of final frame incl length
    length = byte_size(msg) + byte_size(@bgp_marker) + 2
    @bgp_marker <> <<length::bytes(2)>> <> msg
  end

  def generate(:bgp_keepalive) do
    @msg_keepalive |> generate()
  end

  def generate(:bgp_shutdown) do
    (@msg_notification <> @cease_admin_shutdown)
    |> generate()
  end

  # helpers
  def pretty(bin) when is_binary(bin), do: bin |> Base.encode16(case: :lower)
end
