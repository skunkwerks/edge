defmodule BGP4.Protocol do
  @moduledoc """
  Elixir Parser, Generator, and Definitions for BGPv4 Protocol

  See https://tools.ietf.org/html/rfc4271 for BGPv4
  and https://tools.ietf.org/html/rfc4760 for Multiprotocol Extensions
  """
  import Bytesize

  @empty <<>>
  # immutable tags and options in typical packet order
  @bgp_marker <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF::bytes(16)>>
  # packet_length                     << ... :: byte() >>
  @bgp_version <<0x04::byte()>>
  @msg_open <<0x01::byte()>>
  @msg_update <<0x02::byte()>>
  @msg_notification <<0x03::byte()>>
  @msg_keepalive <<0x04::byte()>>
  @bgp_hold_time <<0x00F0::bytes(2)>>
  # # notifications
  @cease_admin_shutdown <<0x0602::bytes(2)>>
  # # optional capabilities
  # @cap_multi_proto_extn <<0x0104_0001_0001::bytes(6)>>
  # #  followed by AS
  # @cap_4_octet_asn <<0x4104::bytes(2)>>
  # @cap_graceful_restart <<0x4006_0000_0001_0100::bytes(8)>>
  # @cap_no_route_refresh <<0x0200::bytes(2)>>
  # @cap_no_enhanced_route_refresh <<0x4600::bytes(2)>>
  # @cap_no_longlived_graceful_restart <<0x4700::bytes(2)>>

  # # sample AS taken from private AS range
  # # 0xfde8
  # @local_as <<65000::bytes(2)>>
  # # 0xfe00
  # @upstream_as <<65530::bytes(2)>>
  # @local_ip <<0x0A634783::bytes(4)>>

  # some protocol frames have no variable components
  # while others need more love and attendion
  def frame_open(as, hold_time, ip, options), do: generate(:bgp_open, as, hold_time, ip, options)

  def frame_update(as, hold_time, ip, options),
    do: generate(:bgp_open, as, hold_time, ip, options)

  def frame_notification(), do: generate(:bgp_notification)
  def frame_keepalive(), do: generate(:bgp_keepalive)
  # def frame_shutdown(), do: generate(:bgp_shutdown)

  @doc """
  Validate and strip off standard preamble and length
  """
  def parse(@bgp_marker <> <<length::bytes(2)>> <> rest = msg)
      when length == byte_size(msg),
      do: parse(rest)

  def parse(@msg_keepalive = msg), do: {:bgp_keepalive, @empty}

  def parse(@msg_notification <> @cease_admin_shutdown = msg), do: {:bgp_shutdown, @empty}

  @doc """
  0                   1                   2                   3
  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+
  |    Version    |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |     My Autonomous System      |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Hold Time           |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                         BGP Identifier                        |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  | Opt Parm Len  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |                                                               |
  |             Optional Parameters (variable)                    |
  |                (possibly zero length)                         |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  """
  def parse(
        @msg_open <>
          @bgp_version <>
          <<as::bytes(2), hold_time::bytes(2), id::bytes(4), length::byte()>> <>
          options = msg
      )
      when length == byte_size(options) do
    options = parse_rfc3392_options(options)
    {:bgp_open, %{as: as, hold_time: hold_time, id: id, options: options}}
  end

  @doc """
  TODO stubbed update message handling
  """
  def parse(@msg_update <> rest = msg), do: {:bgp_update, @empty}

  @doc """
  TODO stubbed RFC 3392 option handling
  """
  def parse_rfc3392_options(<<>>), do: {}
  def parse_rfc3392_options(_), do: {}

  @doc """
  Prepend BGP preamble , then total packet length, and tack on the message

  4.1.  Message Header Format

   Each message has a fixed-size header.  There may or may not be a data
   portion following the header, depending on the message type.  The
   layout of these fields is shown below:

      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |                                                               |
      +                                                               +
      |                                                               |
      +                                                               +
      |                           Marker                              |
      +                                                               +
      |                                                               |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
      |          Length               |      Type     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

      Marker:

         This 16-octet field is included for compatibility; it MUST be
         set to all ones.

      Length:

         This 2-octet unsigned integer indicates the total length of the
         message, including the header in octets.  Thus, it allows one
         to locate the (Marker field of the) next message in the TCP
         stream.  The value of the Length field MUST always be at least
         19 and no greater than 4096, and MAY be further constrained,
         depending on the message type.  "padding" of extra data after
         the message is not allowed.  Therefore, the Length field MUST
         have the smallest value required, given the rest of the
         message.

      Type:

         This 1-octet unsigned integer indicates the type code of the
         message.  This document defines the following type codes:

                              1 - OPEN
                              2 - UPDATE
                              3 - NOTIFICATION
                              4 - KEEPALIVE

         [RFC2918] defines one more type code.
  """
  def wrap(msg) when is_binary(msg) do
    # add 2 bytes for length of final frame incl length
    length = byte_size(msg) + byte_size(@bgp_marker) + 2
    @bgp_marker <> <<length::bytes(2)>> <> msg
  end

  def generate(:bgp_keepalive) do
    @msg_keepalive |> wrap()
  end

  def generate(:bgp_shutdown) do
    (@msg_notification <> @cease_admin_shutdown)
    |> wrap()
  end

  def generate(:bgp_open, as, ip, hold_time, options) do
    (@msg_open <>
       @bgp_version <>
       <<as::bytes(2), hold_time::bytes(2), ip::bytes(4)>> <>
       options)
    |> wrap()
  end

  # helpers
  def pretty(bin) when is_binary(bin), do: bin |> Base.encode16(case: :lower)
end
