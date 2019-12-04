defmodule BGP4.Protocol do
  @moduledoc """
  Elixir Parser, Generator, and Definitions for BGPv4 Protocol

  See https://tools.ietf.org/html/rfc4271 for BGPv4
  and https://tools.ietf.org/html/rfc4760 for Multiprotocol Extensions

  Basic message structure is:

  preamble - 16 bytes
  length - 2 bytes
  message type - 1 byte
  ... variable data
  """
  import Bytesize

  # immutable tags and options in typical packet order
  @preamble <<0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF::bytes(16)>>
  @preamble_and_length_size 18
  # packet_length                     << ... :: byte() >>
  @bgp_version <<0x04::byte()>>
  @msg_open <<0x01::byte()>>
  # @msg_open_empty_options <<0x00>>
  @msg_update <<0x02::byte()>>
  @msg_notification <<0x03::byte()>>
  @msg_keepalive <<0x04::byte()>>
  @bgp_hold_time <<0x005A::bytes(2)>>
  # # notifications
  @cease_admin_shutdown <<0x0602::bytes(2)>>
  @hold_timers_expired <<0x0400::bytes(2)>>
  # # optional capabilities
  @cap_no_options << 0x00 >>
  # @cap_multi_proto_extn <<0x0104_0001_0001::bytes(6)>>
  # #  followed by AS
  # @cap_4_octet_asn <<0x4104::bytes(2)>>
  # @cap_graceful_restart <<0x4006_0000_0001_0100::bytes(8)>>
  # @cap_no_route_refresh <<0x0200::bytes(2)>>
  # @cap_no_enhanced_route_refresh <<0x4600::bytes(2)>>
  # @cap_no_longlived_graceful_restart <<0x4700::bytes(2)>>

  def preamble(), do: @preamble
  def hold_time(), do: @bgp_hold_time
  # sample AS taken from private AS range
  # 10.80.69.129 aka z01
  def local_ip(), do: <<10, 80, 69, 129>>
  # 0xfe00
  def local_as(), do: <<65000::bytes(2)>>
  # 0xfde8
  def upstream_as(), do: <<65530::bytes(2)>>
  def upstream_ip(), do: <<10, 80, 69, 128>>
  # some protocol frames have no variable components
  # while others need more love and attendion
  def frame_open(as, hold_time, ip, options), do: generate(:bgp_open, as, hold_time, ip, options)

  # def frame_update(as, hold_time, ip, options),
  #   do: generate(:bgp_open, as, hold_time, ip, options)

  # def frame_notification(), do: generate(:bgp_notification)
  # def frame_keepalive(), do: generate(:bgp_keepalive)
  # def frame_shutdown(), do: generate(:bgp_shutdown)

  @doc """
  Validate and strip off standard preamble and length, leaving any extra for
  the caller to decide how to handle - it's probably another valid message.

  All messages begin with `preamble` followed by 2 bytes `message length`, and
  a `message type` parameter - a minimum 19 bytes. Messages may also be stacked
  sequentially in a single TCP packet.

  Message Header Format

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
  # accumulate until all data are parsed or we crash the caller
  def parse(packet), do: parse(packet, []) |> Enum.reverse()
  # default case, data is parsed successfully, we are done
  def parse(<<>>, acc), do: acc
  # use length marker to split and parse recursively
  def parse(
        @preamble <>
          <<total_message_size::bytes(2), tail::binary>>,
        acc
      ) do
    # size in bits of remaining message is
    # 8*(total_message_bytes - len(preamble))
    length = total_message_size - @preamble_and_length_size
    <<msg::bytes-size(length), next::binary>> = tail
    parsed_message = parse_msg(msg)
    acc = [parsed_message | acc]

    case next do
      "" -> acc
      _ -> parse(next, acc)
    end
  end

  # a single byte is all that remains
  def parse_msg(@msg_keepalive), do: {:bgp_keepalive, nil}

  def parse_msg(@msg_notification <> @cease_admin_shutdown), do: {:bgp_shutdown, :cease}
  def parse_msg(@msg_notification <> @hold_timers_expired), do: {:bgp_shutdown, :expired}

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
  def parse_msg(
        @msg_open <>
          @bgp_version <>
          <<as::bytes(2), hold_time::bytes(2), id::bytes(4), length::byte()>> <>
          options
      )
      when length == byte_size(options) do
    options = parse_rfc3392_options(options)
    {:bgp_open, %{as: as, hold_time: hold_time, id: id, options: options}}
  end

  @doc """
  TODO stubbed update message handling
  """
  def parse_msg(@msg_update <> _TODO), do: {:bgp_update, nil}

  @doc """
  TODO stubbed RFC 3392 option handling
  """
  def parse_rfc3392_options(<<>>), do: nil
  def parse_rfc3392_options(_), do: nil

  @doc """
  Generate valid BGP4 messages
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
    length = byte_size(msg) + byte_size(@preamble) + 2
    @preamble <> <<length::bytes(2)>> <> msg
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
       as <>
       hold_time <>
       ip <>
       options)
    |> wrap()
  end

  # helpers
  def pretty(bin) when is_binary(bin), do: bin |> Base.encode16(case: :lower)
end
