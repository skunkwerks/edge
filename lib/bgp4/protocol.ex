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
  @msg_update <<0x02::byte()>>
  @msg_notification <<0x03::byte()>>
  @msg_keepalive <<0x04::byte()>>
  @bgp_hold_time <<0x005A::bytes(2)>>
  # # notifications
  @cease_admin_shutdown <<0x0602::bytes(2)>>
  @hold_timers_expired <<0x0400::bytes(2)>>
  # # optional capabilities
  @cap_none <<0x00>>
  # @cap_multi_proto_extn <<0x0104_0001_0001::bytes(6)>>
  # #  followed by AS
  # @cap_4_octet_asn <<0x4104::bytes(2)>>
  # @cap_graceful_restart <<0x4006_0000_0001_0100::bytes(8)>>
  # @cap_no_route_refresh <<0x0200::bytes(2)>>
  # @cap_no_enhanced_route_refresh <<0x4600::bytes(2)>>
  # @cap_no_longlived_graceful_restart <<0x4700::bytes(2)>>

  def preamble(), do: @preamble
  def hold_time(), do: @bgp_hold_time
  def cap_none(), do: @cap_none
  # sample AS taken from private AS range
  # 10.80.69.129 aka z01
  def local_ip(), do: <<10, 80, 69, 129>>
  # 0xfe00
  def local_as(), do: <<65000::bytes(2)>>
  # 0xfde8
  def upstream_as(), do: <<65530::bytes(2)>>
  def upstream_ip(), do: <<10, 80, 69, 128>>

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
  # accumulate until all data are unpacked or we crash the caller
  def unpack(packet), do: unpack(packet, []) |> Enum.reverse()
  # default case, data is unpacked successfully, we are done
  def unpack(<<>>, acc), do: acc
  # use length marker to split and unpack recursively
  def unpack(
        @preamble <>
          <<total_message_size::bytes(2), tail::binary>>,
        acc
      ) do
    # size in bits of remaining message is
    # 8*(total_message_bytes - len(preamble))
    length = total_message_size - @preamble_and_length_size
    <<msg::bytes-size(length), next::binary>> = tail
    parsed_message = unpack_msg(msg)
    acc = [parsed_message | acc]

    case next do
      "" -> acc
      _ -> unpack(next, acc)
    end
  end

  # a single byte is all that remains
  def unpack_msg(@msg_keepalive), do: {:bgp_keepalive, nil}

  def unpack_msg(@msg_notification <> @cease_admin_shutdown), do: {:bgp_shutdown, :cease}
  def unpack_msg(@msg_notification <> @hold_timers_expired), do: {:bgp_shutdown, :expired}

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
  def unpack_msg(
        @msg_open <>
          @bgp_version <>
          <<as::bytes(2), hold_time::bytes(2), id::bytes(4), length::byte()>> <>
          options
      )
      when length == byte_size(options) do
    options = unpack_rfc3392_options(options)
    {:bgp_open, %{as: as, hold_time: hold_time, id: id, options: options}}
  end

  @doc """
  TODO stubbed update message handling
  """
  def unpack_msg(@msg_update <> _TODO), do: {:bgp_update, nil}

  @doc """
  TODO stubbed RFC 3392 option handling
  """
  def unpack_rfc3392_options(<<>>), do: nil
  def unpack_rfc3392_options(_), do: nil

  @doc """
  Generate valid BGP4 messages from internal binary format by prepending
  BGP preamble , calculated total packet length, & finally tack on the
  provided message.

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

  def pack_keepalive() do
    @msg_keepalive |> wrap()
  end

  def pack_notification_shutdown() do
    (@msg_notification <> @cease_admin_shutdown)
    |> wrap()
  end

  def pack_open(as, ip, hold_time, options \\ @bgp_hold_time) do
    (@msg_open <>
       @bgp_version <>
       as <>
       hold_time <>
       ip <>
       options)
    |> wrap()
  end

  ################################################################################
  # update is tricky

  @doc """
  Withdrawn routes are packed into a length, followed by possibly empty
  routes to be withdrawn from the peer's RIB.
  """
  def pack_withdrawn_routes([]), do: <<0x0000::bytes(2)>>
  # TODO pack more than zero routes here
  def pack_withdrawn_routes(_), do: :unsupported

  @doc """
  Path attributes we do not know what these are just yet
  """
  @path_flags <<0x40>>
  @path_type_origin <<0x01>>
  @path_type_AS <<0x02>>
  @path_type_AS_sequence <<0x02>>
  @path_type_next_hop <<0x03>>
  @path_attributes_origin <<0x0100::bytes(2)>>
  @path_AS4_segments <<0x01>>

  def pack_path_origin_igp() do
    @path_flags <>
      @path_type_origin <>
      @path_attributes_origin
  end

  # NB AS will be *either* 4 or 2 byte AS4 or plain AS
  # depending on announced capability, "Support for 4-octet AS numbers"
  def pack_AS_path(as) when byte_size(as) == 2, do: pack_AS_path(<<0::16>> <> as)

  def pack_AS_path(as) when byte_size(as) == 4 do
    @path_flags <>
      @path_type_AS <>
      <<byte_size(as) + 2::byte()>> <>
      @path_type_AS_sequence <>
      @path_AS4_segments <>
      as
  end

  def pack_path_next_hop(ip) do
    @path_flags <>
      @path_type_next_hop <>
      <<byte_size(ip)::byte()>> <>
      ip
  end

  def wrapped_path_attributes(as, next_hop) do
    attributes =
      pack_path_origin_igp() <>
        pack_AS_path(as) <>
        pack_path_next_hop(next_hop)

    len = byte_size(attributes)
    <<len::bytes(2)>> <> attributes
  end

  @doc """
  NLRI (network layer reachability information) describes where the prior
  path attributes can be reached - in short how to get to the path attributes
  described in the preceding fields.
  """
  def pack_nlri(length, prefix), do: <<length::byte()>> <> prefix

  def pack_update(
        as,
        next_hop,
        prefix,
        length,
        withdrawn_routes = [],
        hold_time \\ @bgp_hold_time
      ) do
    wrap(
      @msg_update <>
        pack_withdrawn_routes(withdrawn_routes) <>
        wrapped_path_attributes(as, next_hop) <>
        pack_nlri(length, prefix)
    )
  end

  # helpers
  def string_to_ipv4_tuple!(ip) do
    {:ok, ip} = ip |> String.to_charlist() |> :inet.parse_ipv4strict_address()
    ip
  end

  def ipv4_tuple_to_binary!({a, b, c, d}), do: <<a, b, c, d>>

  def pretty(bin) when is_binary(bin), do: bin |> Base.encode16(case: :lower)
end
