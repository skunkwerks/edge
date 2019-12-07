defmodule Edge do
  @moduledoc """
  Edge provides lightning-fast application availability by directly linking
  with the internet's native routing protocol, BGP4. Use cutting-edge network
  technology to get your bytes faster and closer to users than ever before.

  Edge is the user-facing module to start a BGP peer, and to announce
  routes to other peers.

  It is initially targeted at announcing the availability of an Elixir
  application directly to a network, rather than acting as a BGP4 router.

  You will need to have appropriately configured network interfaces,
  upstream routers to act as peers, and whatever settings your operating
  system require to enable & sign IP traffic with TCP_MD5 checksums.

  While Edge is primarily designed to run as an automatic part of an OTP
  supervision tree, it is possible to run it directly from iex. This
  approach is suitable for testing configurations, but not for
  production usage.

  ## Examples

  iex> Edge.start("100.64.0.1")
  iex> Edge.announce("...")

  """

  import Bytesize
  import BGP4.Protocol

  # default port to reach BGP peers
  @port 179
  # used to decide that a peer is down or to inform a peer of our liveness
  @timeout 90_000
  @withdrawn_routes []

  # sample AS taken from private AS range
  # 10.80.69.129 aka z01
  @local_ip <<10, 80, 69, 129>>
  # 0xfe00
  @local_as <<65000::bytes(2)>>
  # 0xfde8
  @upstream_as <<65530::bytes(2)>>
  @upstream_ip <<10, 80, 69, 128>>
  @bgp_hold_time <<0x005A::bytes(2)>>

  @doc """
  Start a BGP4 peer and establish a reliable connection

  """
  def start(ip \\ :env, port \\ @port, timeout \\ @timeout) do
    ip =
      case ip do
        :env -> System.get_env("PEER") || "127.0.0.1"
        _ -> ip
      end
      |> string_to_ipv4_tuple!()

    peer = %BGP4.Peer{ip: ip, port: port, timeout: timeout}
    {:ok, pid} = Edge.Worker.start_link(peer)
  end

  def open(as \\ @local_as, hold \\ @bgp_hold_time, ip \\ @local_ip) do
    msg = BGP4.Protocol.pack_open(as, hold, ip)
    Edge.Worker.send(__MODULE__, msg)
  end

  def keepalive() do
    msg = BGP4.Protocol.pack_keepalive()
    Edge.Worker.send(__MODULE__, msg)
  end

  def update(as, next_hop, prefix, length) do
    msg = BGP4.Protocol.pack_update(as, next_hop, prefix, length, @withdrawn_routes)

    msg =
      <<0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF003002000000144001010040020602010000FDE84003040A50458120934BC214::bytes(
          48
        )>>

    Edge.Worker.send(__MODULE__, msg)
  end

  def receive() do
    {:ok, messages} = Edge.Worker.recv(__MODULE__, 0)
    BGP4.Protocol.unpack(messages)
  end

  # some protocol frames have no variable components
  # while others need more love and attendion
end
