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

  # default port to reach BGP peers
  @port 179
  # the standard timeout, used to decide that a peer is down
  # or to inform a peer of our liveness
  @timeout 90_000

  @doc """
  Start a BGP4 peer and establish a reliable connection

  """
  def start(ip \\ :env, port \\ @port, timeout \\ @timeout) do
    case ip do
      :env -> System.get_env("BGP_IP") || "127.0.0.1"
      _ -> ip
    end

    {:ok, ip} =
      ip
      |> String.to_charlist()
      |> :inet.parse_ipv4strict_address()

    %BGP4.Peer{ip: ip, port: port, timeout: timeout}
    |> Edge.Worker.start_link()
  end
end
