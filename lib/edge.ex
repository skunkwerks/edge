defmodule Edge do
  @moduledoc """
  Documentation for Edge.
  """

  # some defaults
  @ip "10.80.69.128"
  @port 179
  @timeout 90_000
  @doc """
  Start a BGP4 peer

  ## Examples

      iex> Edge.start(@ip)

  """
  def start(ip \\ @ip, port \\ @port, timeout \\ @timeout) do
    {:ok, ip} =
      ip
      |> String.to_charlist()
      |> :inet.parse_ipv4strict_address()

    %BGP4.Peer{ip: ip, port: port, timeout: timeout}
    |> start_link()
  end
end
