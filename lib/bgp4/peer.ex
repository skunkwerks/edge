defmodule BGP4.Peer do
  @moduledoc """
  Defines the Edge BGP4 peer
  """

  # @derive [Poison.Encoder]
  @enforce_keys [:ip, :port]

  defstruct [
    # upstream router
    :ip,
    :ip6,
    port: 1179,
    timeout: 5000
  ]
end
