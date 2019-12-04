defmodule BGP4.Peer do
  @moduledoc """
  Defines the Edge BGP4 peer and holds the current state machine
  """

  @enforce_keys [:ip, :port]

  defstruct [
    # upstream router
    :ip,
    :ip6,
    :state,
    :port,
    :timeout
  ]
end
