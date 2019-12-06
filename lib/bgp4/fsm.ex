defmodule BGP4.FSM do
  @moduledoc """
  Implements the BGP4 finite state machine as documented in [RFC4271]
  and referenced in [FSM].

  [RFC]: https://tools.ietf.org/html/rfc4271#section-8
  [FSM]: http://net.cmed.us/Home/routing-theory/bgpv4/the-finite-state-machine
  [BGP4]: https://net.cmed.us/Home/routing-theory/bgpv4/the-finite-state-machine
  [PlantUML]: https://www.planttext.com/
  This module is intended to be embedded into some sort of
  GenServer that wraps the network connectivity around it.
  """

  use Fsm, initial_state: :idle

  @doc """
  Initial state of FSM is idle, waiting for the initial TCP connection
  to be initiated.
  """
  defstate idle do
    defevent connect do
      # connect
      next_state(:connected)
    end

    # after timeout, re-try
  end

  @doc """
  The TCP connection is up but we have not exchanged any higher-level BGP4
  messages yet.
  """
  defstate connected do
    defevent open do
      # send open, handle the response
      next_state(:established)
    end

    defevent timeout do
      # after timeout, re-try
      next_state(:idle)
    end
  end

  @doc """
  The connected state is the default state for an active peering
  session. Both sends and receives arrive regularly. An error in this
  stage should recover by restarting the entire FSM and any
  corresponding connection, and logging the unanticipated event details.
  """
  defstate established do
    defevent close do
      # got an explicit shutdown or lost TCP connection
      # clean up and restart
      next_state(:idle)
    end

    defevent timeout do
      # no messages received within expected timeframe
      # send a keepalive, which could be followed by either a shutdown
      # or dropped connection on the next iteration
      next_state(:established)
    end

    defevent update do
      # triggered from our own Application
      # announce a given route
      next_state(:established)
    end

    defevent receive do
      # got a recv, validate it and reply with keepalive
      next_state(:established)
    end
  end
end
