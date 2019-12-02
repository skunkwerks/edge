defmodule Edge.Application do
  @moduledoc false
  @port 1179

  use Application

  def start(_type, _args) do
    ip =
      "127.0.0.1"
      |> String.to_charlist()
      |> :inet.parse_address()
      |> elem(1)

    children = [
      {Edge.Worker, %BGP4.Peer{ip: ip, port: @port}}
    ]

    opts = [strategy: :one_for_one, name: Edge.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
