defmodule Edge.Application do
  @moduledoc false

  use Application

  def start(_type, _args) do
    {:ok, ip} =
      (System.get_env("PEER") || "127.0.0.1")
      |> String.to_charlist()
      |> :inet.parse_address()

    port =
      (System.get_env("PORT") || "179")
      |> String.to_integer()

    timeout =
      (System.get_env("HOLD") || "90000")
      |> String.to_integer()

    children = [
      {Edge.Worker, %BGP4.Peer{ip: ip, port: port, timeout: timeout}}
    ]

    opts = [strategy: :one_for_one, name: Edge.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
