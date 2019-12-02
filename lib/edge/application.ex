defmodule Edge.Application do
  @moduledoc false
  @port 1179
  @tcp_md5sig {:raw, 6, 16, <<1::32>>}
  @defaults [:binary, @tcp_md5sig]

  use Application

  def start(_type, _args) do
    ip = "100.64.0.1"
         |> String.to_charlist()
         |> :inet.parse_address()
         |> elem(1)

    children = [
      {Edge.Worker, %BGP4.Peer{ip: ip, port: @port, tcp_options: @defaults}}
    ]

    opts = [strategy: :one_for_one, name: Edge.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
