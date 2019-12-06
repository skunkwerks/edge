defmodule Edge.Worker do
  @moduledoc """
  TCP-based worker that interacts with a BGP4 Peer to maintain an agreed
  list of routes. Currently supports only IPv4 and does not update
  kernel routing information base - yet.
  """

  import BGP4.Protocol
  use Connection

  @backoff_delay 5000

  # raw socket parameters that request the kernel to sign and tag
  # packets on this TCP connection. May need to be revisited to
  # work on different platforms and architectures.
  @tcp_md5sig {:raw, 6, 16, <<1::32>>}

  # generate(:bgp_open, as, hold_time, ip, options)

  def start_link(%BGP4.Peer{} = peer) do
    Connection.start_link(__MODULE__, peer)
  end

  @impl true
  def init(%BGP4.Peer{} = peer) do
    s = %{
      host: peer.ip,
      port: peer.port,
      opts: [:binary, {:active, false}, @tcp_md5sig],
      timeout: peer.timeout,
      sock: nil
    }

    {:connect, :init, s}
  end

  def send(conn, data), do: Connection.call(conn, {:send, data})

  def recv(conn, bytes, timeout \\ 3000) do
    Connection.call(conn, {:recv, bytes, timeout})
  end

  def close(conn), do: Connection.call(conn, :close)

  @impl true
  def connect(
        _,
        %{sock: nil, host: host, port: port, opts: opts, timeout: timeout} = s
      ) do
    case :gen_tcp.connect(host, port, opts, timeout) do
      {:ok, sock} ->
        {:ok, %{s | sock: sock}}

      {:error, _} ->
        {:backoff, @backoff_delay, s}
    end
  end

  @impl true
  def disconnect(info, %{sock: sock} = s) do
    :ok = :gen_tcp.close(sock)

    case info do
      {:close, from} ->
        Connection.reply(from, :ok)

      {:error, :closed} ->
        :error_logger.format("Connection closed~n", [])

      {:error, reason} ->
        reason = :inet.format_error(reason)
        :error_logger.format("Connection error: ~s~n", [reason])
    end

    {:connect, :reconnect, %{s | sock: nil}}
  end

  @impl true
  def handle_call(_, _, %{sock: nil} = s) do
    {:reply, {:error, :closed}, s}
  end

  def handle_call({:send, data}, _, %{sock: sock} = s) do
    case :gen_tcp.send(sock, data) do
      :ok ->
        {:reply, :ok, s}

      {:error, _} = error ->
        {:disconnect, error, error, s}
    end
  end

  def handle_call({:recv, bytes, timeout}, _, %{sock: sock} = s) do
    case :gen_tcp.recv(sock, bytes, timeout) do
      {:ok, _} = ok ->
        {:reply, ok, s}

      {:error, :timeout} = timeout ->
        {:reply, timeout, s}

      {:error, _} = error ->
        {:disconnect, error, error, s}
    end
  end

  def handle_call(:close, from, s) do
    {:disconnect, {:close, from}, s}
  end

  def child_spec(opts) do
    %{
      id: __MODULE__,
      start: {__MODULE__, :start_link, [opts]},
      type: :worker,
      restart: :permanent,
      shutdown: 500
    }
  end
end
