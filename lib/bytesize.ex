defmodule Bytesize do
  defmacro byte() do
    quote do: 8
  end

  defmacro bytes(2) do
    quote do: 16
  end

  defmacro bytes(4) do
    quote do: 32
  end

  defmacro bytes(6) do
    quote do: 48
  end

  defmacro bytes(8) do
    quote do: 64
  end

  defmacro bytes(16) do
    quote do: 128
  end

  defmacro bytes(19) do
    quote do: 152
  end

  defmacro bytes(21) do
    quote do: 168
  end

  defmacro bytes(25) do
    quote do: 200
  end

  defmacro bytes(32) do
    quote do: 256
  end

  defmacro bytes(48) do
    quote do: 384
  end

  defmacro bytes(57) do
    quote do: 456
  end

  defmacro bytes(63) do
    quote do: 504
  end

  defmacro bytes(82) do
    quote do: 656
  end

  # defmacro bytes(n \\ 1) when is_integer(n) and n > 0 do
  #   quote do: 8 * n
  # end

  # defmacro uint16(n \\ 1) when is_integer(n) and n > 0 do
  #   quote do: 16 * n
  # end

  # defmacro quad(n \\ 1) when is_integer(n) and n > 0 do
  #   quote do: 32 * n
  # end

  # defmacro uint32(n \\ 1) when is_integer(n) and n > 0 do
  #   quote do: 32 * n
  # end

  # defmacro uint64(n \\ 1) when is_integer(n) and n > 0 do
  #   quote do: 64 * n
  # end
end
