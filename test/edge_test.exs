defmodule EdgeTest do
  use ExUnit.Case
  doctest Edge

  test "greets the world" do
    assert Edge.hello() == :world
  end
end
