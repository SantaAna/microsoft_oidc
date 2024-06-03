defmodule MicrosoftOidc.AuthState do
  @moduledoc """
  Tracks state that is used to validate whether this 
  application initiated a given OIDC request. 
  """
  use GenServer
  @m __MODULE__

  def start_link(_) do
    GenServer.start_link(@m, [], name: @m)
  end

  def init(_) do
    {:ok, MapSet.new()}
  end
  
  @spec generate() :: String.t()
  def generate() do
    value =
      :crypto.strong_rand_bytes(Application.get_env(:microsoft_oidc, :state_size, 10))
      |> Base.encode16()

    timeout = Application.get_env(:microsoft_oidc, :state_timeout, 60 * 1000)
    add(value)
    Process.send_after(self(), {:remove, value}, timeout)
    value
  end

  @spec validate(String.t()) :: boolean
  def validate(value) do
    if check(value) do
      remove(value)
      true
    else
      false
    end
  end

  defp check(value) do
    GenServer.call(@m, {:check, value})
  end

  def handle_call({:check, value}, _, state) do
    {:reply, MapSet.member?(state, value), state}
  end

  defp add(value) do
    GenServer.call(@m, {:add, value})
  end

  def handle_call({:add, value}, _, state) do
    {:reply, :ok, MapSet.put(state, value)}
  end

  defp remove(value) do
    GenServer.call(@m, {:remove, value})
  end

  def handle_call({:remove, value}, _, state) do
    {:reply, :ok, MapSet.delete(state, value)}
  end
end
