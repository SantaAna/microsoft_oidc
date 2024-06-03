defmodule MicrosoftOidc.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {MicrosoftOidc.AuthNonce, []},
      {MicrosoftOidc.AuthState, []}
    ]

    opts = [strategy: :one_for_one, name: MicrosoftOidc.Supervisor]
    Supervisor.start_link(children, opts)
  end
end
