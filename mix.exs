defmodule MicrosoftOidc.MixProject do
  use Mix.Project

  def project do
    [
      app: :microsoft_oidc,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {MicrosoftOidc.Application, []}
    ]
  end

  defp deps do
    [
      {:joken, "~> 2.6"},
      {:joken_jwks, "~> 1.6"},
      {:credo, "~> 1.7", only: [:dev], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev], runtime: false}
    ]
  end
end
