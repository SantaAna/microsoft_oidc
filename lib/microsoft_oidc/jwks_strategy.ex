defmodule MicrosoftOidc.JwksStrategy do
  @moduledoc """
  JWKS strategy for MSFT OIDC. 
  """
  use JokenJwks.DefaultStrategyTemplate

  def init_opts(opts) do
    # This URL is taken from MSFT docs.
    url = "https://login.microsoftonline.com/common/discovery/v2.0/keys"
    Keyword.merge(opts, jwks_url: url, explicit_alg: "RS256")
  end
end
